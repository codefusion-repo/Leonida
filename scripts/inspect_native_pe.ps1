# Independent post-build inspection using the runner's Microsoft PE dumper.
param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][ValidateSet('cmake','direct')][string]$Build,
    [Parameter(Mandatory=$true)][string]$Evidence
)
$ErrorActionPreference = 'Stop'
$reportPath = Join-Path $Evidence "$Build.report.json"
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -AsHashtable
if ($report.status -ne 'PASS' -or $report.identity.candidate -ne $env:CANDIDATE_SHA -or
    $report.identity.build -ne $Build -or $report.identity.GITHUB_RUN_ID -ne $env:GITHUB_RUN_ID) {
    throw 'unexpected analysis report identity'
}
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$hash = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne $report.binary.sha256) { throw 'independent SHA256 mismatch' }
$vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $vs -or @($vs).Count -ne 1) { throw 'cannot locate MSVC' }
$version = (Get-Content -LiteralPath (Join-Path $vs 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt') -Raw).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'unexpected MSVC version' }
$dumpbin = Join-Path $vs "VC\Tools\MSVC\$version\bin\HostX64\x64\dumpbin.exe"
if (-not (Test-Path -LiteralPath $dumpbin -PathType Leaf)) { throw 'dumpbin unavailable' }
$env:VSLANG = '1033'
$lines = & $dumpbin /nologo /headers /loadconfig /imports /relocations $binaryPath 2>&1
$rc = $LASTEXITCODE
$raw = ($lines | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
if ($rc -ne 0 -or -not $raw -or $raw.Length -gt 1048576) { throw "dumpbin failed ($rc) or exceeded output limit" }
function Read-Hex([string]$Label) {
    $matchesFound = [regex]::Matches($raw, "(?im)^\s*([0-9a-f]+)\s+" + [regex]::Escape($Label) + "\s*$")
    if ($matchesFound.Count -ne 1) { throw "missing or ambiguous dumpbin field: $Label" }
    return [Convert]::ToUInt64($matchesFound[0].Groups[1].Value,16)
}
$characteristics = Read-Hex 'DLL characteristics'
$guardFlags = Read-Hex 'Guard Flags'
$guardCount = Read-Hex 'Guard CF function count'
if ($characteristics -ne $report.binary.dll_characteristics -or
    $guardFlags -ne $report.binary.cfg.guard_flags -or $guardCount -ne $report.binary.cfg.function_count) {
    throw 'independent header/CFG mismatch'
}
foreach ($needle in @('High Entropy Virtual Addresses','Dynamic base','NX compatible','CF instrumented','FID table present')) {
    if ($raw -notmatch [regex]::Escape($needle)) { throw "missing independent mitigation: $needle" }
}
if ($raw -notmatch '(?i)\bDIR64\b') { throw 'no independently observed DIR64 relocation' }
$dlls = @([regex]::Matches($raw,'(?im)^\s+([A-Za-z0-9_.-]+\.dll)\s*$') |
    ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() } | Sort-Object -Unique)
$expected = @($report.binary.direct_imports.Keys | Sort-Object)
if (($dlls -join ',') -ne ($expected -join ',')) { throw 'independent DLL inventory mismatch' }
$sections = @([regex]::Matches($raw,'(?im)^\s+(\S{1,8})\s+name\s*$') |
    ForEach-Object { $_.Groups[1].Value } | Sort-Object)
$expectedSections = @($report.binary.sections | ForEach-Object { $_.name } | Sort-Object)
if (($sections -join ',') -ne ($expectedSections -join ',')) { throw 'independent section inventory mismatch' }
if ((Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) { throw 'binary changed during inspection' }
$out = @{
    status = 'PASS'
    identity = $report.identity
    sha256 = $hash
    analyzer_report_sha256 = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLowerInvariant()
    tool = 'Microsoft dumpbin'
    tool_version = (Get-Item -LiteralPath $dumpbin).VersionInfo.FileVersion
    exit_code = $rc
    dll_characteristics = $characteristics
    guard_flags = $guardFlags
    guard_function_count = $guardCount
    direct_dlls = $dlls
    sections = $sections
    dumpbin_output = $raw
}
$target = Join-Path $Evidence "$Build.dumpbin.json"
if (Test-Path -LiteralPath $target) { throw 'stale independent inspection' }
$out | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $target -Encoding utf8NoBOM
Write-Host "Independent PE inspection PASS: $Build $hash"
