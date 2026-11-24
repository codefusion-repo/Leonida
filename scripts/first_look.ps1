# Diagnostic-only report. Never execute the supplied image or probe its DLL dependencies.
param(
    [Parameter(Mandatory)][string]$Exe,
    [string]$GameDir
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$inputFile = Get-Item -LiteralPath $Exe -ErrorAction Stop
if ($inputFile.PSIsContainer -or ($inputFile.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "input must be a regular file"
}
$Exe = $inputFile.FullName
if ($PSBoundParameters.ContainsKey("GameDir")) { Write-Warning "--game-dir is ignored in diagnostic-only mode" }
$name = [IO.Path]::GetFileNameWithoutExtension($Exe)
$out = Join-Path $root "reports\exe\$name"
New-Item -ItemType Directory -Force $out | Out-Null

$size = $inputFile.Length
if ($size -lt 64 -or $size -gt 1GB) { throw "invalid PE file size" }
$hash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
"sha256 $hash  size $size" | Set-Content -LiteralPath (Join-Path $out "hash.txt")

# Compile the isolated diagnostic target; do not reuse a cached runtime.
& (Join-Path $PSScriptRoot "build_runtime.ps1") -DirectMsvc
$rt = Join-Path $root "runtime\build\gta6rt.exe"
if (-not (Test-Path -LiteralPath $rt -PathType Leaf)) { throw "runtime build output missing" }

# G4: scan every fresh wrapper runtime in CI before launching diagnostics.
if ($env:GITHUB_ACTIONS -eq "true") {
    & (Join-Path $PSScriptRoot "scan_malware.ps1") -Phase Wrapper
}

# The legacy Python inspector has a separate trust boundary. It is deliberately
# not called here, including before native preflight or after a validation error.
$previous = $ErrorActionPreference
$previousNative = $PSNativeCommandUseErrorActionPreference
try {
    $ErrorActionPreference = "Continue"
    $PSNativeCommandUseErrorActionPreference = $false
    $dryReport = & $rt --dry-run -- $Exe 2>&1
    $dryStatus = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previous
    $PSNativeCommandUseErrorActionPreference = $previousNative
}
$dryReport | Tee-Object -FilePath (Join-Path $out "dryrun.txt")
if ($dryStatus -eq 3) { Write-Warning "Unimplemented imports; diagnostic report only." }
elseif ($dryStatus -ne 0) { throw "runtime dry-run failed ($dryStatus)" }
Write-Host "Reports: $out"
exit $dryStatus
