# Day-one report for the game executable: PE inspection, encryption check, import surface and a loader dry run.
# Reads the exe only; no game code runs.
param(
    [Parameter(Mandatory)][string]$Exe,
    [string]$GameDir = (Split-Path $Exe -Parent)
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$name = [IO.Path]::GetFileNameWithoutExtension($Exe)
$out = Join-Path $root "reports\exe\$name"
New-Item -ItemType Directory -Force $out | Out-Null

if (-not (Test-Path $Exe)) { throw "$Exe not found" }
$fs = [IO.File]::OpenRead($Exe); $mz = New-Object byte[] 2; [void]$fs.Read($mz, 0, 2); $fs.Close()
if ([Text.Encoding]::ASCII.GetString($mz) -ne "MZ") {
    throw "$Exe doesn't start with an MZ header. It's still packaged or encrypted, so there's nothing to inspect."
}

$size = (Get-Item $Exe).Length
$hash = (Get-FileHash $Exe -Algorithm SHA256).Hash.ToLower()
"sha256 $hash  size $size" | Tee-Object (Join-Path $out "hash.txt")

Write-Host "`n== PE inspection"
python -I (Join-Path $root "tools\pe_inspect.py") $Exe --game-dir $GameDir --out $out
if ($LASTEXITCODE -ne 0) { throw "pe_inspect failed" }

$rt = Join-Path $root "runtime\build\gta6rt.exe"
# Do not run a cached pre-hardening executable. The build script checks its exit code.
& (Join-Path $PSScriptRoot "build_runtime.ps1")
if (-not (Test-Path -LiteralPath $rt -PathType Leaf)) { throw "runtime build output missing" }
Write-Host "`n== Loader dry run (diagnostic shim coverage; no image execution)"
# Capture the native exit status before processing the report. Exit 3 is an
# incomplete coverage report, not permission to run the image.
$previous = $ErrorActionPreference
try {
    $ErrorActionPreference = "Continue"
    $dryReport = & $rt --dry-run $Exe --game-dir $GameDir 2>&1
    $dryStatus = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previous
}
$dryReport | Tee-Object (Join-Path $out "dryrun.txt") | Select-Object -Last 40
if ($dryStatus -eq 3) { Write-Warning "Unimplemented imports; diagnostic report only." }
elseif ($dryStatus -ne 0) { throw "runtime dry-run failed ($dryStatus)" }

# Shim to-do list, grouped by DLL, most functions first.
$report = Get-Content (Join-Path $out "$name.json") -Raw | ConvertFrom-Json
$todo = $report.imports | Where-Object { $_.where -eq "shim" } | Sort-Object { -$_.functions.Count }
$lines = foreach ($t in $todo) { "{0,-40} {1,5}" -f $t.dll, $t.functions.Count }
$lines | Set-Content (Join-Path $out "shim-todo.txt")
Write-Host "`n== Shim to-do (DLL, function count)"
$lines
$enc = $report.sections | Where-Object { $_.looks_encrypted } | ForEach-Object { $_.name }
if ($enc) { Write-Warning "High-entropy sections (still encrypted or packed): $($enc -join ', ')" }
Write-Host "`nReports: $out"
