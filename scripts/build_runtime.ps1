# Builds runtime\build\gta6rt.exe with MSVC at BelowNormal priority, on half the cores.
# Uses VS's CMake + Ninja when the "C++ CMake tools" component is installed, otherwise calls cl.exe directly.
param([switch]$Debug, [switch]$DirectMsvc)
$ErrorActionPreference = "Stop"

$root = Split-Path $PSScriptRoot -Parent
$installer = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
$vs = & "$installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "Visual Studio with the C++ x64 tools wasn't found." }
$vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvars64.bat"
$jobs = [Math]::Max(1, [int]([Environment]::ProcessorCount / 2))

$src = Join-Path $root "runtime"
$out = Join-Path $src "build"
# The generated batch file uses ASCII and cmd expansion rules. Reject unsupported
# path characters rather than interpolating them into a command.
foreach ($value in @($root, $installer, $vs, $vcvars, $src, $out)) {
    if ($value -match '[^\x20-\x7e]|[%!^&|<>"]') { throw "unsupported build path characters" }
}
New-Item -ItemType Directory -Force $out | Out-Null

$cmakeDir = Join-Path $vs "Common7\IDE\CommonExtensions\Microsoft\CMake"
$cmake = Join-Path $cmakeDir "CMake\bin\cmake.exe"
$ninja = Join-Path $cmakeDir "Ninja\ninja.exe"
$cfg = if ($Debug) { "Debug" } else { "RelWithDebInfo" }

if (-not $DirectMsvc -and (Test-Path $cmake) -and (Test-Path $ninja)) {
    $body = @"
"$cmake" -S "$src" -B "$out" -G Ninja "-DCMAKE_MAKE_PROGRAM=$ninja" -DCMAKE_BUILD_TYPE=$cfg || exit /b 1
"$cmake" --build "$out" -j $jobs || exit /b 1
"@
} else {
    Write-Host "runtime build: direct MSVC"
    # Never accept a stale executable as evidence of this direct build.
    $target = Join-Path $out "gta6rt.exe"
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -ErrorAction Stop }
    # Keep this list in step with runtime\CMakeLists.txt.
    $files = "src\main.cpp", "src\pe_loader.cpp" | ForEach-Object { "`"$src\$_`"" }
    $opt = if ($Debug) { "/Od /MDd" } else { "/O2 /MD" }
    $body = @"
cd /d "$out" || exit /b 1
cl /nologo /std:c++20 /EHsc /W4 /permissive- /utf-8 /Zi $opt /MP$jobs /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE $($files -join ' ') /Fe:gta6rt.exe || exit /b 1
"@
    if (-not $DirectMsvc) {
        $body += "`r`n" + @"
if defined VULKAN_SDK cl /nologo /std:c++20 /EHsc /O2 /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I "%VULKAN_SDK%\Include" "$src\test\vk_pipeline_check.cpp" /Fe:vk_pipeline_check.exe || exit /b 1
"@
    }
}

# A .cmd file avoids cmd.exe's quote stripping on paths with spaces.
$bat = Join-Path $out "_build.cmd"
"@echo off`r`nset `"PATH=$installer;%PATH%`"`r`ncall `"$vcvars`" >nul || exit /b 1`r`n$body" | Set-Content -Encoding ascii $bat

$cmd = Join-Path $env:SystemRoot "System32\cmd.exe"
$p = Start-Process -FilePath $cmd -ArgumentList ('/d /v:off /s /c ""{0}""' -f $bat) -NoNewWindow -PassThru
$null = $p.Handle  # keeps the exit code readable after WaitForExit
try { $p.PriorityClass = "BelowNormal" } catch {}
$p.WaitForExit()
if ($p.ExitCode -ne 0) { throw "build failed ($($p.ExitCode))" }
if (-not (Test-Path -LiteralPath (Join-Path $out "gta6rt.exe") -PathType Leaf)) { throw "runtime build output missing" }
Write-Host "built $out\gta6rt.exe"
