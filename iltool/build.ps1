# build.ps1 - publish il-tool (framework-dependent, win-x64) into the package
# data directory so run_il_tool() finds it without any configuration.
#
# Requires: .NET 8 SDK (`dotnet --version` >= 8.x).
# Usage:    powershell -ExecutionPolicy Bypass -File .\iltool\build.ps1

$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Join-Path $here "src\IlTool\IlTool.csproj"
$dest = Join-Path $here "..\src\game_modifier\data\il-tool"

# 1. sanity: dotnet SDK present?
try {
    $sdkVersion = (& dotnet --version) 2>&1
} catch {
    $sdkVersion = $null
}
if ($LASTEXITCODE -ne 0 -or -not $sdkVersion) {
    Write-Error ".NET SDK not found. Install the .NET 8 SDK: https://dotnet.microsoft.com/download/dotnet/8.0"
}
Write-Host "dotnet SDK: $sdkVersion"

# 2. publish framework-dependent win-x64 (small output, needs the .NET 8 runtime)
New-Item -ItemType Directory -Force -Path $dest | Out-Null
& dotnet publish $proj -c Release -r win-x64 --self-contained false -o $dest
if ($LASTEXITCODE -ne 0) {
    Write-Error "dotnet publish failed (NuGet restore needs network access for Mono.Cecil 0.11.5)"
}

# 3. smoke: version banner must print on stdout
$exe = Join-Path $dest "il-tool.exe"
if (-not (Test-Path $exe)) {
    Write-Error "publish did not produce $exe"
}
& $exe --version
if ($LASTEXITCODE -ne 0) {
    Write-Error "il-tool --version smoke test failed"
}

Write-Host "OK: published to $dest"
