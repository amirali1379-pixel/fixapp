param(
    [string]$Profile = "release",
    [string]$Target = "x86_64-pc-windows-msvc",
    [string]$OutDir = "dist\network-engine"
)

$ErrorActionPreference = "Stop"

Write-Host "== Network Engine Windows packaging =="
Write-Host "Target: $Target"
Write-Host "Profile: $Profile"

cargo build --target $Target --profile $Profile -p network-engine

$root = Split-Path -Parent $PSScriptRoot
$targetDir = Join-Path $root "target\$Target\$Profile"
$out = Join-Path $root $OutDir

if (Test-Path $out) {
    Remove-Item $out -Recurse -Force
}
New-Item -ItemType Directory -Path $out -Force | Out-Null

$dll = Join-Path $targetDir "network_engine.dll"
if (-not (Test-Path $dll)) {
    throw "network_engine.dll was not produced at $dll"
}

Copy-Item $dll (Join-Path $out "network-engine.dll")

$header = Join-Path $root "dll\network-engine\include\network_engine.h"
if (Test-Path $header) {
    New-Item -ItemType Directory -Path (Join-Path $out "include") -Force | Out-Null
    Copy-Item $header (Join-Path $out "include\network_engine.h")
}

# Runtime assets are kept in native/<backend>/runtime in the repository,
# but Windows DLL dependency resolution for the packaged engine must be able
# to find the DLLs next to network-engine.dll. Import libraries stay out of
# the release package.
$nativeRuntimeFiles = @(
    @{ Name = "windivert"; Path = "native\windivert\runtime"; Required = @("WinDivert.dll", "WinDivert.sys") },
    @{ Name = "npcap"; Path = "native\npcap\runtime"; Required = @("wpcap.dll", "Packet.dll") }
)

foreach ($native in $nativeRuntimeFiles) {
    $source = Join-Path $root $native.Path

    if (-not (Test-Path $source)) {
        throw "Required native runtime directory is missing: $source"
    }

    foreach ($fileName in $native.Required) {
        $sourceFile = Join-Path $source $fileName
        if (-not (Test-Path $sourceFile)) {
            throw "Required $($native.Name) runtime asset is missing: $sourceFile"
        }

        Copy-Item $sourceFile (Join-Path $out $fileName) -Force
    }
}

Write-Host "Package created: $out"
Write-Host "Runtime assets: WinDivert.dll, WinDivert.sys, wpcap.dll, Packet.dll"
Write-Host "Release rule: runtime dependencies only; import libraries and development headers are not distributed."