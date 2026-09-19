# Build the native crypto sidecar for the Windows target and vendor the
# result under engine/native/x86_64-pc-windows-msvc/.  Requires a Rust
# toolchain (MSVC).  Run from the repo root: powershell native\build.ps1

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

cargo build --release --target x86_64-pc-windows-msvc
$out = "..\engine\native\x86_64-pc-windows-msvc"
New-Item -ItemType Directory -Force -Path $out | Out-Null
Copy-Item "target\x86_64-pc-windows-msvc\release\strata_native.dll" `
    "$out\strata_native.dll"
Get-Item "$out\strata_native.dll"