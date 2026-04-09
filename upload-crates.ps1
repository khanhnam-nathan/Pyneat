# Upload pyneat-rs to crates.io
# Usage:
#   Option 1 (recommended): Set CARGO_REGISTRY_TOKEN env var before running
#     $env:CARGO_REGISTRY_TOKEN = "your-crates-io-token"
#     .\upload-crates.ps1
#
#   Option 2: Use cargo login first, then run this script
#     cargo login
#     .\upload-crates.ps1

$ErrorActionPreference = "Stop"

$crateDir = "D:\pyneat-final\pyneat-rs"

if (-not (Test-Path "$crateDir\Cargo.toml")) {
    Write-Host "ERROR: $crateDir\Cargo.toml not found." -ForegroundColor Red
    exit 1
}

Write-Host "Checking Cargo.toml..." -ForegroundColor Cyan
Get-Content "$crateDir\Cargo.toml" | Select-String -Pattern "^version|^name" | Select-Object -First 2

Write-Host ""
Write-Host "Dry-run check:" -ForegroundColor Yellow
Set-Location $crateDir
cargo publish --dry-run 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "DRY-RUN FAILED - fix errors above before publishing." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Dry-run OK. Ready to publish." -ForegroundColor Green
Write-Host ""
Write-Host "To publish for real, run:" -ForegroundColor Cyan
Write-Host "  Set `$env:CARGO_REGISTRY_TOKEN = `"your-token`""
Write-Host "  cd $crateDir"
Write-Host "  cargo publish"
