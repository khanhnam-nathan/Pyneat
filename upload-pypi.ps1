# Upload PyNEAT distributions to PyPI (or Test PyPI).
#
# Usage (production):
#   $env:PYPI_TOKEN = "pypi-..."   # API token from https://pypi.org/manage/account/token/
#   .\upload-pypi.ps1
#
# Test PyPI:
#   $env:PYPI_TOKEN = "pypi-..."   # token from https://test.pypi.org/manage/account/token/
#   .\upload-pypi.ps1 -TestPyPI
#
# Verbose (shows PyPI response body; use when you get 403):
#   .\upload-pypi.ps1 -VerboseUpload
#
# Security: never commit tokens. If a token was pasted into a file or chat, revoke it and create a new one.

[CmdletBinding()]
param(
    [switch] $TestPyPI,
    [switch] $VerboseUpload
)

$ErrorActionPreference = "Stop"

if (-not $env:PYPI_TOKEN) {
    Write-Host "ERROR: Set `$env:PYPI_TOKEN before running." -ForegroundColor Red
    Write-Host '  $env:PYPI_TOKEN = "pypi-..."'
    exit 1
}

# Trim accidental whitespace/newlines from copy-paste
$env:PYPI_TOKEN = $env:PYPI_TOKEN.Trim()

if (-not $env:PYPI_TOKEN.StartsWith("pypi-")) {
    Write-Host "WARNING: PyPI API tokens normally start with 'pypi-'. Check you are not using a password or Test token on the wrong index." -ForegroundColor Yellow
}

# Twine reads these env vars reliably (avoids PowerShell quoting issues with --password)
$env:TWINE_USERNAME = "__token__"
$env:TWINE_PASSWORD = $env:PYPI_TOKEN

try {
    $twineCheck = py -3 -m twine --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: twine not found. Install with: py -3 -m pip install twine" -ForegroundColor Red
        exit 1
    }
    Write-Host "Using: $twineCheck" -ForegroundColor Gray

    # Wheel uses pyneat_cli-...; sdist uses pyneat-cli-... (PEP 503 normalization)
    $distFiles = Get-ChildItem "dist" -File | Where-Object {
        $_.Name -match "^pyneat(-|_)cli-"
    } | Sort-Object LastWriteTime -Descending

    if ($distFiles.Count -eq 0) {
        Write-Host "ERROR: No dist files found. Run 'py -m build --sdist --outdir dist' first." -ForegroundColor Red
        exit 1
    }

    Write-Host "Files to upload:" -ForegroundColor Cyan
    $distFiles | ForEach-Object { Write-Host "  $($_.Name) ($([math]::Round($_.Length / 1KB, 1)) KB)" }

    $repoArgs = @()
    if ($TestPyPI) {
        $repoArgs = @("--repository", "testpypi")
        Write-Host ""
        Write-Host "Target: Test PyPI (https://test.pypi.org/)" -ForegroundColor Yellow
    } else {
        Write-Host ""
        Write-Host "Target: PyPI (https://pypi.org/)" -ForegroundColor Yellow
    }

    $verboseArgs = @()
    if ($VerboseUpload) {
        $verboseArgs = @("--verbose")
    }

    $filePaths = $distFiles | ForEach-Object { $_.FullName }

    Write-Host ""
    & py -3 -m twine upload @repoArgs @verboseArgs $filePaths

    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "UPLOAD FAILED" -ForegroundColor Red
        Write-Host ""
        Write-Host "403 often means:" -ForegroundColor Yellow
        Write-Host "  - Token revoked, wrong, or for Test PyPI used on prod (or the reverse)."
        Write-Host "  - Username must be exactly: __token__ (lowercase)."
        Write-Host "  - Project-scoped token must match the PyPI project name (this package is: pyneat-cli)."
        Write-Host "  - Use 'Entire account' scope or a token scoped to: https://pypi.org/project/pyneat-cli/"
        Write-Host "  - Re-run with -VerboseUpload to see PyPI's full error text."
        exit 1
    }

    Write-Host ""
    if ($TestPyPI) {
        Write-Host "Done! Check https://test.pypi.org/project/pyneat-cli/" -ForegroundColor Green
    } else {
        Write-Host "Done! Check https://pypi.org/project/pyneat-cli/" -ForegroundColor Green
    }
}
finally {
    Remove-Item Env:TWINE_USERNAME -ErrorAction SilentlyContinue
    Remove-Item Env:TWINE_PASSWORD -ErrorAction SilentlyContinue
}
