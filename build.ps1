# PyNEAT Build Script - Windows PowerShell
#
# Usage:
#   .\build.ps1              # Build sdist and wheels
#   .\build.ps1 -Test        # Test build locally
#   .\build.ps1 -Upload      # Upload to PyPI
#   .\build.ps1 -Clean       # Clean build artifacts

param(
    [switch]$Clean,
    [switch]$Test,
    [switch]$Upload,
    [switch]$TestUpload,
    [switch]$Rust,
    [switch]$All
)

# Colors
$RED = "`e[0;31m"
$GREEN = "`e[0;32m"
$YELLOW = "`e[1;33m"
$NC = "`e[0m"

function Info {
    Write-Host "${GREEN}[INFO]${NC} $args"
}

function Warn {
    Write-Host "${YELLOW}[WARN]${NC} $args"
}

function Error {
    Write-Host "${RED}[ERROR]${NC} $args"
}

# Clean function
function Clean-Build {
    Info "Cleaning build artifacts..."
    if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
    if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
    if (Test-Path "*.egg-info") { Remove-Item -Recurse -Force "*.egg-info" }
    if (Test-Path "pyneat.egg-info") { Remove-Item -Recurse -Force "pyneat.egg-info" }
    Get-ChildItem -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Recurse -Filter "*.pyc" | Remove-Item -Force -ErrorAction SilentlyContinue
    Info "Clean complete!"
}

# Build Python package
function Build-Python {
    Info "Building Python package..."
    Clean-Build
    python -m build
    Info "Python package built successfully!"
    Info "Output: dist/"
}

# Build Rust extension
function Build-Rust {
    Info "Building Rust extension..."
    Set-Location "pyneat-rs"

    # Build release
    cargo build --release

    # Build wheels with maturin
    maturin build --release --out ../dist

    Set-Location ".."
    Info "Rust extension built successfully!"
}

# Test local install
function Test-Install {
    Info "Testing local installation..."

    # Create virtual environment
    python -m venv test-env

    # Activate and install
    & "./test-env/Scripts/Activate.ps1"
    pip install -e ".[all]"

    # Test
    pyneat --version
    pyneat rules

    # Cleanup
    deactivate
    Remove-Item -Recurse -Force "test-env"

    Info "Local installation test passed!"
}

# Upload to PyPI
function Upload-PyPI {
    Info "Uploading to PyPI..."

    if (-not $env:PYPI_TOKEN) {
        Warn "No PYPI_TOKEN environment variable set."
        Warn "Set it with: `$env:PYPI_TOKEN = 'your_token'"
        Warn "Or use twine directly with credentials."
    }

    twine upload dist/*
    Info "Upload complete!"
}

# Upload to TestPyPI
function Upload-TestPyPI {
    Info "Uploading to TestPyPI..."
    twine upload --repository testpypi dist/*
    Info "TestPyPI upload complete!"
}

# Main
if ($Clean) {
    Clean-Build
}
elseif ($Test) {
    Build-Python
    Test-Install
}
elseif ($Upload) {
    Build-Python
    Upload-PyPI
}
elseif ($TestUpload) {
    Build-Python
    Upload-TestPyPI
}
elseif ($Rust) {
    Build-Rust
}
elseif ($All) {
    Build-Python
    Build-Rust
}
else {
    Build-Python
    Info "Done! Files in dist/"
    Info ""
    Info "To upload to PyPI:"
    Info '  $env:PYPI_TOKEN = "your_token"'
    Info "  .\build.ps1 -Upload"
    Info ""
    Info "To test locally:"
    Info "  .\build.ps1 -Test"
}
