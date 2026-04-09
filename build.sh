#!/bin/bash
# PyNEAT Build Script - Unix/Linux/macOS
#
# Usage:
#   ./build.sh              # Build sdist and wheels
#   ./build.sh --test       # Test build locally
#   ./build.sh --upload     # Upload to PyPI
#   ./build.sh --clean      # Clean build artifacts

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Clean function
clean() {
    info "Cleaning build artifacts..."
    rm -rf dist/ build/ *.egg-info/
    rm -rf pyneat.egg-info/
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    info "Clean complete!"
}

# Build Python package
build_python() {
    info "Building Python package..."

    # Clean first
    clean

    # Build sdist and wheel
    python -m build
    info "Python package built successfully!"
    info "Output: dist/"
}

# Build Rust extension
build_rust() {
    info "Building Rust extension..."
    cd pyneat-rs

    # Build release
    cargo build --release

    # Build wheels with maturin
    maturin build --release --out ../dist

    cd ..
    info "Rust extension built successfully!"
}

# Test local install
test_install() {
    info "Testing local installation..."

    # Create virtual environment
    python -m venv test-env
    source test-env/bin/activate

    # Install package
    pip install -e ".[all]"

    # Test
    pyneat --version
    pyneat rules

    # Cleanup
    deactivate
    rm -rf test-env

    info "Local installation test passed!"
}

# Upload to PyPI
upload() {
    info "Uploading to PyPI..."

    if [ ! -f "~/.pypirc" ] && [ -z "$PYPI_TOKEN" ]; then
        warn "No PyPI token found. Set PYPI_TOKEN environment variable."
        warn "Or create ~/.pypirc with your credentials."
    fi

    twine upload dist/*
    info "Upload complete!"
}

# Upload to TestPyPI
upload_test() {
    info "Uploading to TestPyPI..."
    twine upload --repository testpypi dist/*
    info "TestPyPI upload complete!"
}

# Main
case "${1:-}" in
    --clean)
        clean
        ;;
    --test)
        build_python
        test_install
        ;;
    --upload)
        build_python
        upload
        ;;
    --test-upload)
        build_python
        upload_test
        ;;
    --rust)
        build_rust
        ;;
    --all)
        build_python
        build_rust
        ;;
    *)
        build_python
        info "Done! Files in dist/"
        info ""
        info "To upload to PyPI:"
        info "  PYPI_TOKEN=your_token ./build.sh --upload"
        info ""
        info "To test locally:"
        info "  ./build.sh --test"
        ;;
esac
