#!/usr/bin/env python3
"""
Test runner for multi-language samples.
Tests pyneat check and clean commands on all sample files.
"""

import subprocess
import sys
from pathlib import Path

SAMPLES_DIR = Path(__file__).parent

def run_command(cmd, cwd=None):
    """Run a command and return output."""
    print(f"\n{'='*60}")
    print(f"Running: {' '.join(cmd)}")
    print('='*60)
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd or SAMPLES_DIR,
            capture_output=True,
            text=True,
            timeout=60
        )
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("TIMEOUT: Command took too long")
        return -1
    except Exception as e:
        print(f"ERROR: {e}")
        return -1

def test_python():
    """Test Python sample."""
    print("\n" + "="*60)
    print("TESTING: Python Sample")
    print("="*60)
    sample = SAMPLES_DIR / "python" / "sample.py"
    if not sample.exists():
        print(f"NOT FOUND: {sample}")
        return

    run_command(["pyneat", "check", "python/sample.py", "--severity"])
    run_command(["pyneat", "clean", "python/sample.py", "--dry-run"])

def test_javascript():
    """Test JavaScript sample."""
    print("\n" + "="*60)
    print("TESTING: JavaScript Sample")
    print("="*60)
    sample = SAMPLES_DIR / "javascript" / "sample.js"
    if not sample.exists():
        print(f"NOT FOUND: {sample}")
        return

    run_command(["pyneat", "check", "javascript/sample.js", "--lang", "javascript", "--severity"])

def test_go():
    """Test Go sample."""
    print("\n" + "="*60)
    print("TESTING: Go Sample")
    print("="*60)
    sample = SAMPLES_DIR / "go" / "sample.go"
    if not sample.exists():
        print(f"NOT FOUND: {sample}")
        return

    run_command(["pyneat", "check", "go/sample.go", "--lang", "go", "--severity"])

def test_java():
    """Test Java sample."""
    print("\n" + "="*60)
    print("TESTING: Java Sample")
    print("="*60)
    sample = SAMPLES_DIR / "java" / "Sample.java"
    if not sample.exists():
        print(f"NOT FOUND: {sample}")
        return

    run_command(["pyneat", "check", "java/Sample.java", "--lang", "java", "--severity"])

def test_rust():
    """Test Rust sample."""
    print("\n" + "="*60)
    print("TESTING: Rust Sample")
    print("="*60)
    sample = SAMPLES_DIR / "rust" / "sample.rs"
    if not sample.exists():
        print(f"NOT FOUND: {sample}")
        return

    run_command(["pyneat", "check", "rust/sample.rs", "--lang", "rust", "--severity"])

def test_csharp():
    """Test C# sample."""
    print("\n" + "="*60)
    print("TESTING: C# Sample")
    print("="*60)
    sample = SAMPLES_DIR / "csharp" / "Sample.cs"
    if not sample.exists():
        print(f"NOT FOUND: {sample}")
        return

    run_command(["pyneat", "check", "csharp/Sample.cs", "--lang", "csharp", "--severity"])

def test_php():
    """Test PHP sample."""
    print("\n" + "="*60)
    print("TESTING: PHP Sample")
    print("="*60)
    sample = SAMPLES_DIR / "php" / "sample.php"
    if not sample.exists():
        print(f"NOT FOUND: {sample}")
        return

    run_command(["pyneat", "check", "php/sample.php", "--lang", "php", "--severity"])

def test_ruby():
    """Test Ruby sample."""
    print("\n" + "="*60)
    print("TESTING: Ruby Sample")
    print("="*60)
    sample = SAMPLES_DIR / "ruby" / "sample.rb"
    if not sample.exists():
        print(f"NOT FOUND: {sample}")
        return

    run_command(["pyneat", "check", "ruby/sample.rb", "--lang", "ruby", "--severity"])

def main():
    print("PYNEAT MULTI-LANGUAGE TEST SUITE")
    print("="*60)
    print(f"Test samples directory: {SAMPLES_DIR}")
    print("="*60)

    # Test all languages
    test_python()

    # Test other languages (may have limited support)
    test_javascript()
    test_go()
    test_java()
    test_rust()
    test_csharp()
    test_php()
    test_ruby()

    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()
