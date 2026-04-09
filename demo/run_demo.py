"""
PyNEAT 2.2.0-beta - Demo Comparison Script
=========================================

This script demonstrates PyNEAT's capabilities by:
1. Scanning a vulnerable Python file
2. Showing the detected issues
3. Applying auto-fixes
4. Showing the improved code
"""

import subprocess
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEMO_FILE = "demo_security_vulnerabilities.py"


def run_command(cmd):
    """Run shell command and return output."""
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True
    )
    return result.stdout + result.stderr


def main():
    print("=" * 70)
    print("PyNEAT 2.2.0-beta Demo - Security Vulnerability Detection")
    print("=" * 70)
    print()

    # Step 1: Check security vulnerabilities
    print("[Step 1] Running security scan...")
    print("-" * 70)
    output = run_command(f'python -m pyneat.cli check demo/{DEMO_FILE}')
    print(output)
    print()

    # Step 2: Show AI bug patterns
    print("[Step 2] Running AI bug pattern detection...")
    print("-" * 70)
    output = run_command(f'python -m pyneat.cli clean demo/{DEMO_FILE} --enable-ai-bugs')
    print(output[:2000] if len(output) > 2000 else output)
    print()

    # Step 3: Clean code
    print("[Step 3] Cleaning code...")
    print("-" * 70)
    output = run_command(f'python -m pyneat.cli clean demo/{DEMO_FILE}')
    print(output[:2000] if len(output) > 2000 else output)
    print()

    print("=" * 70)
    print("Demo complete! Check the cleaned file in demo/output/")
    print("=" * 70)


if __name__ == "__main__":
    main()
