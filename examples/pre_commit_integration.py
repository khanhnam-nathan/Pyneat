#!/usr/bin/env python3
"""
PyNeat Pre-commit Integration Example

Copyright (c) 2026 PyNEAT Authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

This example demonstrates integrating PyNeat with pre-commit hooks:
1. Configure pre-commit for PyNeat
2. Create a pre-commit configuration
3. Run pre-commit on staged files

Run: python examples/pre_commit_integration.py
"""

import sys
import subprocess
import os
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyneat.pre_commit import get_staged_files, run_pyneat


def check_pre_commit_installed() -> bool:
    """Check if pre-commit is installed."""
    try:
        subprocess.run(
            ["pre-commit", "--version"],
            capture_output=True,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def create_pre_commit_config() -> Path:
    """Create a sample pre-commit configuration file."""
    config_content = '''# Pre-commit configuration for PyNeat
# See https://pre-commit.com for more information
repos:
  - repo: local
    hooks:
      - id: pyneat-security
        name: PyNeat Security Scan
        entry: pyneat check
        language: system
        types: [python]
        pass_filenames: true
        stages: [pre-commit, push]

      - id: pyneat-clean
        name: PyNeat Clean (Dry Run)
        entry: pyneat clean --dry-run --diff
        language: system
        types: [python]
        pass_filenames: true
        stages: [pre-commit]

      - id: pyneat-check
        name: PyNeat Check Mode
        entry: pyneat clean --check
        language: system
        types: [python]
        pass_filenames: true
        stages: [push]
'''
    config_path = Path(".pre-commit-config.yaml")
    if not config_path.exists():
        config_path.write_text(config_content)
        print(f"    Created: {config_path}")
    else:
        print(f"    File already exists: {config_path}")
    return config_path


def run_pre_commit_check(files: List[str]) -> bool:
    """
    Run PyNeat check on specified files.
    Simulates what pre-commit would do.
    """
    print(f"\n[3] Running PyNeat check on {len(files)} file(s)...")
    print("    Files:", ", ".join(files))

    all_passed = True
    for file in files:
        result = run_pyneat([file], check_only=True)
        if not result:
            all_passed = False
            print(f"    FAIL: {file}")
        else:
            print(f"    PASS: {file}")

    return all_passed


def setup_git_repo() -> bool:
    """Ensure we're in a git repository."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip() == "true"
    except subprocess.CalledProcessError:
        return False


def run_pre_commit_example():
    """Run pre-commit integration example."""
    print("=" * 60)
    print("PyNeat Pre-commit Integration Example")
    print("=" * 60)

    # Check git repository
    print("\n[1] Checking git repository...")
    in_git_repo = setup_git_repo()
    if not in_git_repo:
        print("    Not in a git repository. Some features limited.")
    else:
        print("    Git repository detected.")

    # Check pre-commit installation
    print("\n[2] Checking pre-commit installation...")
    pre_commit_installed = check_pre_commit_installed()
    if pre_commit_installed:
        print("    pre-commit is installed.")
    else:
        print("    pre-commit is NOT installed.")
        print("    Install with: pip install pre-commit")

    # Create sample pre-commit config
    print("\n[3] Pre-commit configuration:")
    config_path = create_pre_commit_config()

    # Show configuration content
    print("\n[4] Configuration content:")
    print("-" * 40)
    for line in config_path.read_text().split("\n"):
        print(f"    {line}")
    print("-" * 40)

    # Show how to use with pre-commit
    print("\n[5] How to use with pre-commit:")
    print("    # Install pre-commit hooks")
    print("    pip install pre-commit")
    print("    pre-commit install")
    print()
    print("    # Run on staged files")
    print("    git add *.py")
    print("    pre-commit run")
    print()
    print("    # Run on all files")
    print("    pre-commit run --all-files")
    print()
    print("    # Update hook versions")
    print("    pre-commit autoupdate")

    # Simulate pre-commit check
    print("\n[6] Simulating pre-commit check...")
    sample_files = [
        "__init__.py",
        "examples/__init__.py",
    ]

    # Check if files exist
    existing_files = [f for f in sample_files if Path(f).exists()]
    if existing_files:
        success = run_pre_commit_check(existing_files)
        if success:
            print("\n    All checks passed!")
        else:
            print("\n    Some checks failed.")
    else:
        print("    Sample files not found. Creating test file...")
        test_file = Path("test_precommit.py")
        test_file.write_text('''
import utils

def bad_function():
    x != None
    print("debug")
''')
        print(f"    Created test file: {test_file}")
        print("    Run 'python examples/pre_commit_integration.py' again to test.")

    # PyNeat pre-commit module usage
    print("\n[7] Using PyNeat pre-commit module programmatically:")
    print("""
    from pyneat.pre_commit import get_staged_files, run_pyneat

    # Get files staged in git
    staged = get_staged_files()

    # Run pyneat check
    result = run_pyneat(staged, check_only=True)
    if not result:
        sys.exit(1)  # Fail the commit
    """)

    print("\n" + "=" * 60)
    print("Pre-commit integration example completed!")
    print("=" * 60)


if __name__ == "__main__":
    run_pre_commit_example()
