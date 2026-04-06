#!/usr/bin/env python3
"""Pre-commit hook for PyNeat - Clean AI-generated Python code before commit.

Install:
    pre-commit install --hook-type pre-commit
    # or
    pre-commit install --hook-type pre-commit --allow-missing-config

Usage:
    Add to .pre-commit-config.yaml:
        repos:
          - repo: local
            hooks:
              - id: pyneat-clean
                name: PyNeat Clean
                entry: pyneat-clean
                language: system
                files: \.py$
                args: [--diff]
"""

import sys
import subprocess
import os
from pathlib import Path


def main():
    """Run pyneat-clean on staged Python files."""
    # Get staged .py files
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True
        )
        staged_files = [
            f.strip() for f in result.stdout.strip().split('\n')
            if f.strip().endswith('.py')
        ]
    except subprocess.CalledProcessError:
        print("Error: Failed to get staged files")
        return 1
    except FileNotFoundError:
        print("Error: git not found in PATH")
        return 1

    if not staged_files:
        print("No Python files staged")
        return 0

    print(f"PyNeat: Checking {len(staged_files)} Python file(s)...")

    # Run pyneat clean on each file
    failed = []
    for filepath in staged_files:
        if not Path(filepath).exists():
            continue

        try:
            result = subprocess.run(
                [sys.executable, "-m", "pyneat", "clean", filepath, "--diff"],
                capture_output=False,
                text=True
            )
            if result.returncode != 0:
                failed.append(filepath)
        except Exception as e:
            print(f"Error running pyneat on {filepath}: {e}")
            failed.append(filepath)

    if failed:
        print(f"\nPyNeat: {len(failed)} file(s) had issues:")
        for f in failed:
            print(f"  - {f}")
        return 1

    print("PyNeat: All files passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
