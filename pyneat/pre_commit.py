"""Pre-commit hook integration for PyNeat.

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

For commercial licensing, contact: license@pyneat.dev

Install:
    pip install pyneat

Usage in .pre-commit-config.yaml:

    repos:
      - repo: local
        hooks:
          - id: pyneat-clean
            name: PyNeat Code Cleaner
            entry: pyneat clean --diff --dry-run
            language: system
            files: \.py$
            stages: [pre-commit]

Or install the hook directly:

    pre-commit install --hook-type pre-commit --hook-id pyneat-clean
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Optional


def get_staged_files() -> List[str]:
    """Get list of staged .py files from git."""
    try:
        import subprocess
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return []
        files = result.stdout.strip().split("\n")
        return [f for f in files if f.endswith(".py") and f]
    except Exception:
        return []


def get_files_from_args() -> List[str]:
    """Get list of .py files from pre-commit arguments or environment."""
    files = []

    if os.environ.get("PRE_COMMIT"):
        files = get_staged_files()

    if not files and len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            path = Path(arg)
            if path.is_file() and path.suffix == ".py":
                files.append(str(path))
            elif path.is_dir():
                files.extend(str(p) for p in path.rglob("*.py"))

    if not files:
        return []

    return list(dict.fromkeys(files))


def run_pyneat(files: List[str]) -> int:
    """Run pyneat clean on the given files."""
    import subprocess

    if not files:
        return 0

    for file_path in files:
        result = subprocess.run(
            [sys.executable, "-m", "pyneat", "clean", file_path, "--dry-run"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"PyNeat found issues in {file_path}", file=sys.stderr)
            if result.stdout:
                print(result.stdout, file=sys.stderr)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            return 1

    return 0


def main() -> int:
    """Main entry point for pre-commit hook."""
    files = get_files_from_args()
    if not files:
        return 0
    return run_pyneat(files)


if __name__ == "__main__":
    sys.exit(main())
