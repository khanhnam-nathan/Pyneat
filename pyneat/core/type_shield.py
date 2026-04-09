"""Type-aware shield — detects new type errors introduced by transformations.

Copyright (c) 2024-2026 PyNEAT Authors

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

Integrates with mypy or pyright to establish a baseline of type errors
before transformation, then flags any new errors appearing after.
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional, List, Set, Tuple

logger = logging.getLogger(__name__)


class TypeAwareShield:
    """Detects type-checker regressions introduced by code transformations.

    Usage::

        shield = TypeAwareShield("mypy")   # or "pyright"
        baseline = shield.get_baseline(Path("myfile.py"))
        # ... apply transformations ...
        new_errors = shield.check_new_errors(Path("myfile.py"), baseline)
        if new_errors:
            logger.warning("New type errors detected: %s", new_errors)
    """

    def __init__(self, type_checker: str = "mypy", enabled: bool = False):
        """Initialize the shield.

        Args:
            type_checker: "mypy" or "pyright".
            enabled: If False (default), get_baseline and check_new_errors
                are no-ops. Set to True to enable type checking.
        """
        self.type_checker = type_checker
        self.enabled = enabled

    # --------------------------------------------------------------------------
    # Public API
    # --------------------------------------------------------------------------

    def get_baseline(self, file_path: Path) -> Set[str]:
        """Capture the set of type errors present in file_path *before* transformation.

        Returns:
            A frozenset of error strings. Empty if the file has no type errors
            or if the type checker is not available.
        """
        if not self.enabled:
            return set()

        errors = self._run_type_checker(file_path)
        logger.debug("TypeAwareShield baseline for %s: %d errors", file_path, len(errors))
        return set(errors)

    def check_new_errors(
        self,
        file_path: Path,
        baseline: Set[str],
    ) -> List[Tuple[str, int, str]]:
        """Return new type errors not present in the baseline.

        Args:
            file_path: Path to the (already-transformed) file.
            baseline: Set returned by a prior ``get_baseline`` call.

        Returns:
            List of (error_message, line_number, error_code) tuples.
            Empty list means no regressions were introduced.
        """
        if not self.enabled:
            return []

        after_errors = self._run_type_checker(file_path)
        after_set = set(after_errors)

        new_errors = [
            err for err in after_set
            if err not in baseline
        ]

        if new_errors:
            logger.warning(
                "TypeAwareShield: detected %d NEW type errors in %s",
                len(new_errors),
                file_path,
            )

        return [
            (err, self._extract_line(err), self._extract_code(err))
            for err in new_errors
        ]

    def is_available(self) -> bool:
        """Return True if the configured type checker is installed."""
        return self._find_type_checker() is not None

    # --------------------------------------------------------------------------
    # Internals
    # --------------------------------------------------------------------------

    def _run_type_checker(self, file_path: Path) -> List[str]:
        """Run the type checker and return parsed error lines."""
        checker = self._find_type_checker()
        if not checker:
            logger.debug(
                "TypeAwareShield: %s not found, skipping type check",
                self.type_checker,
            )
            return []

        try:
            if self.type_checker == "mypy":
                cmd = [sys.executable, "-m", "mypy", str(file_path), "--no-error-summary"]
            else:  # pyright
                cmd = [
                    sys.executable, "-m", "pyright",
                    "--outputjson",
                    "--stdout",
                    str(file_path),
                ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            return self._parse_errors(result.stdout + result.stderr)

        except subprocess.TimeoutExpired:
            logger.warning("TypeAwareShield: type checker timed out on %s", file_path)
            return []
        except Exception as e:
            logger.warning("TypeAwareShield: failed to run %s: %s", self.type_checker, e)
            return []

    def _find_type_checker(self) -> Optional[str]:
        """Return the path to the type checker if it exists."""
        try:
            if self.type_checker == "mypy":
                result = subprocess.run(
                    [sys.executable, "-m", "mypy", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return "mypy" if result.returncode == 0 else None
            else:
                result = subprocess.run(
                    [sys.executable, "-m", "pyright", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return "pyright" if result.returncode == 0 else None
        except Exception:
            return None

    def _parse_errors(self, output: str) -> List[str]:
        """Parse type-checker stdout/stderr into a list of error strings."""
        errors: List[str] = []

        if self.type_checker == "mypy":
            # Format: "file.py:10: error: message [error-code]"
            pattern = re.compile(
                r"^(.+?):(\d+):\s+(error|warning):\s+(.+?)(?: \[(.+?)\])?$",
                re.MULTILINE,
            )
            for m in pattern.finditer(output):
                errors.append(f"{m.group(1)}:{m.group(2)}: {m.group(4)} [{m.group(5) or '?'}]")

        else:  # pyright
            # JSON output: parse severity + message + line
            import json
            try:
                data = json.loads(output)
                diagnostics = data.get("generalDiagnostics", [])
                for diag in diagnostics:
                    severity = diag.get("severity", "error")
                    if severity in ("error", "warning"):
                        msg = diag.get("message", "")
                        line = diag.get("range", {}).get("start", {}).get("line", 1)
                        errors.append(f"{severity} at line {line}: {msg}")
            except (json.JSONDecodeError, TypeError):
                # Fallback: parse plain text
                for line in output.splitlines():
                    if "error" in line.lower():
                        errors.append(line.strip())

        return errors

    @staticmethod
    def _extract_line(error: str) -> int:
        """Pull the line number out of an error string."""
        m = re.search(r":(\d+):", error)
        return int(m.group(1)) if m else 0

    @staticmethod
    def _extract_code(error: str) -> str:
        """Pull the error code out of an error string."""
        m = re.search(r"\[([^\]]+)\]$", error)
        return m.group(1) if m else ""
