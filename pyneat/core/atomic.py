"""Atomic file writer — ensures no data loss on crash.

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

All writes go through a temporary file → compile check → atomic rename.
On any failure the original file remains untouched.
"""

from __future__ import annotations

import atexit
import logging
import os
import py_compile
import shutil
import sys
from pathlib import Path
from typing import Optional, Set

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Cleanup on interpreter shutdown
# --------------------------------------------------------------------------

_TMP_PATTERNS: Set[Path] = set()


def _register_tmp(tmp_path: Path) -> None:
    _TMP_PATTERNS.add(tmp_path)


def _cleanup_tmp_files() -> None:
    """Remove any leftover .pyneat_tmp files on interpreter exit."""
    for tmp_path in list(_TMP_PATTERNS):
        try:
            if tmp_path.exists():
                tmp_path.unlink()
                logger.debug("Cleaned up temporary file: %s", tmp_path)
        except OSError as e:
            logger.warning("Failed to clean up %s: %s", tmp_path, e)


atexit.register(_cleanup_tmp_files)


# --------------------------------------------------------------------------
# AtomicWriter
# --------------------------------------------------------------------------

class AtomicWriter:
    """Writes files atomically: tmp → compile → rename.

    Guarantees the original file is never corrupted, even if:
    - The process crashes mid-write
    - A SyntaxError is found in the content
    - Disk I/O fails partway

    Usage::

        writer = AtomicWriter()
        success = writer.write(Path("myfile.py"), "# new content")
    """

    TMP_SUFFIX: str = ".pyneat_tmp"

    def write(self, file_path: Path, content: str) -> bool:
        """Atomically write content to file_path.

        Args:
            file_path: Destination file. Parent directory must exist.
            content: New file contents.

        Returns:
            True if write succeeded (original replaced) OR content unchanged (no-op).
            False if write failed (original untouched, tmp deleted).
        """
        tmp_path = file_path.with_suffix(self.TMP_SUFFIX)

        # Normalize: strip any leading BOM so it never leaks into written content
        UTF8_BOM = "\ufeff"
        normalized_content = content.lstrip(UTF8_BOM)

        # No-op: content unchanged — skip write entirely
        try:
            current_raw = file_path.read_bytes()
            current = current_raw.decode("utf-8-sig")
        except FileNotFoundError:
            current = None

        if current is not None and current == normalized_content:
            logger.debug(
                "AtomicWriter: content unchanged for %s, skipping write",
                file_path,
            )
            return True  # no-op: not a failure

        try:
            # Write normalized content (no BOM)
            tmp_path.write_text(normalized_content, encoding="utf-8")
            _register_tmp(tmp_path)

            # Full compile check — write to tmp so we can compile from file
            try:
                compile_check_path = tmp_path.with_suffix(".compile_check.py")
                try:
                    compile_check_path.write_text(normalized_content, encoding="utf-8")
                    py_compile.compile(str(compile_check_path), doraise=True)
                finally:
                    compile_check_path.unlink(missing_ok=True)
            except (SyntaxError, py_compile.PyCompileError):
                logger.warning(
                    "AtomicWriter: syntax error in %s, rolling back",
                    file_path,
                )
                tmp_path.unlink(missing_ok=True)
                _TMP_PATTERNS.discard(tmp_path)
                return False

            # Atomic rename — this is the only point where original is modified
            tmp_path.replace(file_path)
            _TMP_PATTERNS.discard(tmp_path)
            logger.debug("AtomicWriter: successfully wrote %s", file_path)
            return True

        except OSError as e:
            logger.error("AtomicWriter: I/O error writing %s: %s", file_path, e)
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            _TMP_PATTERNS.discard(tmp_path)
            return False

    def write_batch(self, items: list[tuple[Path, str]]) -> dict[Path, bool]:
        """Write multiple files atomically.

        Args:
            items: List of (file_path, content) tuples.

        Returns:
            Dict mapping each file_path to True (success) or False (failure).
        """
        results: dict[Path, bool] = {}
        for file_path, content in items:
            results[file_path] = self.write(file_path, content)
        return results

    def backup(self, file_path: Path) -> Optional[Path]:
        """Create a backup copy of file_path next to the original.

        Args:
            file_path: File to back up.

        Returns:
            Path to the backup file, or None if the original doesn't exist.
        """
        if not file_path.exists():
            return None

        backup_path = file_path.with_suffix(file_path.suffix + ".pyneat.bak")
        shutil.copy2(file_path, backup_path)
        return backup_path

    def rollback(self, backup_path: Path, original_path: Path) -> bool:
        """Restore file from a backup.

        Args:
            backup_path: Path to the backup file.
            original_path: Path to restore to.

        Returns:
            True if restore succeeded.
        """
        try:
            shutil.copy2(backup_path, original_path)
            return True
        except OSError as e:
            logger.error("AtomicWriter: rollback failed for %s: %s", original_path, e)
            return False

    def recover_tmp(self, dir_path: Path) -> int:
        """Remove all leftover .pyneat_tmp files in a directory tree.

        Useful for cleanup after an unclean shutdown.

        Args:
            dir_path: Root directory to search.

        Returns:
            Number of files removed.
        """
        count = 0
        for tmp_path in dir_path.rglob(f"*{self.TMP_SUFFIX}"):
            try:
                tmp_path.unlink()
                count += 1
            except OSError as e:
                logger.warning("Failed to remove tmp file %s: %s", tmp_path, e)
        return count
