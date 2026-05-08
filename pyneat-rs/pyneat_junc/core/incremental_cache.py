"""Incremental scanning cache using file-hash comparison.

This module provides file-level incremental scanning by tracking file hashes.
Only files whose content or modification time has changed are reprocessed.
"""

from __future__ import annotations

import hashlib
import json
import os
import logging
from pathlib import Path
from typing import Dict, Set

logger = logging.getLogger(__name__)

CACHE_DIR = ".pyneat-cache"
CACHE_FILE = "file_hashes.json"


class IncrementalCache:
    """File-hash based incremental scanning cache.

    Tracks files by computing a fast hash from path + mtime + size.
    Files are only reprocessed when their hash changes.
    """

    def __init__(self, cache_dir: str = CACHE_DIR):
        self.cache_dir = Path(cache_dir)
        self.cache_file = self.cache_dir / CACHE_FILE
        self._cache: Dict[str, str] = {}

    def load(self) -> "IncrementalCache":
        """Load cache from disk. Returns self for chaining."""
        if self.cache_file.exists():
            try:
                self._cache = json.loads(self.cache_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Failed to load incremental cache: {e}. Starting fresh.")
                self._cache = {}
        return self

    def save(self) -> None:
        """Persist cache to disk."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(
                json.dumps(self._cache, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
        except OSError as e:
            logger.warning(f"Failed to save incremental cache: {e}")

    def compute_hash(self, path: Path) -> str:
        """Compute a fast hash for a file based on path + mtime + size."""
        try:
            stat = path.stat()
            key = f"{path}:{stat.st_mtime}:{stat.st_size}"
            return hashlib.md5(key.encode("utf-8")).hexdigest()
        except OSError:
            return ""

    def should_process(self, path: Path) -> bool:
        """Return True if the file needs reprocessing.

        Updates the cached hash for the file.
        """
        current_hash = self.compute_hash(path)
        cached_hash = self._cache.get(str(path), "")
        if cached_hash != current_hash:
            self._cache[str(path)] = current_hash
            return True
        return False

    def filter_changed(self, paths: list[Path]) -> list[Path]:
        """Return only files that have changed since last scan."""
        return [p for p in paths if self.should_process(p)]

    def get_unchanged_count(self, total: int, changed_count: int) -> int:
        """Calculate how many files were unchanged."""
        return total - changed_count

    def get_stats(self) -> Dict:
        """Return cache statistics."""
        return {
            "tracked_files": len(self._cache),
            "cache_file": str(self.cache_file),
        }
