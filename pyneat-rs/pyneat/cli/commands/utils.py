"""Shared utilities for CLI commands.

Provides LanguageRegistry, unified file collection, and other
cross-command helpers.

Copyright (c) 2026 PyNEAT Authors
"""

from pathlib import Path
from typing import Optional


# --------------------------------------------------------------------------
# Language Registry
# --------------------------------------------------------------------------

LANG_EXT_GLOBS: dict[str, list[str]] = {
    "javascript": ["*.js", "*.jsx", "*.mjs", "*.cjs"],
    "typescript": ["*.ts", "*.tsx"],
    "go": ["*.go"],
    "java": ["*.java"],
    "rust": ["*.rs"],
    "csharp": ["*.cs"],
    "php": ["*.php"],
    "ruby": ["*.rb"],
    "python": ["*.py"],
}

LANG_EXT_MAP: dict[str, str] = {
    "js": "javascript",
    "jsx": "javascript",
    "mjs": "javascript",
    "cjs": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "go": "go",
    "java": "java",
    "rs": "rust",
    "cs": "csharp",
    "php": "php",
    "rb": "ruby",
    "py": "python",
}


def detect_language_from_extension(ext: str) -> Optional[str]:
    """Detect language from a file extension (with or without leading dot).

    Returns the canonical language name (e.g. "javascript") or None.
    """
    ext = ext.lstrip(".")
    return LANG_EXT_MAP.get(ext.lower())


def validate_language(lang: str) -> bool:
    """Check if a language name/alias is supported."""
    key = lang.lower()
    return key in LANG_EXT_GLOBS or key in LANG_EXT_MAP


def get_language_key(lang: str) -> str:
    """Normalize a language name/alias to a canonical key."""
    key = lang.lower()
    return LANG_EXT_MAP.get(key, key)


def collect_files_by_lang(
    directory: Path,
    lang: str,
    skip_dirs: Optional[list[str]] = None,
) -> list[Path]:
    """Collect all files matching the given language's glob patterns.

    Args:
        directory: Root directory to search.
        lang: Language name (e.g. "javascript", "python").
        skip_dirs: Directory names to skip (e.g. ["__pycache__", ".venv"]).

    Returns:
        Sorted list of matching file paths.
    """
    if skip_dirs is None:
        skip_dirs = ["__pycache__", ".venv", "venv", ".git", "node_modules"]

    lang_key = get_language_key(lang)
    globs = LANG_EXT_GLOBS.get(lang_key, [])

    if not globs:
        return []

    files: list[Path] = []
    for pattern in globs:
        files.extend(directory.rglob(pattern))

    return sorted([
        f for f in files
        if not any(skip in f.parts for skip in skip_dirs)
    ])


def collect_python_files(directory: Path, pattern: str = "*.py") -> list[Path]:
    """Collect Python files matching a glob pattern."""
    skip = ["__pycache__", ".venv", "venv", ".git", "node_modules", ".pytest_cache", ".egg-info"]
    files = list(directory.rglob(pattern))
    return sorted([
        f for f in files
        if not any(skip_name in f.parts for skip_name in skip)
    ])


# --------------------------------------------------------------------------
# Path resolution helpers
# --------------------------------------------------------------------------

def resolve_target_path(target: str) -> Optional[Path]:
    """Resolve a target string to an existing Path.

    Tries in order:
    1. As-is (relative to cwd)
    2. Relative to cwd
    3. Recursive rglob search (for bare filenames)
    """
    target_path = Path(target)

    if target_path.is_absolute():
        return target_path if target_path.exists() else None

    if target_path.exists():
        return target_path

    cwd_path = Path.cwd() / target
    if cwd_path.exists():
        return cwd_path

    if target_path.suffix and "." in target:
        matches = list(Path.cwd().rglob(target))
        if len(matches) == 1:
            return matches[0]

    return None


# --------------------------------------------------------------------------
# Shared config
# --------------------------------------------------------------------------

SKIP_DIRS: list[str] = [
    "__pycache__",
    ".venv",
    "venv",
    ".git",
    "node_modules",
    ".pytest_cache",
    ".egg-info",
]
