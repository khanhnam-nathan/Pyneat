"""Shared core utilities for PyNEAT CLI commands.

This module provides shared helpers like logo printing, config loading,
and engine building that are used across multiple commands.

Copyright (c) 2026 PyNEAT Authors
"""

# Re-export from the main cli implementation for convenience
from pyneat.cli.cli_impl import (
    _print_logo,
    _build_engine,
    _load_config,
    show_diff,
    _inject_pyneat_comments,
)

__all__ = [
    '_print_logo',
    '_build_engine',
    '_load_config',
    'show_diff',
    '_inject_pyneat_comments',
]
