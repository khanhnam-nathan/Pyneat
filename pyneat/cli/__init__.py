"""PyNEAT CLI - Modular command-line interface.

Copyright (c) 2026 PyNEAT Authors

This module provides the pyneat CLI entry point. All commands are
defined in `cli_impl`. Sub-modules provide shared utilities:

- core: Logo, config loading, engine building, helpers
- commands: Individual command implementations (clean, check, etc.)
- testing: CLI-driven test framework for per-language testing
"""

from pyneat.cli.cli_impl import cli

__all__ = ['cli']
