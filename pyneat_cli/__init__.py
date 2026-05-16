"""PyNeat CLI — Self-contained CLI entry point.

Separated from the pyneat API package so that the CLI entry point
does not depend on how maturin/Rust packages the .pyd extension.
"""

__version__ = "3.2.0"
__version_info__ = tuple(__version__.split("."))

from pyneat_cli.cli import main

__all__ = ["main", "__version__"]
