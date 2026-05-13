"""Entry point for running pyneat as a module.

Usage: python -m pyneat [args]

This module provides the `python -m pyneat` entry point.
The primary entry point for the `pyneat` command is pyneat_cli.cli:main()
(which is registered via [project.scripts.pyneat] in pyproject.toml).

This __main__.py exists as a secondary entry path.
"""

from pyneat.cli.cli_impl import cli

if __name__ == "__main__":
    cli()
