"""CLI command modules.

Each module exports a `register_<name>` function that attaches Click commands
to the parent CLI group. This makes it easy to add or remove commands
without touching the main `cli` definition.
"""

from typing import Callable, TYPE_CHECKING

import click

if TYPE_CHECKING:
    # Only for type checking — avoids circular imports at runtime
    pass


# --------------------------------------------------------------------------
# Command registry
# Each tuple: (module_name, function_name)
# --------------------------------------------------------------------------

COMMAND_REGISTRY: list[tuple[str, str]] = [
    # Commands are defined in cli_impl.py as top-level @cli.command() decorators.
    # They are NOT registered via this registry — they are registered
    # directly by the Click decorator in cli_impl.py.
    #
    # This registry is provided for documentation and future command discovery.
]


def get_all_commands() -> list[str]:
    """Return all registered command names."""
    return [name for _, name in COMMAND_REGISTRY]
