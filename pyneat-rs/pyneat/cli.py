"""PyNEAT CLI - Backward compatibility shim.

The main CLI lives in pyneat_cli.cli:main().
This shim re-exports the Click CLI group for:
  - python -m pyneat  (via __main__.py)
  - any external code doing: from pyneat.cli import cli
"""

from pyneat.cli.cli_impl import (
    cli,
    clean,
    clean_dir,
    check,
    rules,
    explain,
    ignore,
    report,
    audit_deps,
    sbom_cmd,
    mcp,
    lsp,
    test_cmd,
)

__all__ = [
    'cli',
    'clean',
    'clean_dir',
    'check',
    'rules',
    'explain',
    'ignore',
    'report',
    'audit_deps',
    'sbom_cmd',
    'mcp',
    'lsp',
]
