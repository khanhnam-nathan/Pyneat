"""PyNEAT CLI - Re-exported from pyneat.cli for backward compatibility.

The main CLI implementation lives in `pyneat/cli/cli_impl.py`.
"""

# Re-export everything from the modular CLI package
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
