"""Type stubs for pyneat_rs - Rust-accelerated security scanner.

This module provides type annotations for the Rust extension module.
Generated from: pyneat-rs/src/lib.rs
"""

from typing import Any

def scan_security(code: str) -> str:
    """Scan Python code for security vulnerabilities.

    Args:
        code: Python source code to scan

    Returns:
        JSON string containing list of findings
    """
    ...

def apply_auto_fix(code: str, finding_json: str) -> str:
    """Apply auto-fix to code.

    Args:
        code: Original source code
        finding_json: JSON-encoded finding with replacement

    Returns:
        Fixed code
    """
    ...

def version() -> str:
    """Get scanner version.

    Returns:
        Version string in format 'pyneat-rs vX.Y.Z'
    """
    ...

def get_rules() -> str:
    """Get all available security rules.

    Returns:
        JSON string containing list of rule metadata
    """
    ...

__version__: str
