"""
PyNeat Examples Package

This package contains example scripts demonstrating various PyNeat features.

Examples:
    - basic_usage.py: Scan and clean a single file
    - security_scan.py: Security scanning with SARIF export
    - batch_processing.py: Process entire projects
    - custom_rule.py: Create and use custom rules
    - pre_commit_integration.py: Integrate with pre-commit hooks
"""

from .basic_usage import run_basic_example
from .security_scan import run_security_example
from .batch_processing import run_batch_example

__all__ = [
    "run_basic_example",
    "run_security_example",
    "run_batch_example",
]
