"""
PyNeat Examples Package

Copyright (c) 2026 PyNEAT Authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

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
