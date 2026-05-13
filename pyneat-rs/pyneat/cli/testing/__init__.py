"""PyNEAT CLI testing package.

Provides a CLI-driven test framework that runs actual pyneat commands
as subprocesses to validate the user experience end-to-end.
"""

from pyneat.cli.testing.cli_tester import CLITester, TestCase, TestResult
from pyneat.cli.testing.test_cases import (
    ALL_LANG_CASES,
    ALL_LANGUAGES,
    get_all_test_cases,
    get_test_cases,
    get_test_cases_for_command,
)

__all__ = [
    'CLITester',
    'TestCase',
    'TestResult',
    'ALL_LANG_CASES',
    'ALL_LANGUAGES',
    'get_all_test_cases',
    'get_test_cases',
    'get_test_cases_for_command',
]
