"""CLI-driven test framework for PyNEAT.

This module provides a framework for testing CLI commands by running
them as subprocesses and verifying the output — rather than importing
modules directly. This catches the real user experience.

Usage:
    from pyneat.cli.testing.cli_tester import CLITester, TestResult

    tester = CLITester(verbose=True)
    result = tester.run("pyneat test --lang python")
    print(result)
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------

@dataclass
class TestResult:
    """Result of a single CLI test."""

    name: str
    passed: bool
    return_code: int
    stdout: str
    stderr: str
    duration_ms: float
    expected_return: int = 0
    expected_contains: Optional[str] = None
    expected_not_contains: Optional[str] = None
    expected_severity: Optional[str] = None
    error_message: Optional[str] = None

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        icon = "[OK]" if self.passed else "[!!]"
        lines = [f"{icon} {self.name} ({self.duration_ms:.1f}ms)"]
        if not self.passed and self.error_message:
            lines.append(f"    Error: {self.error_message}")
        if self.return_code != self.expected_return:
            lines.append(f"    Exit code: {self.return_code} (expected {self.expected_return})")
        return " ".join(lines)


@dataclass
class TestCase:
    """Definition of a single test case."""

    name: str
    input_code: str
    lang: str = "python"
    command: str = "clean"
    expected_contains: Optional[str] = None
    expected_not_contains: Optional[str] = None
    expected_severity: Optional[str] = None
    expected_return: int = 0
    flags: list[str] = field(default_factory=list)
    timeout: int = 30

    def build_command(self, pyneat_path: Optional[str] = None) -> list[str]:
        """Build the CLI command for this test case."""
        cmd = [pyneat_path or sys.executable, "-m", "pyneat", self.command]

        if self.lang and self.lang != "python":
            cmd.extend(["--lang", self.lang])

        cmd.extend(self.flags)
        return cmd


# --------------------------------------------------------------------------
# CLI Tester
# --------------------------------------------------------------------------

class CLITester:
    """Runs PyNEAT CLI commands as subprocesses and validates output.

    Args:
        verbose: Print verbose output during tests.
        pyneat_path: Path to the pyneat binary/script. Defaults to sys.executable -m pyneat.
        temp_dir: Directory for temporary test files. Defaults to system temp.
    """

    def __init__(
        self,
        verbose: bool = False,
        pyneat_path: Optional[str] = None,
        temp_dir: Optional[Path] = None,
    ):
        self.verbose = verbose
        self.pyneat_path = pyneat_path
        self.temp_dir = temp_dir or Path(tempfile.gettempdir()) / "pyneat_cli_tests"
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def _make_temp_file(self, content: str, suffix: str = ".py") -> Path:
        """Create a temporary file with the given content."""
        import uuid
        path = self.temp_dir / f"test_{uuid.uuid4().hex[:8]}{suffix}"
        path.write_bytes(content.encode("utf-8", errors="replace"))
        return path

    def run_command(
        self,
        cmd: list[str],
        input_file: Optional[Path] = None,
        timeout: int = 30,
        capture_output: bool = True,
    ) -> tuple[int, str, str, float]:
        """Run a CLI command with optional file argument.

        Returns (return_code, stdout, stderr, duration_ms).
        """
        actual_cmd = cmd[:]
        if input_file:
            actual_cmd.append(str(input_file))

        start = time.time()
        try:
            result = subprocess.run(
                actual_cmd,
                capture_output=capture_output,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=timeout,
            )
            duration_ms = (time.time() - start) * 1000
            return result.returncode, result.stdout or "", result.stderr or "", duration_ms
        except subprocess.TimeoutExpired as e:
            duration_ms = (time.time() - start) * 1000
            stdout = e.stdout.decode('utf-8', errors='replace') if e.stdout else ""
            stderr = e.stderr.decode('utf-8', errors='replace') if e.stderr else f"Timeout after {timeout}s"
            return -1, stdout, stderr, duration_ms
        except Exception as e:
            duration_ms = (time.time() - start) * 1000
            return -1, "", str(e), duration_ms

    def run_test_case(self, case: TestCase) -> TestResult:
        """Run a single test case end-to-end via CLI subprocess."""
        input_file = self._make_temp_file(
            case.input_code,
            suffix=self._suffix_for_lang(case.lang),
        )

        cmd = [sys.executable, "-m", "pyneat", case.command]
        if case.lang and case.lang != "python":
            cmd.extend(["--lang", case.lang])
        cmd.extend(case.flags)

        return_code, stdout, stderr, duration_ms = self.run_command(
            cmd, input_file=input_file, timeout=case.timeout
        )

        error_message: Optional[str] = None
        passed = True

        if return_code != case.expected_return:
            passed = False
            error_message = f"Exit code {return_code}, expected {case.expected_return}"

        if case.expected_contains and case.expected_contains not in stdout:
            passed = False
            error_message = f"Expected output to contain: {case.expected_contains}"

        if case.expected_not_contains and case.expected_not_contains in stdout:
            passed = False
            error_message = f"Expected output NOT to contain: {case.expected_not_contains}"

        if case.expected_severity:
            sev_upper = case.expected_severity.upper()
            if sev_upper not in stdout.upper():
                passed = False
                error_message = f"Expected severity '{case.expected_severity}' in output"

        return TestResult(
            name=case.name,
            passed=passed,
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            expected_return=case.expected_return,
            expected_contains=case.expected_contains,
            expected_not_contains=case.expected_not_contains,
            expected_severity=case.expected_severity,
            error_message=error_message,
        )

    def run(
        self,
        command: str,
        args: Optional[list[str]] = None,
        expected_return: int = 0,
        expected_contains: Optional[str] = None,
        expected_not_contains: Optional[str] = None,
        timeout: int = 30,
    ) -> TestResult:
        """Run an arbitrary CLI command and validate the output.

        Args:
            command: The CLI subcommand to run (e.g., "clean", "check --lang python")
            args: Additional arguments to append.
            expected_return: Expected process exit code.
            expected_contains: String that must appear in stdout.
            expected_not_contains: String that must NOT appear in stdout.
            timeout: Seconds before timeout.

        Returns:
            TestResult with pass/fail and output details.
        """
        parts = command.split()
        cmd = [sys.executable, "-m"] + parts
        if args:
            cmd.extend(args)

        return_code, stdout, stderr, duration_ms = self.run_command(
            cmd, timeout=timeout
        )

        error_message: Optional[str] = None
        passed = True

        if return_code != expected_return:
            passed = False
            error_message = f"Exit code {return_code}, expected {expected_return}"

        if expected_contains and expected_contains not in stdout:
            passed = False
            error_message = f"Expected output to contain: {expected_contains}"

        if expected_not_contains and expected_not_contains in stdout:
            passed = False
            error_message = f"Expected output NOT to contain: {expected_not_contains}"

        return TestResult(
            name=command,
            passed=passed,
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            expected_return=expected_return,
            expected_contains=expected_contains,
            expected_not_contains=expected_not_contains,
            error_message=error_message,
        )

    def run_suite(
        self,
        cases: list[TestCase],
        stop_on_first_failure: bool = False,
    ) -> tuple[int, int, list[TestResult]]:
        """Run a suite of test cases.

        Args:
            cases: List of TestCase definitions.
            stop_on_first_failure: Stop after first failure.

        Returns:
            Tuple of (passed_count, failed_count, results).
        """
        results: list[TestResult] = []
        passed_count = 0
        failed_count = 0

        for case in cases:
            result = self.run_test_case(case)
            results.append(result)

            if result.passed:
                passed_count += 1
            else:
                failed_count += 1
                if self.verbose:
                    print(f"    {result}")

            if not result.passed and stop_on_first_failure:
                break

        return passed_count, failed_count, results

    def _suffix_for_lang(self, lang: str) -> str:
        """Map language to file extension."""
        suffix_map = {
            "javascript": ".js",
            "typescript": ".ts",
            "go": ".go",
            "java": ".java",
            "rust": ".rs",
            "csharp": ".cs",
            "php": ".php",
            "ruby": ".rb",
            "python": ".py",
        }
        return suffix_map.get(lang.lower(), ".py")
