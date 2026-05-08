"""Rust Scanner Integration for PyNEAT.

This module provides a Python wrapper around the Rust-based pyneat-rs scanner,
enabling high-performance security scanning using tree-sitter and regex patterns.

Copyright (c) 2026 PyNEAT Authors
"""

import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Scan options for the Rust scanner
# --------------------------------------------------------------------------

@dataclass
class ScanOptions:
    """Configuration options for a configured security scan.

    All fields are optional. Defaults are used when fields are None.
    """
    language: Optional[str] = None
    rule_ids: Optional[List[str]] = field(default_factory=list)
    severities: Optional[List[str]] = field(default_factory=list)
    ignore_paths: Optional[List[str]] = field(default_factory=list)
    file_path: Optional[str] = None


@dataclass
class ScanResult:
    """Result of a configured security scan from the Rust scanner.

    Contains findings plus scan metadata (timing, rule counts, severity breakdown).
    """
    findings: List[Dict[str, Any]]
    total_lines: int
    language: str
    file_path: Optional[str]
    scan_time_ms: int
    rules_evaluated: int
    severity_counts: Dict[str, int]

    @property
    def critical_count(self) -> int:
        return self.severity_counts.get("critical", 0)

    @property
    def high_count(self) -> int:
        return self.severity_counts.get("high", 0)

    @property
    def medium_count(self) -> int:
        return self.severity_counts.get("medium", 0)

    @property
    def low_count(self) -> int:
        return self.severity_counts.get("low", 0)

    @property
    def info_count(self) -> int:
        return self.severity_counts.get("info", 0)


@dataclass
class BatchFixResult:
    """Result of applying multiple auto-fixes."""
    code: str
    applied: List[str]
    conflicts: int
    errors: List[str]

    @property
    def has_conflicts(self) -> bool:
        return self.conflicts > 0

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0


class RustScanner:
    """Wrapper around the Rust-based pyneat-rs scanner.

    This class provides a Python interface to the high-performance Rust scanner,
    with automatic fallback to the Python-based rules when Rust is unavailable.
    """

    _instance: Optional['RustScanner'] = None
    _available: bool = False
    _binary_path: Optional[str] = None
    _version: Optional[str] = None

    def __new__(cls) -> 'RustScanner':
        """Singleton pattern to ensure only one Rust scanner instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self) -> None:
        """Initialize the Rust scanner.

        Tries to find the Rust binary in common locations and validates it.
        """
        self._find_binary()
        if self._available:
            self._validate_binary()

    def _find_binary(self) -> None:
        """Find the Rust binary in common locations."""
        possible_paths = [
            # Current directory
            Path("pyneat-rs/target/debug/pyneat-rs.exe"),
            Path("pyneat-rs/target/debug/pyneat-rs"),
            # Installed via maturin
            Path(sys.prefix) / "bin" / "pyneat-rs",
            Path(sys.prefix) / "Scripts" / "pyneat-rs.exe",
            # User installation
            Path.home() / ".cargo" / "bin" / "pyneat-rs",
            # Current working directory - prefer release binary (most up-to-date)
            Path.cwd() / "pyneat-rs" / "target" / "release" / "pyneat.exe",
            Path.cwd() / "pyneat-rs" / "target" / "debug" / "pyneat-rs.exe",
            Path.cwd() / "pyneat-rs" / "target" / "debug" / "pyneat.exe",
            Path.cwd() / "pyneat-rs.exe",
            Path.cwd() / "pyneat-rs",
        ]

        for path in possible_paths:
            if path.exists():
                self._binary_path = str(path)
                self._available = True
                logger.info(f"Found Rust scanner at: {path}")
                return

        # Try to use the Python extension module
        try:
            import pyneat
            self._available = True
            self._binary_path = "<pymodule>"
            logger.info("Using pyneat_rs Python extension module")
            return
        except ImportError:
            pass

        # Try cargo run
        cargo_path = Path("pyneat-rs")
        if cargo_path.exists():
            Cargo_toml = cargo_path / "Cargo.toml"
            if Cargo_toml.exists():
                self._available = True
                self._binary_path = "<cargo>"
                logger.info("Rust scanner available via cargo run")

    def _validate_binary(self) -> None:
        """Validate that the Rust binary is working."""
        try:
            if self._binary_path == "<cargo>":
                result = subprocess.run(
                    ["cargo", "run", "--", "--version"],
                    cwd="pyneat-rs",
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    self._version = result.stdout.strip()
                else:
                    self._available = False
                    logger.warning(f"Failed to validate Rust binary: cargo run failed with code {result.returncode}")
                    return
            elif self._binary_path == "<pymodule>":
                import pyneat
                self._version = pyneat_rs.version()
            else:
                result = subprocess.run(
                    [self._binary_path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    self._version = result.stdout.strip()
                else:
                    self._available = False
                    logger.warning(f"Failed to validate Rust binary: binary exited with code {result.returncode}")
                    return
        except Exception as e:
            logger.warning(f"Failed to validate Rust binary: {e}")
            self._available = False

    @property
    def is_available(self) -> bool:
        """Check if the Rust scanner is available."""
        return self._available

    @property
    def version(self) -> Optional[str]:
        """Get the Rust scanner version."""
        return self._version

    def scan(self, code: str, file_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan code for security vulnerabilities using the Rust scanner.

        Args:
            code: Python source code to scan
            file_path: Optional file path for better error reporting

        Returns:
            List of findings as dictionaries
        """
        if not self._available:
            return []

        try:
            if self._binary_path == "<pymodule>":
                return self._scan_via_pymodule(code)
            elif self._binary_path == "<cargo>":
                return self._scan_via_cargo(code, file_path)
            else:
                return self._scan_via_binary(code, file_path)
        except Exception as e:
            logger.error(f"Rust scanner error: {e}")
            return []

    def scan_configured(self, code: str, options: Optional[ScanOptions] = None) -> ScanResult:
        """Scan code with full configuration options.

        Args:
            code: Source code to scan
            options: ScanOptions with language, rule_ids, severities, etc.

        Returns:
            ScanResult with findings, metadata, and severity counts
        """
        if not self._available:
            return ScanResult(
                findings=[], total_lines=0, language="python",
                file_path=None, scan_time_ms=0, rules_evaluated=0,
                severity_counts={},
            )

        if options is None:
            options = ScanOptions()

        try:
            if self._binary_path == "<pymodule>":
                return self._scan_configured_via_pymodule(code, options)
            else:
                # Fall back to basic scan and approximate metadata
                findings = self.scan(code, options.file_path)
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                for f in findings:
                    sev = f.get("severity", "info")
                    if sev in severity_counts:
                        severity_counts[sev] += 1

                return ScanResult(
                    findings=findings,
                    total_lines=code.count("\n") + 1,
                    language=options.language or "python",
                    file_path=options.file_path,
                    scan_time_ms=0,
                    rules_evaluated=0,
                    severity_counts=severity_counts,
                )
        except Exception as e:
            logger.error(f"Rust scanner configured error: {e}")
            return ScanResult(
                findings=[], total_lines=0, language="python",
                file_path=None, scan_time_ms=0, rules_evaluated=0,
                severity_counts={},
            )

    def _scan_via_pymodule(self, code: str) -> List[Dict[str, Any]]:
        """Scan using the Python extension module."""
        import pyneat
        result = pyneat.scan_security(code)
        return json.loads(result)

    def _scan_configured_via_pymodule(self, code: str, options: ScanOptions) -> ScanResult:
        """Scan with full configuration using the Python extension module."""
        import pyneat

        kwargs = {}
        if options.language is not None:
            kwargs["language"] = options.language
        if options.rule_ids:
            kwargs["rule_ids"] = options.rule_ids
        if options.severities:
            kwargs["severities"] = options.severities
        if options.ignore_paths:
            kwargs["ignore_paths"] = options.ignore_paths
        if options.file_path is not None:
            kwargs["file_path"] = options.file_path

        result = pyneat.scan_security_configured(code, **kwargs)
        data = json.loads(result)

        return ScanResult(
            findings=data.get("findings", []),
            total_lines=data.get("total_lines", 0),
            language=data.get("language", "python"),
            file_path=data.get("file_path"),
            scan_time_ms=data.get("scan_time_ms", 0),
            rules_evaluated=data.get("rules_evaluated", 0),
            severity_counts=data.get("severity_counts", {}),
        )

    def _scan_via_cargo(self, code: str, file_path: Optional[str]) -> List[Dict[str, Any]]:
        """Scan using cargo run."""
        result = subprocess.run(
            ["cargo", "run", "--", "scan", "-f", "json"],
            input=code,
            cwd="pyneat-rs",
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse Rust output: {result.stdout[:200]}")
                return []
        return []

    def _scan_via_binary(self, code: str, file_path: Optional[str]) -> List[Dict[str, Any]]:
        """Scan using the direct binary via stdin."""
        result = subprocess.run(
            [self._binary_path, "-f", "json", "check", code],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse Rust output: {result.stdout[:200]}")
                return []
        return []

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a file for security vulnerabilities.

        Args:
            file_path: Path to the Python file to scan

        Returns:
            List of findings as dictionaries
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            return self.scan(code, file_path)
        except Exception as e:
            logger.error(f"Failed to scan file {file_path}: {e}")
            return []

    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all available rules from the Rust scanner.

        Returns:
            List of rule metadata as dictionaries
        """
        if not self._available:
            return []

        try:
            if self._binary_path == "<pymodule>":
                import pyneat
                result = pyneat_rs.get_rules()
                return json.loads(result)
            elif self._binary_path == "<cargo>":
                result = subprocess.run(
                    ["cargo", "run", "--", "rules", "-f", "json"],
                    cwd="pyneat-rs",
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    return json.loads(result.stdout)
            else:
                result = subprocess.run(
                    [self._binary_path, "rules", "-f", "json"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    return json.loads(result.stdout)
        except Exception as e:
            logger.error(f"Failed to get rules from Rust scanner: {e}")

        return []

    def apply_fix(self, code: str, finding: Dict[str, Any]) -> Optional[str]:
        """Apply an auto-fix to code.

        Args:
            code: Original source code
            finding: Finding containing fix information

        Returns:
            Fixed code, or None if fix could not be applied
        """
        if not self._available:
            return None

        try:
            if self._binary_path == "<pymodule>":
                import pyneat
                return pyneat_rs.apply_auto_fix(code, json.dumps(finding))

            # For CLI-based scanner, use subprocess
            result = subprocess.run(
                [self._binary_path, "fix", "-f", "json"],
                input=json.dumps({"code": code, "finding": finding}),
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return json.loads(result.stdout).get("code")
        except Exception as e:
            logger.error(f"Failed to apply fix: {e}")

        return None

    def apply_fixes_batch(self, code: str, findings: List[Dict[str, Any]]) -> BatchFixResult:
        """Apply multiple auto-fixes with conflict resolution.

        Args:
            code: Original source code
            findings: List of findings containing fix information

        Returns:
            BatchFixResult with fixed code, applied rules, conflicts, and errors
        """
        if not self._available:
            return BatchFixResult(code=code, applied=[], conflicts=0, errors=["Rust scanner not available"])

        try:
            if self._binary_path == "<pymodule>":
                import pyneat
                result = pyneat_rs.apply_fixes_batch(code, json.dumps(findings))
                data = json.loads(result)
                return BatchFixResult(
                    code=data.get("code", code),
                    applied=data.get("applied", []),
                    conflicts=data.get("conflicts", 0),
                    errors=data.get("errors", []),
                )
        except Exception as e:
            logger.error(f"Failed to apply fixes batch: {e}")

        return BatchFixResult(code=code, applied=[], conflicts=0, errors=[str(e)])


# Singleton instance
_scanner: Optional[RustScanner] = None


def get_scanner() -> RustScanner:
    """Get the singleton Rust scanner instance.

    Returns:
        The RustScanner singleton instance
    """
    global _scanner
    if _scanner is None:
        _scanner = RustScanner()
    return _scanner


def is_rust_available() -> bool:
    """Check if the Rust scanner is available.

    Returns:
        True if Rust scanner is available, False otherwise
    """
    return get_scanner().is_available


def scan_code(code: str, file_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Convenience function to scan code using the Rust scanner.

    Args:
        code: Python source code to scan
        file_path: Optional file path for better error reporting

    Returns:
        List of findings as dictionaries
    """
    return get_scanner().scan(code, file_path)


def scan_file(file_path: str) -> List[Dict[str, Any]]:
    """Convenience function to scan a file using the Rust scanner.

    Args:
        file_path: Path to the Python file to scan

    Returns:
        List of findings as dictionaries
    """
    return get_scanner().scan_file(file_path)
