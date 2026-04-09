"""Rust Scanner Integration for PyNEAT.

This module provides a Python wrapper around the Rust-based pyneat-rs scanner,
enabling high-performance security scanning using tree-sitter and regex patterns.

Copyright (c) 2024-2026 PyNEAT Authors
"""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable

logger = logging.getLogger(__name__)


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
            # Current working directory
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
            import pyneat_rs
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
            elif self._binary_path == "<pymodule>":
                import pyneat_rs
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

    def _scan_via_pymodule(self, code: str) -> List[Dict[str, Any]]:
        """Scan using the Python extension module."""
        import pyneat_rs
        result = pyneat_rs.scan_security(code)
        return json.loads(result)

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
                import pyneat_rs
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
                import pyneat_rs
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
