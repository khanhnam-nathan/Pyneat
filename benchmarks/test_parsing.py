"""Benchmark for AST/CST parsing speed."""

import pytest
from pathlib import Path

from pyneat.core.engine import RuleEngine
from pyneat.core.types import CodeFile, RuleConfig
from pyneat.rules.security import SecurityScannerRule

from benchmarks.conftest import generate_python_code, generate_code_with_issues


class TestParsingBenchmark:
    """Benchmark for code parsing operations."""

    def test_parse_100_lines(self, benchmark):
        """Benchmark parsing 100 lines of Python code."""
        code = generate_python_code(100)
        code_file = CodeFile(path=Path("bench.py"), content=code)
        benchmark(code_file.content.splitlines)

    def test_parse_1000_lines(self, benchmark):
        """Benchmark parsing 1000 lines of Python code."""
        code = generate_python_code(1000)
        code_file = CodeFile(path=Path("bench.py"), content=code)
        benchmark(code_file.content.splitlines)

    def test_parse_5000_lines(self, benchmark):
        """Benchmark parsing 5000 lines of Python code."""
        code = generate_python_code(5000)
        code_file = CodeFile(path=Path("bench.py"), content=code)
        benchmark(code_file.content.splitlines)

    def test_engine_init(self, benchmark):
        """Benchmark RuleEngine initialization."""
        benchmark(RuleEngine)

    def test_security_rule_init(self, benchmark):
        """Benchmark SecurityScannerRule initialization."""
        benchmark(SecurityScannerRule)


class TestRuleEngineBenchmark:
    """Benchmark for RuleEngine operations."""

    def test_process_100_lines_safe(self, benchmark):
        """Benchmark processing 100 lines with safe package."""
        code = generate_python_code(100)
        engine = RuleEngine([
            SecurityScannerRule(RuleConfig(enabled=True))
        ])
        benchmark(engine.process_code_file, CodeFile(path=Path("bench.py"), content=code))

    def test_process_1000_lines_safe(self, benchmark):
        """Benchmark processing 1000 lines with safe package."""
        code = generate_python_code(1000)
        engine = RuleEngine([
            SecurityScannerRule(RuleConfig(enabled=True))
        ])
        benchmark(engine.process_code_file, CodeFile(path=Path("bench.py"), content=code))

    def test_process_5000_lines_safe(self, benchmark):
        """Benchmark processing 5000 lines with safe package."""
        code = generate_python_code(5000)
        engine = RuleEngine([
            SecurityScannerRule(RuleConfig(enabled=True))
        ])
        benchmark(engine.process_code_file, CodeFile(path=Path("bench.py"), content=code))


class TestSecurityScanBenchmark:
    """Benchmark for security scanning operations."""

    def test_security_scan_100_lines(self, benchmark):
        """Benchmark security scan of 100 lines."""
        code = generate_code_with_issues(100)
        engine = RuleEngine([SecurityScannerRule()])
        benchmark(engine.process_code_file, CodeFile(path=Path("bench.py"), content=code))

    def test_security_scan_1000_lines(self, benchmark):
        """Benchmark security scan of 1000 lines."""
        code = generate_code_with_issues(1000)
        engine = RuleEngine([SecurityScannerRule()])
        benchmark(engine.process_code_file, CodeFile(path=Path("bench.py"), content=code))

    def test_security_scan_5000_lines(self, benchmark):
        """Benchmark security scan of 5000 lines."""
        code = generate_code_with_issues(5000)
        engine = RuleEngine([SecurityScannerRule()])
        benchmark(engine.process_code_file, CodeFile(path=Path("bench.py"), content=code))
