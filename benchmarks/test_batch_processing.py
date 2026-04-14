"""Benchmark for batch file processing operations."""

import pytest
from pathlib import Path
import tempfile
import shutil

from pyneat.core.engine import RuleEngine
from pyneat.core.types import CodeFile, RuleConfig
from pyneat.rules.security import SecurityScannerRule

from benchmarks.conftest import generate_python_code


def create_test_files(tmp_path: Path, num_files: int, lines_per_file: int) -> list:
    """Create test files for benchmarking."""
    files = []
    for i in range(num_files):
        file_path = tmp_path / f"test_{i}.py"
        code = generate_python_code(lines_per_file)
        file_path.write_text(code, encoding="utf-8")
        files.append(file_path)
    return files


class TestBatchProcessingBenchmark:
    """Benchmark for batch processing operations."""

    def test_batch_10_files(self, benchmark, tmp_path):
        """Benchmark processing 10 files."""
        files = create_test_files(tmp_path, 10, 100)
        engine = RuleEngine([SecurityScannerRule()])

        def run_batch():
            results = []
            for f in files:
                r = engine.process_file(f)
                results.append(r)
            return results

        benchmark(run_batch)

    def test_batch_50_files(self, benchmark, tmp_path):
        """Benchmark processing 50 files."""
        files = create_test_files(tmp_path, 50, 100)
        engine = RuleEngine([SecurityScannerRule()])

        def run_batch():
            results = []
            for f in files:
                r = engine.process_file(f)
                results.append(r)
            return results

        benchmark(run_batch)

    def test_batch_100_files(self, benchmark, tmp_path):
        """Benchmark processing 100 files."""
        files = create_test_files(tmp_path, 100, 100)
        engine = RuleEngine([SecurityScannerRule()])

        def run_batch():
            results = []
            for f in files:
                r = engine.process_file(f)
                results.append(r)
            return results

        benchmark(run_batch)


class TestDirectoryProcessingBenchmark:
    """Benchmark for directory processing."""

    def test_process_directory_10_files(self, benchmark, tmp_path):
        """Benchmark directory processing of 10 files."""
        create_test_files(tmp_path, 10, 100)
        engine = RuleEngine([SecurityScannerRule()])
        benchmark(engine.process_directory, tmp_path, pattern="*.py", recursive=True)

    def test_process_directory_50_files(self, benchmark, tmp_path):
        """Benchmark directory processing of 50 files."""
        create_test_files(tmp_path, 50, 100)
        engine = RuleEngine([SecurityScannerRule()])
        benchmark(engine.process_directory, tmp_path, pattern="*.py", recursive=True)

    def test_process_directory_100_files(self, benchmark, tmp_path):
        """Benchmark directory processing of 100 files."""
        create_test_files(tmp_path, 100, 100)
        engine = RuleEngine([SecurityScannerRule()])
        benchmark(engine.process_directory, tmp_path, pattern="*.py", recursive=True)


class TestCacheBenchmark:
    """Benchmark for cache performance."""

    def test_cache_hit(self, benchmark, tmp_path):
        """Benchmark cache hit performance."""
        code = generate_python_code(500)
        file_path = tmp_path / "cached.py"
        file_path.write_text(code, encoding="utf-8")
        engine = RuleEngine([SecurityScannerRule()])

        # First pass - cache miss
        engine.process_file(file_path)

        # Second pass - cache hit
        def run_cached():
            engine.clear_cache()
            engine.process_file(file_path)

        benchmark(run_cached)

    def test_cache_miss(self, benchmark, tmp_path):
        """Benchmark cache miss performance."""
        code = generate_python_code(500)
        engine = RuleEngine([SecurityScannerRule()])

        def run_no_cache():
            engine.clear_cache()
            engine.process_code_file(CodeFile(path=Path("bench.py"), content=code))

        benchmark(run_no_cache)
