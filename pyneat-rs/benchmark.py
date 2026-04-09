"""Benchmark: Python vs Rust security scanner.

This script compares the performance of the pure Python scanner
vs the Rust-accelerated scanner.
"""

from __future__ import annotations

import gc
import os
import sys
import time
import statistics
from pathlib import Path
from typing import Callable

# Add parent directory to path for imports
import sys
from pathlib import Path

# Make sure we get the installed version from site-packages
# Don't add parent dir to path to avoid conflicting with local pyneat_rs
# The site-packages path is already in sys.path

from pyneat_rs import SecurityScanner


def collect_test_files(
    root_dir: str | Path,
    min_size: int = 200,
    max_files: int = 500
) -> list[Path]:
    """Collect Python files for benchmarking.

    Args:
        root_dir: Root directory to search
        min_size: Minimum file size in bytes
        max_files: Maximum number of files to collect

    Returns:
        List of file paths
    """
    root = Path(root_dir)
    files = []

    for ext in ["*.py", "*.pyx", "*.pxd"]:
        for f in root.rglob(ext):
            if f.is_file():
                try:
                    size = f.stat().st_size
                    if size >= min_size:
                        files.append(f)
                        if len(files) >= max_files:
                            return files
                except (OSError, PermissionError):
                    pass

    return files


def benchmark_scanner(
    scanner: SecurityScanner,
    files: list[Path],
    name: str,
    iterations: int = 5
) -> dict:
    """Benchmark a scanner on a set of files.

    Args:
        scanner: Scanner instance
        files: List of files to scan
        name: Name for the benchmark
        iterations: Number of iterations

    Returns:
        Dictionary with benchmark results
    """
    # Read all files first
    contents = []
    for f in files:
        try:
            with open(f, encoding="utf-8", errors="ignore") as fp:
                contents.append(fp.read())
        except (OSError, PermissionError):
            pass

    if not contents:
        return {"error": "No files could be read"}

    # Warmup
    for content in contents[:min(10, len(contents))]:
        scanner.scan(content)

    # Benchmark
    times = []
    total_findings = 0

    for _ in range(iterations):
        gc.collect()  # Force GC before measurement
        start = time.perf_counter_ns()

        for content in contents:
            findings = scanner.scan(content)
            total_findings += len(findings)

        elapsed = time.perf_counter_ns() - start
        times.append(elapsed / 1_000_000_000)  # Convert to seconds

    return {
        "name": name,
        "files": len(contents),
        "total_findings": total_findings,
        "min_time": min(times),
        "max_time": max(times),
        "avg_time": statistics.mean(times),
        "median_time": statistics.median(times),
        "std_dev": statistics.stdev(times) if len(times) > 1 else 0,
        "files_per_sec": len(contents) / statistics.median(times),
        "mb_per_sec": sum(len(c) for c in contents) / 1024 / 1024 / statistics.median(times),
    }


def print_results(results: list[dict]):
    """Print benchmark results in a formatted table."""
    print("\n" + "=" * 80)
    print("BENCHMARK RESULTS")
    print("=" * 80)

    for r in results:
        if "error" in r:
            print(f"\n{r['name']}: ERROR - {r['error']}")
            continue

        print("\n{0}".format("-" * 40))
        print(f"  {r['name']}")
        print(f"{'=' * 40}")
        print(f"  Files scanned:     {r['files']:,}")
        print(f"  Total findings:    {r['total_findings']:,}")
        print(f"  Median time:       {r['median_time']*1000:.2f} ms")
        print(f"  Min/Max time:      {r['min_time']*1000:.2f} / {r['max_time']*1000:.2f} ms")
        print(f"  Std deviation:     {r['std_dev']*1000:.2f} ms")
        print(f"  Throughput:        {r['files_per_sec']:.1f} files/sec")
        print(f"  Data throughput:   {r['mb_per_sec']:.2f} MB/sec")

    # Calculate speedup if both Python and Rust were tested
    python_result = next((r for r in results if "Python" in r.get("name", "")), None)
    rust_result = next((r for r in results if "Rust" in r.get("name", "") and "error" not in r), None)

    if python_result and rust_result:
        speedup = python_result["median_time"] / rust_result["median_time"]
        print("\n{0}".format("-" * 40))
        print(f"  SPEEDUP: Rust is {speedup:.1f}x faster than Python")
        print(f"{'=' * 40}")

    print("\n" + "=" * 80)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Benchmark Python vs Rust security scanner")
    parser.add_argument(
        "--dir", "-d",
        default=".",
        help="Directory to search for Python files (default: .)"
    )
    parser.add_argument(
        "--files", "-n",
        type=int,
        default=200,
        help="Number of files to test (default: 200)"
    )
    parser.add_argument(
        "--iterations", "-i",
        type=int,
        default=5,
        help="Number of iterations (default: 5)"
    )
    parser.add_argument(
        "--python-only",
        action="store_true",
        help="Only test Python scanner (skip Rust)"
    )
    parser.add_argument(
        "--rust-only",
        action="store_true",
        help="Only test Rust scanner (skip Python)"
    )

    args = parser.parse_args()

    print(f"Collecting files from: {args.dir}")
    files = collect_test_files(args.dir, min_size=200, max_files=args.files)

    if not files:
        print("ERROR: No Python files found!")
        sys.exit(1)

    print(f"Found {len(files)} files")

    # Show file size distribution
    sizes = [f.stat().st_size for f in files if f.exists()]
    if sizes:
        print(f"File size distribution:")
        print(f"  Min:    {min(sizes):,} bytes")
        print(f"  Max:    {max(sizes):,} bytes")
        print(f"  Avg:    {statistics.mean(sizes):,.0f} bytes")
        print(f"  Total:  {sum(sizes):,} bytes ({sum(sizes)/1024/1024:.1f} MB)")

    results = []

    # Test Rust scanner
    if not args.python_only:
        print("\n[1/2] Testing Rust scanner...")
        rust_scanner = SecurityScanner()
        if rust_scanner.rust_available:
            results.append(benchmark_scanner(
                rust_scanner, files, "Rust Scanner", args.iterations
            ))
        else:
            print("  (Rust extension not available)")

    # Test Python scanner
    if not args.rust_only:
        print(f"\n[2/2] Testing Python scanner...")
        python_scanner = SecurityScanner()
        results.append(benchmark_scanner(
            python_scanner, files, "Python Scanner (Pure)", args.iterations
        ))

    print_results(results)

    # Save results to JSON
    import json
    results_file = Path("benchmark_results.json")
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {results_file}")


if __name__ == "__main__":
    main()
