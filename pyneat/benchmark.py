"""Benchmark script to measure PyNeat performance.

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

For commercial licensing, contact: khanhnam.copywriting@gmail.com

Usage:
    python -m pyneat.benchmark
    python -m pyneat.benchmark --files pyneat/rules/*.py
    python -m pyneat.benchmark --profile
    python -m pyneat.benchmark --iterations 50

This script benchmarks PyNeat across the codebase itself and provides:
- Per-file timing (avg, min, max over N iterations)
- Per-rule timing breakdown (if --profile is set)
- Bottleneck analysis: parsing vs transformation time
- Recommendation on whether Rust is needed based on results
"""

from __future__ import annotations

import argparse
import cProfile
import io
import pstats
import sys
import time
import tracemalloc
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyneat.cli import _build_engine
from pyneat.core.engine import RuleEngine, clear_module_cache


def find_python_files(paths: List[str], recursive: bool = True) -> List[Path]:
    """Find all Python files from given paths."""
    files = []
    for path_str in paths:
        path = Path(path_str)
        if path.is_file() and path.suffix == ".py":
            files.append(path)
        elif path.is_dir():
            pattern = "**/*.py" if recursive else "*.py"
            files.extend(path.glob(pattern))
    return sorted(set(files))


def benchmark_file(file_path: Path, iterations: int, warmup: int = 1) -> Dict[str, Any]:
    """Benchmark a single file with N iterations (after warmup)."""
    # _build_engine(config, package, 17 bool flags, debug_clean_mode keyword)
    _FALSE17 = (False,) * 17
    engine = _build_engine({}, None, *_FALSE17, debug_clean_mode='off')

    for _ in range(warmup):
        clear_module_cache()
        engine.process_file(file_path)

    cold_times = []
    for _ in range(iterations):
        clear_module_cache()
        start = time.perf_counter()
        result = engine.process_file(file_path)
        elapsed = time.perf_counter() - start
        cold_times.append(elapsed * 1000)

    warm_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        result = engine.process_file(file_path)
        elapsed = time.perf_counter() - start
        warm_times.append(elapsed * 1000)

    return {
        'file': str(file_path),
        'size_kb': file_path.stat().st_size / 1024,
        'cold_avg_ms': round(sum(cold_times) / len(cold_times), 3),
        'cold_min_ms': round(min(cold_times), 3),
        'cold_max_ms': round(max(cold_times), 3),
        'warm_avg_ms': round(sum(warm_times) / len(warm_times), 3),
        'warm_min_ms': round(min(warm_times), 3),
        'warm_max_ms': round(max(warm_times), 3),
        'changes': len(result.changes_made) if result else 0,
        'success': result.success if result else False,
    }


def benchmark_all_rules(file_path: Path, iterations: int = 5) -> Dict[str, float]:
    """Benchmark each individual rule on a file."""
    from pyneat.rules.safe import (
        IsNotNoneRule, RangeLenRule, SecurityScannerRule,
        TypingRule, CodeQualityRule, PerformanceRule,
    )
    from pyneat.rules.conservative import (
        UnusedImportRule, InitFileProtectionRule, FStringRule, DataclassSuggestionRule, MagicNumberRule,
    )
    from pyneat.rules.destructive import (
        ImportCleaningRule, NamingConventionRule, RefactoringRule,
        DebugCleaner, CommentCleaner, RedundantExpressionRule,
        DeadCodeRule, MatchCaseRule,
    )
    from pyneat.core.types import CodeFile

    rules = [
        IsNotNoneRule(), RangeLenRule(), SecurityScannerRule(),
        TypingRule(), CodeQualityRule(), PerformanceRule(),
        UnusedImportRule(), InitFileProtectionRule(), FStringRule(),
        DataclassSuggestionRule(), MagicNumberRule(),
        ImportCleaningRule(), NamingConventionRule(),
        RefactoringRule(), DebugCleaner(), CommentCleaner(),
        RedundantExpressionRule(), DeadCodeRule(), MatchCaseRule(),
    ]

    timings: Dict[str, float] = {}
    code_file = CodeFile(path=file_path, content=file_path.read_text(encoding='utf-8'))

    for rule in rules:
        rule_times = []
        for _ in range(iterations):
            clear_module_cache()
            start = time.perf_counter()
            try:
                rule.apply(code_file)
            except Exception:
                pass
            elapsed = time.perf_counter() - start
            rule_times.append(elapsed * 1000)
        avg = sum(rule_times) / len(rule_times)
        timings[rule.name] = round(avg, 3)

    return timings


def profile_file(file_path: Path, iterations: int = 20) -> str:
    """Profile a file and return formatted stats."""
    profiler = cProfile.Profile()
    _TRUE17 = (True,) * 17
    engine = _build_engine({}, None, *_TRUE17, debug_clean_mode='safe')

    for _ in range(iterations):
        clear_module_cache()
        engine.process_file(file_path)

    profiler.enable()
    for _ in range(iterations * 2):
        engine.process_file(file_path)
    profiler.disable()

    stream = io.StringIO()
    stats = pstats.Stats(profiler, stream=stream)
    stats.sort_stats('cumulative')
    stats.print_stats(30)
    return stream.getvalue()


def print_benchmark_table(results: List[Dict[str, Any]]) -> None:
    """Print a formatted benchmark table."""
    print()
    print(f"{'File':<60} {'Size':>6} {'Cold':>8} {'Warm':>8} {'Changes':>7} {'Status':>7}")
    print("-" * 102)
    for r in results:
        status = "OK" if r['success'] else "FAIL"
        print(
            f"{r['file']:<60} "
            f"{r['size_kb']:>5.1f}k "
            f"{r['cold_avg_ms']:>7.2f}ms "
            f"{r['warm_avg_ms']:>7.2f}ms "
            f"{r['changes']:>6} "
            f"{status:>6}"
        )
    print("-" * 102)

    total_size = sum(r['size_kb'] for r in results)
    avg_cold = sum(r['cold_avg_ms'] for r in results) / len(results)
    avg_warm = sum(r['warm_avg_ms'] for r in results) / len(results)
    total_changes = sum(r['changes'] for r in results)
    print(f"{'TOTAL/AVG':<60} {total_size:>5.1f}k {avg_cold:>7.2f}ms {avg_warm:>7.2f}ms {total_changes:>6}")
    print()


def print_rule_breakdown(timings: Dict[str, float]) -> None:
    """Print per-rule timing breakdown."""
    print()
    print("Per-Rule Timing (avg ms over N iterations):")
    print("-" * 50)
    sorted_rules = sorted(timings.items(), key=lambda x: x[1], reverse=True)
    total = sum(timings.values())
    for name, ms in sorted_rules:
        pct = (ms / total * 100) if total > 0 else 0
        bar = '#' * int(pct / 2)
        print(f"  {name:<40} {ms:>7.3f}ms {pct:>5.1f}% {bar}")
    print(f"  {'TOTAL':<40} {total:>7.3f}ms 100.0%")
    print()


def analyze_bottlenecks(results: List[Dict[str, Any]], timings: Dict[str, float]) -> None:
    """Analyze bottlenecks and print recommendation."""
    total_avg = sum(r['cold_avg_ms'] for r in results) / len(results)

    print()
    print("=" * 60)
    print("BOTTLENECK ANALYSIS")
    print("=" * 60)
    print(f"  Average cold-start time per file: {total_avg:.2f}ms")
    print(f"  Number of files benchmarked:      {len(results)}")
    print(f"  Total code size:                  {sum(r['size_kb'] for r in results):.1f}KB")

    if not timings:
        print()
        print("  (Run with --rules to see per-rule breakdown)")
        return

    sorted_rules = sorted(timings.items(), key=lambda x: x[1], reverse=True)
    top_rules = sorted_rules[:5]
    top_time = sum(ms for _, ms in top_rules)

    print()
    print(f"  Top 5 slowest rules:")
    for name, ms in top_rules:
        print(f"    - {name}: {ms:.3f}ms ({ms/total_avg*100:.1f}% of file avg)")

    print()
    if total_avg > 500:
        print("  RECOMMENDATION: Consider Rust for hot-path rules (>500ms avg)")
        print("  The slowest rules should be rewritten in Rust via PyO3.")
    elif total_avg > 200:
        print("  RECOMMENDATION: Python is acceptable but monitor growth.")
        print("  Consider caching improvements or selective rule enabling.")
    else:
        print("  RECOMMENDATION: Python performance is acceptable.")
        print("  No Rust migration needed at current scale.")

    print()
    print("  Rust migration priority (if needed):")
    print("    1. AST/CST parsing layer (shared by all rules)")
    print("    2. Hot-path rules (SecurityScanner, Refactoring, DebugCleaner)")
    print("    3. Cross-file analysis (NamingConventionRule)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark PyNeat performance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '--files', '-f', nargs='+', default=[],
        help='Files or directories to benchmark (default: pyneat/rules/)',
    )
    parser.add_argument(
        '--iterations', '-n', type=int, default=10,
        help='Number of iterations per file (default: 10)',
    )
    parser.add_argument(
        '--profile', '-p', action='store_true',
        help='Run cProfile and show top 30 functions by cumulative time',
    )
    parser.add_argument(
        '--rules', '-r', action='store_true',
        help='Run per-rule breakdown on the largest file',
    )
    parser.add_argument(
        '--warmup', '-w', type=int, default=1,
        help='Warmup iterations (default: 1)',
    )
    parser.add_argument(
        '--output', '-o', type=str, default=None,
        help='Write results to a JSON file',
    )
    parser.add_argument(
        '--lang', '-l', type=str, default='python',
        choices=['python', 'javascript', 'typescript', 'go', 'java', 'rust', 'csharp', 'php', 'ruby'],
        help='Language for multi-language benchmarks (default: python)',
    )
    parser.add_argument(
        '--compare', '-c', action='store_true',
        help='Compare with competitor tools (ruff, bandit)',
    )
    parser.add_argument(
        '--memory', '-m', action='store_true',
        help='Enable memory profiling using tracemalloc',
    )

    args = parser.parse_args()

    if not args.files:
        pyneat_rules = list(Path(__file__).parent.parent.glob("pyneat/rules/*.py"))
        if pyneat_rules:
            args.files = [str(Path(__file__).parent.parent / "pyneat/rules")]
        else:
            print("No files specified and pyneat/rules/ not found.")
            return 1

    files = find_python_files(args.files)
    if not files:
        print(f"No Python files found in: {args.files}")
        return 1

    print(f"Benchmarking {len(files)} file(s) with {args.iterations} iterations each...")
    print(f"(Warmup: {args.warmup} iteration(s))")

    import json as _json
    results: List[Dict[str, Any]] = []

    for i, file_path in enumerate(files):
        if not file_path.exists():
            continue
        print(f"[{i+1}/{len(files)}] {file_path.name}...", end=" ", flush=True)
        try:
            result = benchmark_file(file_path, args.iterations, args.warmup)
            results.append(result)
            print(f"COLD={result['cold_avg_ms']:.2f}ms WARM={result['warm_avg_ms']:.2f}ms")
        except Exception as e:
            print(f"ERROR: {e}")

    if not results:
        print("No files were successfully benchmarked.")
        return 1

    print_benchmark_table(results)

    if args.profile and results:
        largest = max(results, key=lambda r: r['size_kb'])
        print(f"\nProfiling largest file: {largest['file']}")
        print("-" * 60)
        profile_output = profile_file(Path(largest['file']), args.iterations)
        print(profile_output[:3000])

    if args.rules and results:
        largest = max(results, key=lambda r: r['size_kb'])
        print(f"\nPer-rule breakdown for: {largest['file']}")
        timings = benchmark_all_rules(Path(largest['file']), iterations=5)
        print_rule_breakdown(timings)

    analyze_bottlenecks(results, {})

    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults written to: {args.output}")

    # Memory profiling
    if args.memory:
        print("\n" + "=" * 60)
        print("MEMORY PROFILING")
        print("=" * 60)
        memory_results = profile_memory(args.files or ['pyneat/rules'])
        print_memory_stats(memory_results)

    # Competitor comparison
    if args.compare:
        print("\n" + "=" * 60)
        print("COMPETITOR COMPARISON")
        print("=" * 60)
        comparison_results = compare_with_competitors(files)
        print_comparison_table(comparison_results)

    return 0


def profile_memory(paths: List[str]) -> Dict[str, Any]:
    """Profile memory usage of PyNeat scanning."""
    import tracemalloc
    from pyneat.core.engine import RuleEngine, clear_module_cache

    tracemalloc.start()

    files = find_python_files(paths)
    snapshot_before = tracemalloc.take_snapshot()

    clear_module_cache()
    _FALSE17 = (False,) * 17
    engine = _build_engine({}, None, *_FALSE17, debug_clean_mode='off')

    for file_path in files[:10]:  # Limit to first 10 files
        if file_path.exists():
            engine.process_file(file_path)

    snapshot_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    top_stats = snapshot_after.compare_to(snapshot_before, 'lineno')
    total_diff = sum(stat.size_diff for stat in top_stats)

    return {
        'total_memory_mb': total_diff / 1024 / 1024,
        'top_allocations': [
            {'file': str(stat.traceback), 'size_kb': stat.size_diff / 1024}
            for stat in top_stats[:10]
        ]
    }


def print_memory_stats(memory_results: Dict[str, Any]) -> None:
    """Print memory profiling results."""
    print(f"  Total memory used: {memory_results['total_memory_mb']:.2f} MB")
    print()
    print("  Top memory allocations:")
    for alloc in memory_results['top_allocations'][:5]:
        print(f"    {alloc['size_kb']:.2f} KB: {alloc['file']}")


def compare_with_competitors(files: List[Path]) -> List[Dict[str, Any]]:
    """Compare PyNeat with competitor tools."""
    import subprocess
    import shutil
    results = []

    # PyNeat baseline
    pyneat_time = measure_pyneat_time(files)
    results.append({
        'tool': 'PyNeat (Python)',
        'avg_time_ms': pyneat_time,
        'files_per_sec': len(files) / (pyneat_time / 1000) if pyneat_time > 0 else 0,
    })

    # ruff comparison
    if shutil.which('ruff'):
        ruff_time = measure_ruff_time(files)
        results.append({
            'tool': 'ruff',
            'avg_time_ms': ruff_time,
            'files_per_sec': len(files) / (ruff_time / 1000) if ruff_time > 0 else 0,
        })
    else:
        results.append({
            'tool': 'ruff',
            'avg_time_ms': None,
            'files_per_sec': None,
            'note': 'Not installed',
        })

    # bandit comparison
    if shutil.which('bandit'):
        bandit_time = measure_bandit_time(files)
        results.append({
            'tool': 'bandit',
            'avg_time_ms': bandit_time,
            'files_per_sec': len(files) / (bandit_time / 1000) if bandit_time > 0 else 0,
        })
    else:
        results.append({
            'tool': 'bandit',
            'avg_time_ms': None,
            'files_per_sec': None,
            'note': 'Not installed',
        })

    return results


def measure_pyneat_time(files: List[Path]) -> float:
    """Measure PyNeat scanning time."""
    import time
    clear_module_cache()
    _FALSE17 = (False,) * 17
    engine = _build_engine({}, None, *_FALSE17, debug_clean_mode='off')

    times = []
    for file_path in files[:20]:  # Limit for speed
        if file_path.exists():
            start = time.perf_counter()
            engine.process_file(file_path)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)

    return sum(times) / len(times) if times else 0


def measure_ruff_time(files: List[Path]) -> float:
    """Measure ruff scanning time."""
    import subprocess
    import time

    if not files:
        return 0

    start = time.perf_counter()
    try:
        subprocess.run(
            ['ruff', 'check', '--output-format=json', str(files[0].parent)],
            capture_output=True,
            timeout=30,
        )
    except Exception:
        pass
    elapsed = (time.perf_counter() - start) * 1000

    return elapsed / min(len(files), 20)


def measure_bandit_time(files: List[Path]) -> float:
    """Measure bandit scanning time."""
    import subprocess
    import time

    if not files:
        return 0

    start = time.perf_counter()
    try:
        subprocess.run(
            ['bandit', '-f', 'json', '-r', str(files[0].parent)],
            capture_output=True,
            timeout=60,
        )
    except Exception:
        pass
    elapsed = (time.perf_counter() - start) * 1000

    return elapsed / min(len(files), 20)


def print_comparison_table(results: List[Dict[str, Any]]) -> None:
    """Print competitor comparison table."""
    print(f"  {'Tool':<20} {'Avg Time':>12} {'Files/sec':>12}")
    print("  " + "-" * 46)
    for r in results:
        if r['avg_time_ms'] is not None:
            print(f"  {r['tool']:<20} {r['avg_time_ms']:>10.2f}ms {r['files_per_sec']:>10.1f}")
        else:
            print(f"  {r['tool']:<20} {'N/A':>12} {r.get('note', 'N/A'):>12}")


if __name__ == "__main__":
    sys.exit(main())
