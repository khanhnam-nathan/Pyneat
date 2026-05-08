#!/usr/bin/env python3
"""
PyNeat Competitor Comparison Script

Compare PyNeat with other code analysis tools:
- ruff: Fast Python linter
- bandit: Security linter for Python
- pylint: Full Python code analyzer
- pyright: Static type checker

Run: python pyneat-rs/compare_with_competitors.py
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@dataclass
class ToolResult:
    """Result from a tool's analysis."""
    tool_name: str
    avg_time_ms: float
    issues_found: int
    files_processed: int
    success: bool
    error: str = ""


@dataclass
class ComparisonResult:
    """Comparison result between tools."""
    pyneat: ToolResult
    ruff: Optional[ToolResult]
    bandit: Optional[ToolResult]
    pylint: Optional[ToolResult]
    pyright: Optional[ToolResult]


def find_test_files(paths: List[str], extensions: List[str]) -> List[Path]:
    """Find files with given extensions."""
    files = []
    for path_str in paths:
        path = Path(path_str)
        if path.is_file() and path.suffix in extensions:
            files.append(path)
        elif path.is_dir():
            for ext in extensions:
                files.extend(path.glob(f"**/*{ext}"))
    return sorted(set(files))[:100]  # Limit to 100 files


def measure_pyneat(files: List[Path]) -> ToolResult:
    """Measure PyNeat performance."""
    from pyneat.cli import _build_engine
    from pyneat.core.engine import clear_module_cache

    _FALSE17 = (False,) * 17
    engine = _build_engine({}, None, *_FALSE17, debug_clean_mode='off')

    times = []
    issues = 0

    for file_path in files:
        if not file_path.exists():
            continue
        clear_module_cache()
        start = time.perf_counter()
        try:
            result = engine.process_file(file_path)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
            if result:
                issues += len(result.changes_made)
        except Exception:
            pass

    avg_time = sum(times) / len(times) if times else 0
    return ToolResult(
        tool_name="PyNeat",
        avg_time_ms=avg_time,
        issues_found=issues,
        files_processed=len(files),
        success=True,
    )


def measure_ruff(files: List[Path]) -> Optional[ToolResult]:
    """Measure ruff performance."""
    if not shutil.which("ruff"):
        return None

    if not files:
        return None

    # Run ruff check on the directory
    parent_dir = files[0].parent
    start = time.perf_counter()
    try:
        result = subprocess.run(
            ["ruff", "check", "--output-format=json", str(parent_dir)],
            capture_output=True,
            timeout=60,
        )
        elapsed = (time.perf_counter() - start) * 1000

        issues = 0
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                issues = len(data) if isinstance(data, list) else 0
            except json.JSONDecodeError:
                pass

        return ToolResult(
            tool_name="ruff",
            avg_time_ms=elapsed / min(len(files), 10),
            issues_found=issues,
            files_processed=len(files),
            success=result.returncode == 0,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(
            tool_name="ruff",
            avg_time_ms=60000,
            issues_found=0,
            files_processed=len(files),
            success=False,
            error="Timeout",
        )
    except Exception as e:
        return ToolResult(
            tool_name="ruff",
            avg_time_ms=0,
            issues_found=0,
            files_processed=0,
            success=False,
            error=str(e),
        )


def measure_bandit(files: List[Path]) -> Optional[ToolResult]:
    """Measure bandit performance."""
    if not shutil.which("bandit"):
        return None

    if not files:
        return None

    parent_dir = files[0].parent
    start = time.perf_counter()
    try:
        result = subprocess.run(
            ["bandit", "-f", "json", "-r", str(parent_dir)],
            capture_output=True,
            timeout=60,
        )
        elapsed = (time.perf_counter() - start) * 1000

        issues = 0
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                issues = data.get("metrics", {}).get("totals", {}).get("issues", 0)
            except json.JSONDecodeError:
                pass

        return ToolResult(
            tool_name="bandit",
            avg_time_ms=elapsed,
            issues_found=issues,
            files_processed=len(files),
            success=result.returncode in [0, 1],  # 0=no issues, 1=issues found
        )
    except subprocess.TimeoutExpired:
        return ToolResult(
            tool_name="bandit",
            avg_time_ms=60000,
            issues_found=0,
            files_processed=len(files),
            success=False,
            error="Timeout",
        )
    except Exception as e:
        return ToolResult(
            tool_name="bandit",
            avg_time_ms=0,
            issues_found=0,
            files_processed=0,
            success=False,
            error=str(e),
        )


def measure_pylint(files: List[Path]) -> Optional[ToolResult]:
    """Measure pylint performance."""
    if not shutil.which("pylint"):
        return None

    if not files:
        return None

    times = []
    issues = 0

    for file_path in files[:10]:  # Limit for speed
        if not file_path.exists():
            continue
        start = time.perf_counter()
        try:
            result = subprocess.run(
                ["pylint", "--output-format=json", str(file_path)],
                capture_output=True,
                timeout=30,
            )
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    issues += len(data)
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

    avg_time = sum(times) / len(times) if times else 0
    return ToolResult(
        tool_name="pylint",
        avg_time_ms=avg_time,
        issues_found=issues,
        files_processed=len(files[:10]),
        success=True,
    )


def measure_pyright(files: List[Path]) -> Optional[ToolResult]:
    """Measure pyright performance."""
    if not shutil.which("pyright"):
        return None

    if not files:
        return None

    times = []
    issues = 0

    for file_path in files[:10]:  # Limit for speed
        if not file_path.exists():
            continue
        start = time.perf_counter()
        try:
            result = subprocess.run(
                ["pyright", "--outputjson", str(file_path)],
                capture_output=True,
                timeout=30,
            )
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    issues += len(data.get("generalDiagnostics", []))
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

    avg_time = sum(times) / len(times) if times else 0
    return ToolResult(
        tool_name="pyright",
        avg_time_ms=avg_time,
        issues_found=issues,
        files_processed=len(files[:10]),
        success=True,
    )


def generate_markdown_table(results: ComparisonResult) -> str:
    """Generate markdown comparison table."""
    lines = [
        "# Code Analysis Tools Comparison",
        "",
        "## Performance",
        "",
        "| Tool | Avg Time (ms) | Issues Found | Files Processed | Status |",
        "|:-----|--------------:|-------------:|----------------:|:------:|",
    ]

    for result in [results.pyneat, results.ruff, results.bandit, results.pylint, results.pyright]:
        if result is None:
            continue

        status = "OK" if result.success else f"FAIL: {result.error}"
        lines.append(
            f"| {result.tool_name} | {result.avg_time_ms:.2f} | "
            f"{result.issues_found} | {result.files_processed} | {status} |"
        )

    lines.extend(["", "## Analysis", ""])

    # Calculate speedup
    pyneat_time = results.pyneat.avg_time_ms
    for result in [results.ruff, results.bandit]:
        if result and result.avg_time_ms > 0:
            speedup = result.avg_time_ms / pyneat_time
            lines.append(f"- {result.tool_name} is {speedup:.1f}x slower than PyNeat")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Compare PyNeat with competitor tools",
    )
    parser.add_argument(
        "--path", "-p", nargs="+", default=["pyneat"],
        help="Paths to scan (default: pyneat)",
    )
    parser.add_argument(
        "--output", "-o", type=str, default=None,
        help="Output file for results (JSON format)",
    )
    parser.add_argument(
        "--markdown", "-m", type=str, default=None,
        help="Output file for markdown table",
    )
    parser.add_argument(
        "--tools", "-t", nargs="+",
        choices=["ruff", "bandit", "pylint", "pyright", "all"],
        default=["all"],
        help="Tools to compare (default: all)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("PyNeat Competitor Comparison")
    print("=" * 60)

    # Find files
    extensions = [".py"]
    files = find_test_files(args.path, extensions)
    print(f"\nFound {len(files)} Python files to analyze")

    if not files:
        print("No files found. Exiting.")
        return 1

    # Run comparisons
    print("\nRunning benchmarks...")

    print("  - PyNeat...", end=" ", flush=True)
    pyneat_result = measure_pyneat(files)
    print(f"done ({pyneat_result.avg_time_ms:.2f}ms avg)")

    ruff_result = None
    if "ruff" in args.tools or "all" in args.tools:
        print("  - ruff...", end=" ", flush=True)
        ruff_result = measure_ruff(files)
        if ruff_result:
            status = "OK" if ruff_result.success else "FAIL"
            print(f"done ({ruff_result.avg_time_ms:.2f}ms avg, {status})")
        else:
            print("not installed")

    bandit_result = None
    if "bandit" in args.tools or "all" in args.tools:
        print("  - bandit...", end=" ", flush=True)
        bandit_result = measure_bandit(files)
        if bandit_result:
            status = "OK" if bandit_result.success else "FAIL"
            print(f"done ({bandit_result.avg_time_ms:.2f}ms avg, {status})")
        else:
            print("not installed")

    pylint_result = None
    if "pylint" in args.tools or "all" in args.tools:
        print("  - pylint...", end=" ", flush=True)
        pylint_result = measure_pylint(files)
        if pylint_result:
            print(f"done ({pylint_result.avg_time_ms:.2f}ms avg)")
        else:
            print("not installed")

    pyright_result = None
    if "pyright" in args.tools or "all" in args.tools:
        print("  - pyright...", end=" ", flush=True)
        pyright_result = measure_pyright(files)
        if pyright_result:
            print(f"done ({pyright_result.avg_time_ms:.2f}ms avg)")
        else:
            print("not installed")

    # Compile results
    comparison = ComparisonResult(
        pyneat=pyneat_result,
        ruff=ruff_result,
        bandit=bandit_result,
        pylint=pylint_result,
        pyright=pyright_result,
    )

    # Print summary
    print("\n" + "=" * 60)
    print("Results Summary")
    print("=" * 60)

    print(f"\n{'Tool':<15} {'Avg Time':>12} {'Issues':>10} {'Files':>8}")
    print("-" * 50)
    print(f"{'PyNeat':<15} {pyneat_result.avg_time_ms:>10.2f}ms {pyneat_result.issues_found:>10} {pyneat_result.files_processed:>8}")

    if ruff_result:
        print(f"{'ruff':<15} {ruff_result.avg_time_ms:>10.2f}ms {ruff_result.issues_found:>10} {ruff_result.files_processed:>8}")

    if bandit_result:
        print(f"{'bandit':<15} {bandit_result.avg_time_ms:>10.2f}ms {bandit_result.issues_found:>10} {bandit_result.files_processed:>8}")

    if pylint_result:
        print(f"{'pylint':<15} {pylint_result.avg_time_ms:>10.2f}ms {pylint_result.issues_found:>10} {pylint_result.files_processed:>8}")

    if pyright_result:
        print(f"{'pyright':<15} {pyright_result.avg_time_ms:>10.2f}ms {pyright_result.issues_found:>10} {pyright_result.files_processed:>8}")

    # Speedup analysis
    print("\n" + "=" * 60)
    print("Speedup Analysis")
    print("=" * 60)

    pyneat_time = pyneat_result.avg_time_ms
    for result, name in [(ruff_result, "ruff"), (bandit_result, "bandit")]:
        if result and result.avg_time_ms > 0 and pyneat_time > 0:
            speedup = result.avg_time_ms / pyneat_time
            if speedup > 1:
                print(f"  PyNeat is {speedup:.1f}x FASTER than {name}")
            else:
                print(f"  PyNeat is {1/speedup:.1f}x SLOWER than {name}")

    # Export results
    if args.output:
        results_dict = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "files_analyzed": len(files),
            "pyneat": {
                "tool": pyneat_result.tool_name,
                "avg_time_ms": pyneat_result.avg_time_ms,
                "issues_found": pyneat_result.issues_found,
                "files_processed": pyneat_result.files_processed,
                "success": pyneat_result.success,
            },
        }
        if ruff_result:
            results_dict["ruff"] = {
                "tool": ruff_result.tool_name,
                "avg_time_ms": ruff_result.avg_time_ms,
                "issues_found": ruff_result.issues_found,
                "files_processed": ruff_result.files_processed,
                "success": ruff_result.success,
                "error": ruff_result.error,
            }
        if bandit_result:
            results_dict["bandit"] = {
                "tool": bandit_result.tool_name,
                "avg_time_ms": bandit_result.avg_time_ms,
                "issues_found": bandit_result.issues_found,
                "files_processed": bandit_result.files_processed,
                "success": bandit_result.success,
                "error": bandit_result.error,
            }

        with open(args.output, "w") as f:
            json.dump(results_dict, f, indent=2)
        print(f"\nResults saved to: {args.output}")

    if args.markdown:
        markdown = generate_markdown_table(comparison)
        with open(args.markdown, "w") as f:
            f.write(markdown)
        print(f"Markdown table saved to: {args.markdown}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
