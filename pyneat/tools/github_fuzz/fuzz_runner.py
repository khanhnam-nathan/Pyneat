"""Core fuzz testing loop.

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

For commercial licensing, contact: license@pyneat.dev

For each downloaded Python file, runs pyneat with all configured rule
combinations, detecting crashes, regressions, and performance issues.
"""

from __future__ import annotations

import ast
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Iterator, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from pyneat.tools.github_fuzz import FuzzConfig, FuzzResult, RuleCombination
    from pyneat.tools.github_fuzz.debug_logger import FuzzLogger

from pyneat.core.engine import RuleEngine, clear_module_cache
from pyneat.core.types import CodeFile, RuleConfig
from pyneat.cli import _build_engine
from pyneat.tools.github_fuzz import FuzzResult, FuzzConfig, RuleCombination
from pyneat.tools.github_fuzz.debug_logger import format_traceback, truncate_snippet

# Re-export for convenience
__all__ = ["_run_fuzz"]


# ---------------------------------------------------------------------------
# Semantic bug detection helpers
# ---------------------------------------------------------------------------

# Patterns that are known to change semantics when auto-fixed.
# These are "dangerous" transformations that might break runtime behavior.
_SEMANTICALLY_SENSITIVE_PATTERNS = {
    # RedundantExpressionRule: these simplifications can change truthiness
    "Simplified redundant comparison": [
        ("x == True", "bool(x) or x"),
        ("x == False", "not x"),
    ],
    # IsNotNoneRule: is not None is equivalent but changes AST representation
    "Fixed != None to is not None": [
        # "x != None" -> "x is not None" is semantically equivalent
        # but worth flagging for review
    ],
}


def _detect_semantic_bugs(
    content: str,
    transformed_content: str,
    changes: List[str],
) -> List[str]:
    """Detect transformations that may change runtime semantics.

    Returns a list of warnings for potentially dangerous transformations.
    """
    warnings: List[str] = []

    for change in changes:
        # Flag truthiness changes from redundant expression simplification
        if "Simplified redundant comparison" in change:
            # Check if it was "x == True" or "x == False"
            # These changes affect truthiness in edge cases like x=1
            warnings.append(
                "SEMANTIC-WARNING: 'x == True' simplified to 'x'. "
                "Note: '1 == True' is True but 'x=1; x' is truthy. "
                "Behavior is equivalent for booleans but different for truthy values."
            )

        # Flag removal of 'is True' / 'is False' comparisons
        if "is True" in change or "is False" in change:
            warnings.append(
                "SEMANTIC-WARNING: 'x is True/False' simplification may change "
                "truthiness behavior in edge cases."
            )

        # Flag empty except clauses converted to raise (behavioral change)
        if "Replaced 'pass' with 'raise'" in change:
            warnings.append(
                "SEMANTIC-WARNING: empty 'except: pass' converted to 'except: raise'. "
                "This changes silent-ignore behavior to fail-fast behavior."
            )

        # Flag os.system -> subprocess.run (security fix, worth noting)
        if "os.system()" in change and "subprocess.run" in change:
            warnings.append(
                "SECURITY-FIX: os.system() replaced with subprocess.run(). "
                "This fixes a command injection vulnerability."
            )

    return warnings


# ---------------------------------------------------------------------------
# Exception categories (for categorised crash reporting)
# ---------------------------------------------------------------------------

CRITICAL_EXCEPTIONS = (
    TypeError, AttributeError, IndexError, KeyError,
    ValueError, SyntaxError, RecursionError, OSError,
    ImportError, RuntimeError, NotImplementedError,
)


# ---------------------------------------------------------------------------
# Build engine from a RuleCombination
# ---------------------------------------------------------------------------

def _build_engine_from_combination(
    combination: RuleCombination,
) -> RuleEngine:
    """Build a RuleEngine configured for the given combination.

    SAFE rules (IsNotNoneRule, RangeLenRule, SecurityScannerRule, TypingRule,
    CodeQualityRule, PerformanceRule) are ALWAYS added because they are detection-only
    rules that don't modify code unless there's a real issue. They should run on every
    test to ensure fuzz coverage of all rule types.

    CONSERVATIVE rules (unused, redundant, dead_code, fstring, dataclass) are opt-in
    and controlled by combination flags.

    DESTRUCTIVE rules (import_cleaning, naming, refactoring, comment_clean) are also
    opt-in and controlled by combination flags.

    debug_clean_mode (off/safe/aggressive) controls DebugCleaner behavior.
    """
    flags = combination.flags.copy()
    debug_mode = flags.pop("debug_clean_mode", "off")

    # Safe rules: ALWAYS enabled (detection-only, no false positives)
    enable_is_not_none = True   # fixes != None -> is not None (PEP8)
    enable_range_len = True    # detects range(len()) anti-pattern
    enable_security = True    # detects security issues
    enable_typing = True      # suggests type annotations
    enable_quality = True     # detects magic numbers, empty except
    enable_performance = True  # detects inefficient loops

    return _build_engine(
        {},  # no config file
        None,  # package (None = safe rules only)
        # Safe rules (always added)
        enable_security=enable_security,
        enable_quality=enable_quality,
        enable_performance=enable_performance,
        # Conservative rules (opt-in via flags)
        enable_unused=flags.pop("enable_unused", False),
        enable_redundant=flags.pop("enable_redundant", False),
        enable_is_not_none=enable_is_not_none,
        enable_magic_numbers=False,
        enable_dead_code=flags.pop("enable_dead_code", False),
        enable_fstring=flags.pop("enable_fstring", False),
        enable_range_len=enable_range_len,
        enable_typing=enable_typing,
        enable_match_case=False,
        enable_dataclass=flags.pop("enable_dataclass", False),
        # Destructive rules (opt-in via flags)
        enable_import_cleaning=flags.pop("enable_import_cleaning", False),
        enable_naming=flags.pop("enable_naming", False),
        enable_refactoring=flags.pop("enable_refactoring", False),
        enable_comment_clean=flags.pop("enable_comment_clean", False),
        # debug_clean handled separately
        debug_clean_mode=debug_mode,
    )


# ---------------------------------------------------------------------------
# Process a single file with a single combination
# ---------------------------------------------------------------------------

def _test_file_with_combination(
    repo: str,
    gh_file_path: str,
    content: str,
    combination: RuleCombination,
    timeout_seconds: float = 30.0,
) -> FuzzResult:
    """Test one file with one rule combination.

    Returns a FuzzResult with the outcome:
    - success: engine ran without errors
    - crash: engine raised an unhandled exception
    - regression: output is not valid Python
    - no_op: no changes were made
    - timeout: processing exceeded timeout
    """
    start = time.perf_counter()

    # Track whether input was valid Python (set early, available in catch-all too)
    input_valid = True

    try:
        # ---- Build engine for this combination ----
        engine = _build_engine_from_combination(combination)

        # ---- Create CodeFile ----
        file_path = Path(gh_file_path)
        line_count = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
        code_file = CodeFile(path=file_path, content=content)

        # ---- Check input validity (needed for regression classification in catch-all) ----
        try:
            ast.parse(content)
        except SyntaxError:
            input_valid = False

        # ---- Process with timeout via polling (Windows-compatible) ----
        import threading
        result = None
        error_info = {}

        def _process():
            nonlocal result
            try:
                # Use process_code_file (not process_file) so we process the
                # provided content directly. process_file would read from disk
                # which would be empty for fuzz content that hasn't been saved.
                result = engine.process_code_file(code_file)
            except Exception as e:
                error_info["exc"] = e
                error_info["tb"] = traceback.format_exc()

        thread = threading.Thread(target=_process, daemon=True)
        thread.start()
        thread.join(timeout=timeout_seconds)

        if thread.is_alive():
            # Timeout — mark as timeout, engine may still be running
            elapsed_ms = (time.perf_counter() - start) * 1000
            return FuzzResult(
                repo=repo,
                file_path=gh_file_path,
                combination_id=combination.id,
                status="timeout",
                elapsed_ms=elapsed_ms,
            )

        if error_info:
            # Crash in the thread
            exc = error_info["exc"]
            tb = error_info["tb"]
            elapsed_ms = (time.perf_counter() - start) * 1000

            return FuzzResult(
                repo=repo,
                file_path=gh_file_path,
                combination_id=combination.id,
                status="crash",
                elapsed_ms=elapsed_ms,
                exception_type=type(exc).__name__,
                exception_message=str(exc),
                traceback=tb,
            )

        if result is None:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return FuzzResult(
                repo=repo,
                file_path=gh_file_path,
                combination_id=combination.id,
                status="crash",
                elapsed_ms=elapsed_ms,
                exception_type="InternalError",
                exception_message="Engine returned None (unknown error)",
            )

        # ---- Pre-check: is input valid Python? ----
        # If input has SyntaxError, it's Python 2 or otherwise invalid.
        # Mark as "unsupported" rather than regression since pyneat only handles Python 3.
        input_valid = True
        try:
            ast.parse(content)
        except SyntaxError:
            input_valid = False

        # ---- Check regression: did a rule break valid Python? ----
        # Regression = input was valid but output is invalid.
        try:
            ast.parse(result.transformed_content)
        except SyntaxError as e:
            elapsed_ms = (time.perf_counter() - start) * 1000
            if input_valid:
                # Genuine regression: engine broke valid Python
                return FuzzResult(
                    repo=repo,
                    file_path=gh_file_path,
                    combination_id=combination.id,
                    status="regression",
                    elapsed_ms=elapsed_ms,
                    syntax_error=f"line {e.lineno}: {e.msg}",
                    original_snippet=_get_snippet_around_line(content, e.lineno),
                    transformed_snippet=result.transformed_content,
                )
            else:
                # Input was already invalid (Python 2 or broken) — not a regression
                return FuzzResult(
                    repo=repo,
                    file_path=gh_file_path,
                    combination_id=combination.id,
                    status="unsupported",
                    elapsed_ms=elapsed_ms,
                    syntax_error=f"line {e.lineno}: {e.msg} [Python 2/invalid input]",
                )

        elapsed_ms = (time.perf_counter() - start) * 1000

        # ---- Check no-op ----
        # no-op: output is identical to input (regardless of whether input is valid)
        if content == result.transformed_content:
            return FuzzResult(
                repo=repo,
                file_path=gh_file_path,
                combination_id=combination.id,
                status="no_op",
                elapsed_ms=elapsed_ms,
                changes=list(result.changes_made),
                line_count=line_count,
            )

        # ---- Success ----
        # Detect semantic bugs in the changes
        semantic_bugs = _detect_semantic_bugs(content, result.transformed_content, list(result.changes_made))
        return FuzzResult(
            repo=repo,
            file_path=gh_file_path,
            combination_id=combination.id,
            status="success",
            elapsed_ms=elapsed_ms,
            changes=list(result.changes_made),
            line_count=line_count,
            semantic_bugs=semantic_bugs,
        )

    # Catch-all for any other unhandled exceptions
    except Exception as e:  # noqa: BLE001
        elapsed_ms = (time.perf_counter() - start) * 1000
        tb = traceback.format_exc()

        # Check if it's a SyntaxError regression (parse failure during rule apply)
        if isinstance(e, SyntaxError):
            return FuzzResult(
                repo=repo,
                file_path=gh_file_path,
                combination_id=combination.id,
                status="regression" if input_valid else "unsupported",
                elapsed_ms=elapsed_ms,
                syntax_error=f"line {e.lineno}: {e.msg}",
                original_snippet=truncate_snippet(content),
                transformed_snippet="[could not parse transformed output]",
            )

        return FuzzResult(
            repo=repo,
            file_path=gh_file_path,
            combination_id=combination.id,
            status="crash",
            elapsed_ms=elapsed_ms,
            exception_type=type(e).__name__,
            exception_message=str(e),
            traceback=tb,
        )


def _get_snippet_around_line(content: str, line_no: int, context: int = 10) -> str:
    """Get a few lines of context around a specific line number."""
    lines = content.split("\n")
    start = max(0, line_no - context - 1)
    end = min(len(lines), line_no + context)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end))


# ---------------------------------------------------------------------------
# Progress callback helper
# ---------------------------------------------------------------------------

class ProgressTracker:
    """Track and display fuzz test progress."""

    def __init__(self, total_tests: int, verbose: bool = True):
        self._total = total_tests
        self._done = 0
        self._verbose = verbose
        self._start_time = time.perf_counter()
        self._crashes = 0
        self._regressions = 0

    def record(self, result: FuzzResult) -> None:
        self._done += 1
        if result.status == "crash":
            self._crashes += 1
        elif result.status == "regression":
            self._regressions += 1

    def print_update(self) -> None:
        if not self._verbose:
            return
        elapsed = time.perf_counter() - self._start_time
        pct = self._total * 100 / max(self._total, 1)
        bar_len = 20
        filled = int(bar_len * self._done / max(self._total, 1))
        bar = "#" * filled + "." * (bar_len - filled)
        rate = self._done / max(elapsed, 0.001)

        status = (
            f"\r[PYNEAT-FUZZ] [{bar}] {self._done}/{self._total} "
            f"({pct:.0f}%) | {rate:.1f} test/s | "
            f"crash={self._crashes} regression={self._regressions}"
        )
        print(status, end="", flush=True)

    def finish(self) -> None:
        if self._verbose:
            print()  # newline after progress bar


# ---------------------------------------------------------------------------
# Main fuzz loop
# ---------------------------------------------------------------------------

def _run_fuzz(config: FuzzConfig) -> List[FuzzResult]:
    """Run the fuzz test loop with the given configuration.

    This is the core entry point called by `run_fuzz()` and the CLI.
    """
    from pyneat.tools.github_fuzz.github_client import download_repos_py_files
    from pyneat.tools.github_fuzz.debug_logger import FuzzLogger

    # Clear module cache between runs for accurate measurements
    clear_module_cache()

    # ---- Setup logger ----
    logger = FuzzLogger(output_dir=config.output_dir)
    logger.start_run(config)

    combinations = config.get_combinations()
    total_combinations = len(combinations)

    print(f"\n[PyNeat Fuzz] Starting fuzz test")
    print(f"  Repos          : {len(config.repos)}")
    print(f"  Max files/repo : {config.max_files_per_repo}")
    print(f"  Combinations   : {total_combinations}")
    print(f"  Timeout/file   : {config.timeout_seconds}s")
    print(f"  Workers        : {config.max_workers}")
    print(f"  Output         : {config.output_dir}")
    print()

    all_results: List[FuzzResult] = []
    file_queue: List[tuple] = []  # (repo, gh_file, content)

    # ---- Phase 1: Download files ----
    print("[PyNeat Fuzz] Phase 1/2: Downloading files from GitHub...")

    if config.resume_from and Path(config.resume_from).exists():
        # Resume from cached files
        from pyneat.tools.github_fuzz.github_client import load_cache
        cached = load_cache(Path(config.resume_from))
        if cached:
            for gh_file, content in cached.files:
                file_queue.append((cached.repo, gh_file, content))
            print(f"  Resumed {len(file_queue)} files from cache")
    else:
        for repo, gh_file, content in download_repos_py_files(
            repos=config.repos,
            max_files_per_repo=config.max_files_per_repo,
            token=config.github_token,
        ):
            file_queue.append((repo, gh_file, content))

    if config.dry_download:
        print(f"[PyNeat Fuzz] Dry run — downloaded {len(file_queue)} files, skipping tests")
        return []

    total_tests = len(file_queue) * total_combinations
    print(f"  Collected {len(file_queue)} files × {total_combinations} = {total_tests} tests")
    print()

    # ---- Phase 2: Run fuzz tests ----
    print("[PyNeat Fuzz] Phase 2/2: Running fuzz tests...")
    tracker = ProgressTracker(total_tests, verbose=config.verbose)
    github_stats = {}

    if config.max_workers == 1:
        # Sequential processing
        for repo, gh_file, content in file_queue:
            for combination in combinations:
                result = _test_file_with_combination(
                    repo=repo,
                    gh_file_path=gh_file.path,
                    content=content,
                    combination=combination,
                    timeout_seconds=config.timeout_seconds,
                )
                tracker.record(result)
                logger.record(result)
                all_results.append(result)
                tracker.print_update()
    else:
        # Parallel processing
        with ThreadPoolExecutor(max_workers=config.max_workers) as executor:
            futures = {}
            for repo, gh_file, content in file_queue:
                for combination in combinations:
                    future = executor.submit(
                        _test_file_with_combination,
                        repo=repo,
                        gh_file_path=gh_file.path,
                        content=content,
                        combination=combination,
                        timeout_seconds=config.timeout_seconds,
                    )
                    futures[future] = (repo, gh_file, combination)

            for future in as_completed(futures):
                repo, gh_file, combination = futures[future]
                try:
                    result = future.result()
                except Exception as e:
                    result = FuzzResult(
                        repo=repo,
                        file_path=gh_file.path,
                        combination_id=combination.id,
                        status="crash",
                        elapsed_ms=0,
                        exception_type=type(e).__name__,
                        exception_message=str(e),
                        traceback=traceback.format_exc(),
                    )
                tracker.record(result)
                logger.record(result)
                all_results.append(result)
                tracker.print_update()

    tracker.finish()

    # ---- Finalize reports ----
    logger.record_file_count(len(file_queue))
    logger.set_github_stats(github_stats)

    json_path = logger.export_json()
    txt_path = logger.export_txt()

    print(f"\n[PyNeat Fuzz] Done.")
    print(f"  Total results  : {len(all_results)}")
    print(f"  Crashes        : {sum(1 for r in all_results if r.status == 'crash')}")
    print(f"  Regressions    : {sum(1 for r in all_results if r.status == 'regression')}")
    print(f"  Timeouts       : {sum(1 for r in all_results if r.status == 'timeout')}")
    print(f"  JSON report    : {json_path}")
    print(f"  TXT summary    : {txt_path}")

    return all_results


# ---------------------------------------------------------------------------
# Convenience: test a single file with all combinations (for debugging)
# ---------------------------------------------------------------------------

def test_single_file(
    content: str,
    file_path: str = "<test>.py",
    repo: str = "local",
    combination_preset: str = "quick",
) -> List[FuzzResult]:
    """Test a single file with a subset of rule combinations.

    Useful for debugging specific crashes without downloading from GitHub.
    """
    from pyneat.tools.github_fuzz import FuzzConfig

    config = FuzzConfig(
        repos=[repo],
        combination_preset=combination_preset,
        verbose=True,
    )

    from pyneat.tools.github_fuzz.github_client import GitHubFile

    results = []
    for combination in config.get_combinations():
        result = _test_file_with_combination(
            repo=repo,
            gh_file_path=file_path,
            content=content,
            combination=combination,
            timeout_seconds=30.0,
        )
        results.append(result)

    return results


if __name__ == "__main__":
    # Allow running the module directly for quick testing
    import argparse

    parser = argparse.ArgumentParser(description="Quick fuzz test of a single file")
    parser.add_argument("file", help="Path to Python file to fuzz")
    parser.add_argument("--preset", default="quick", choices=["safe", "conservative", "destructive", "all", "quick"])
    args = parser.parse_args()

    content = Path(args.file).read_text(encoding="utf-8")
    results = test_single_file(content, file_path=args.file, combination_preset=args.preset)

    for r in results:
        print(f"[{r.combination_id}] {r.status} — {r.elapsed_ms:.1f}ms")
        if r.status in ("crash", "regression"):
            print(f"  {r.exception_type or r.syntax_error}: {r.exception_message or ''}")
            if r.traceback:
                print(r.traceback)