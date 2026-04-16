"""Debug logging for fuzz test results.

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

Produces structured JSON reports and human-readable TXT summaries
that make it easy to reproduce and fix bugs found during fuzz testing.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from pyneat.tools.github_fuzz import FuzzConfig, FuzzResult


# ---------------------------------------------------------------------------
# ANSI colour constants (for terminal output)
# ---------------------------------------------------------------------------

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ---------------------------------------------------------------------------
# FuzzLogger — main logging class
# ---------------------------------------------------------------------------

class FuzzLogger:
    """Collects and exports fuzz test results.

    Produces:
    - A JSON report with full details (crashes, regressions, stats)
    - A TXT summary for quick triage

    Example:
        logger = FuzzLogger("./results")
        logger.start_run(config)
        for result in results:
            logger.record(result)
        logger.finalize()
    """

    def __init__(self, output_dir: str = "pyneat_fuzz_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._crashes: List[dict] = []
        self._regressions: List[dict] = []
        self._unsupported: List[dict] = []
        self._no_ops: List[dict] = []
        self._successes: List[dict] = []
        self._slow_files: List[dict] = []
        self._by_exception_type: Dict[str, int] = {}

        self._start_time: Optional[datetime] = None
        self._config: Optional["FuzzConfig"] = None
        self._github_stats: Dict[str, Any] = {}
        self._total_files_tested = 0
        self._total_tests = 0

        # Timestamp for this run (reused across all files)
        ts = datetime.now(timezone.utc)
        self._ts_str = ts.strftime("%Y%m%d_%H%M%S")
        self._ts_iso = ts.isoformat()

    # ------------------------------------------------------------------
    # Recording results
    # ------------------------------------------------------------------

    def start_run(self, config: "FuzzConfig") -> None:
        """Mark the start of a fuzz run."""
        self._config = config
        self._start_time = datetime.now(timezone.utc)
        self._crashes.clear()
        self._regressions.clear()
        self._unsupported.clear()
        self._no_ops.clear()
        self._successes.clear()
        self._slow_files.clear()
        self._by_exception_type.clear()
        self._total_files_tested = 0
        self._total_tests = 0

    def record(self, result: "FuzzResult") -> None:
        """Record a single fuzz test result."""
        self._total_tests += 1
        if result.line_count == 0:
            # count lines from the file path string as a proxy
            pass

        d = result.to_dict()

        if result.status == "crash":
            self._crashes.append(d)
            exc_type = result.exception_type or "UnknownError"
            self._by_exception_type[exc_type] = self._by_exception_type.get(exc_type, 0) + 1
        elif result.status == "regression":
            self._regressions.append(d)
        elif result.status == "unsupported":
            self._unsupported.append(d)
        elif result.status == "no_op":
            self._no_ops.append(d)
        elif result.status == "timeout":
            self._slow_files.append(d)
        elif result.status == "success":
            if result.changes:
                self._successes.append(d)
            else:
                self._no_ops.append(d)

        # Track slow files (> 5 seconds)
        if result.elapsed_ms > 5000:
            self._slow_files.append({
                "repo": result.repo,
                "file": result.file_path,
                "elapsed_ms": round(result.elapsed_ms, 2),
                "combination": result.combination_id,
            })

    def record_file_count(self, count: int) -> None:
        self._total_files_tested = count

    def set_github_stats(self, stats: Dict[str, Any]) -> None:
        self._github_stats = stats

    # ------------------------------------------------------------------
    # JSON export
    # ------------------------------------------------------------------

    def export_json(self) -> Path:
        """Export the full JSON report and return the path."""
        report: Dict[str, Any] = {
            "report_version": "1.0",
            "generated_at": self._ts_iso,
            "total_files_tested": self._total_files_tested,
            "total_combinations": len(self._config.get_combinations()) if self._config else 0,
            "total_tests": self._total_tests,
            "elapsed_seconds": self._elapsed_seconds(),
            "summary": {
                "crashes": len(self._crashes),
                "regressions": len(self._regressions),
                "unsupported": len(self._unsupported),
                "no_ops": len(self._no_ops),
                "successes": len(self._successes),
                "slow_files": len(self._slow_files),
                "by_exception_type": dict(self._by_exception_type),
            },
            "crashes": self._crashes,
            "regressions": self._regressions,
            "unsupported": self._unsupported,
            "no_ops": self._no_ops,
            "successes": self._successes,
            "slow_files": self._slow_files,
            "github_stats": self._github_stats,
        }

        # Enhanced summary: richer stats for the report
        if self._successes:
            # Top rule by change count
            rule_change_counts: Dict[str, int] = {}
            for s in self._successes:
                comb = s.get("combination", "unknown")
                changes = s.get("changes", [])
                rule_change_counts[comb] = rule_change_counts.get(comb, 0) + len(changes)

            top_rule = max(rule_change_counts.items(), key=lambda x: x[1]) if rule_change_counts else ("N/A", 0)
            files_with_changes = len(set(s["file"] for s in self._successes))

            report["summary"]["top_rule_by_changes"] = f"{top_rule[0]}: {top_rule[1]} changes"
            report["summary"]["files_with_changes"] = files_with_changes

            # Semantic bug summary
            semantic_warnings = [s for s in self._successes if s.get("semantic_bugs")]
            if semantic_warnings:
                report["summary"]["semantic_warnings_count"] = len(semantic_warnings)

            # Rule conflict summary
            conflicts = [s for s in self._successes if s.get("rule_conflicts")]
            if conflicts:
                report["summary"]["rule_conflicts_count"] = len(conflicts)

        if self._config:
            report["config"] = {
                "repos": self._config.repos,
                "max_files_per_repo": self._config.max_files_per_repo,
                "combination_preset": self._config.combination_preset,
                "timeout_seconds": self._config.timeout_seconds,
                "max_workers": self._config.max_workers,
            }

        filename = f"PYNEAT_FUZZ_REPORT_{self._ts_str}.json"
        out_path = self.output_dir / filename
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return out_path

    # ------------------------------------------------------------------
    # TXT summary export
    # ------------------------------------------------------------------

    def export_txt(self) -> Path:
        """Export the human-readable TXT summary and return the path."""
        lines: List[str] = []

        def rule(title: str) -> None:
            lines.append("")
            lines.append(f"{'=' * 60}")
            lines.append(f"{title}")
            lines.append(f"{'=' * 60}")

        def divider(char: str = "-") -> None:
            lines.append(char * 60)

        ts_display = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        rule(f"PYNEAT FUZZ TEST REPORT — {ts_display}")
        divider()
        lines.append(
            f"Files tested  : {self._total_files_tested}  |  "
            f"Combinations: {len(self._config.get_combinations()) if self._config else 0}  |  "
            f"Total tests : {self._total_tests}"
        )
        if self._start_time:
            elapsed = (datetime.now(timezone.utc) - self._start_time).total_seconds()
            lines.append(f"Elapsed time : {elapsed:.1f}s")
        divider()

        total_crashes = len(self._crashes)
        total_regressions = len(self._regressions)
        total_slow = len(self._slow_files)

        lines.append(f"CRASHES       : {total_crashes}  [!]" if total_crashes else f"CRASHES       : {total_crashes}")
        lines.append(f"REGRESSIONS   : {total_regressions}  [!]" if total_regressions else f"REGRESSIONS   : {total_regressions}")
        lines.append(f"SLOW FILES    : {total_slow}")
        lines.append(f"UNSUPPORTED   : {len(self._unsupported)} [Python 2 / invalid input]")
        lines.append(f"NO_OP         : {len(self._no_ops)}")
        lines.append(f"SUCCESS       : {len(self._successes)}")

        if self._by_exception_type:
            divider()
            lines.append("Exception breakdown:")
            for exc_type, count in sorted(
                self._by_exception_type.items(), key=lambda x: -x[1]
            ):
                lines.append(f"  {exc_type}: {count}")

        # ---- Crashes ----
        if self._crashes:
            rule("CRASHES")
            for i, c in enumerate(self._crashes, 1):
                lines.append("")
                lines.append(f"{BOLD}=== CRASH #{i}{RESET}")
                lines.append(f"Repo    : {c['repo']}")
                lines.append(f"File    : {c['file']} (line count: {c.get('line_count', '?')})")
                lines.append(f"Rule    : {c.get('combination', 'unknown')}")
                lines.append(f"Error   : {c.get('exception_type', '?')}: {c.get('exception_message', '')}")
                lines.append(f"Context : combination_id={c.get('combination', '?')}")

                if c.get("original_snippet"):
                    lines.append("─── Code snippet ────────────────────────────────────")
                    snippet = c.get("original_snippet", "")
                    for ln in snippet.split("\n")[:20]:
                        lines.append(f"  {ln}")
                    lines.append("─── Transformed (may be partial) ────────────────────")
                    t_snippet = c.get("transformed_snippet", "")
                    for ln in t_snippet.split("\n")[:20]:
                        lines.append(f"  {ln}")

                if c.get("traceback"):
                    lines.append("─── Stack trace ─────────────────────────────────────")
                    lines.append(c["traceback"])

                lines.append(f"{BOLD}─── Recommendation ─────────────────────────────────────{RESET}")
                rec = _suggest_fix(c.get("exception_type", ""), c.get("exception_message", ""))
                lines.append(rec)

        # ---- Regressions ----
        if self._regressions:
            rule("REGRESSIONS (output is invalid Python)")
            for i, r in enumerate(self._regressions, 1):
                lines.append("")
                lines.append(f"{BOLD}=== REGRESSION #{i}{RESET}")
                lines.append(f"Repo    : {r['repo']}")
                lines.append(f"File    : {r['file']}")
                lines.append(f"Rule    : {r.get('combination', 'unknown')}")
                lines.append(f"Syntax  : {r.get('syntax_error', '?')}")

                if r.get("original_snippet"):
                    lines.append("─── Original code ────────────────────────────────────")
                    for ln in r["original_snippet"].split("\n")[:15]:
                        lines.append(f"  {ln}")

                if r.get("transformed_snippet"):
                    lines.append("─── Transformed (broken) ────────────────────────────")
                    for ln in r["transformed_snippet"].split("\n")[:15]:
                        lines.append(f"  {ln}")

        # ---- Unsupported (Python 2 / invalid input) ----
        if self._unsupported:
            rule("UNSUPPORTED (Python 2 / invalid input — not a regression)")
            for i, u in enumerate(self._unsupported, 1):
                lines.append("")
                lines.append(f"{BOLD}=== UNSUPPORTED #{i}{RESET}")
                lines.append(f"Repo    : {u['repo']}")
                lines.append(f"File    : {u['file']}")
                lines.append(f"Rule    : {u.get('combination', 'unknown')}")
                lines.append(f"Note    : {u.get('syntax_error', '?')}")

        # ---- Slow files ----
        if self._slow_files:
            rule("SLOW FILES (> 5 seconds)")
            for s in self._slow_files:
                lines.append(
                    f"  {s['repo']}/{s['file']} — "
                    f"{s.get('elapsed_ms', '?')}ms  [{s.get('combination', '')}]"
                )

        # ---- GitHub stats ----
        if self._github_stats:
            rule("GITHUB STATS")
            for k, v in self._github_stats.items():
                lines.append(f"  {k}: {v}")

        # ---- Footer ----
        lines.append("")
        divider()
        lines.append(f"Full JSON report: {self.export_json().name}")
        lines.append(f"Generated at: {ts_display}")

        filename = f"PYNEAT_FUZZ_SUMMARY_{self._ts_str}.txt"
        out_path = self.output_dir / filename
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return out_path

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _elapsed_seconds(self) -> float:
        if self._start_time:
            return (datetime.now(timezone.utc) - self._start_time).total_seconds()
        return 0.0

    def print_progress(self, current: int, total: int, prefix: str = "") -> None:
        """Print a compact progress line (overwrites same line)."""
        pct = int(current / max(total, 1) * 100)
        bar_len = 20
        filled = int(bar_len * current / max(total, 1))
        bar = "#" * filled + "." * (bar_len - filled)
        status = f"\r{prefix} [{bar}] {current}/{total} ({pct}%)"
        print(status, end="", flush=True)


# ---------------------------------------------------------------------------
# Recommendation engine (simple heuristic-based suggestions)
# ---------------------------------------------------------------------------

def _suggest_fix(exception_type: str, message: str) -> str:
    """Generate a suggestion string based on exception type and message."""
    msg_lower = message.lower()

    if "AttributeError" in exception_type or "'NoneType'" in message:
        return (
            "Null check missing. Add guard for None values before accessing attributes. "
            "Check for 'None' nodes in AST traversal — use isinstance(x, SomeType) or "
            "if x is not None before accessing x.name / x.attr"
        )
    if "TypeError" in exception_type:
        if "unexpected keyword" in msg_lower or "got an unexpected keyword" in msg_lower:
            return (
                "Argument mismatch in rule constructor. Check the rule's __init__ signature "
                "matches how it's being called in _build_engine()"
            )
        if "unsupported operand" in msg_lower:
            return "Type mismatch in binary operation. Check operand types in CST transformer."
        return "Type error — verify argument types passed to LibCST nodes match expected types."
    if "IndexError" in exception_type:
        return (
            "Index out of range. Check list/sequence access in rule logic. "
            "Add bounds checking before accessing list[idx] or use len() guard."
        )
    if "KeyError" in exception_type:
        return (
            "Dict key not found. Check dictionary access — use dict.get(key) "
            "or check 'key in dict' before access."
        )
    if "ValueError" in exception_type:
        return (
            "Invalid value. Check value constraints in rule logic — "
            "e.g., CST node type checks may be failing."
        )
    if "SyntaxError" in exception_type:
        return (
            "Generated code is invalid Python. Check LibCST transformer output — "
            "ensure nodes are properly formed and matched (opening/closing parens, etc.)"
        )
    if "RecursionError" in exception_type:
        return (
            "Infinite recursion detected. Check CST visitor/transformer — "
            "ensure leave_X methods return updated nodes and don't re-trigger visits."
        )
    if "libcst" in msg_lower or "cst" in msg_lower:
        return (
            "LibCST transformation error. Check CST node structure — "
            "ensure nodes are properly cloned/wrapped when modifying the tree."
        )
    return (
        f"Unhandled exception ({exception_type}): {message[:200]}. "
        "Wrap the rule's apply() method in try/except and log the error context."
    )


# ---------------------------------------------------------------------------
# Standalone helpers for use in other modules
# ---------------------------------------------------------------------------

def format_traceback(exc: Optional[BaseException] = None) -> str:
    """Return a clean traceback string for an exception.

    If exc is None, captures the currently active exception.
    """
    if exc is None:
        return "".join(traceback.format_exception(*sys.exc_info()))
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def truncate_snippet(content: str, max_lines: int = 30) -> str:
    """Truncate a code snippet to max_lines, keeping the first and last few lines."""
    lines = content.split("\n")
    if len(lines) <= max_lines:
        return content
    keep = max_lines // 2
    return "\n".join(lines[:keep]) + f"\n... ({len(lines) - max_lines} lines omitted) ...\n" + "\n".join(lines[-keep:])


def safe_json_dump(obj: Any) -> str:
    """Serialize an object to JSON, handling non-serializable values gracefully."""
    try:
        return json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps({"_serialization_error": str(obj)}, default=str)