"""PyNeat GitHub Fuzz Testing Tool.

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

Liên tục tải các file Python từ GitHub repos nổi tiếng, chạy pyneat lên
chúng với mọi tổ hợp rule, phát hiện crash/regression và ghi chi tiết ra
file debug phục vụ việc phân tích và sửa lỗi sau này.

Usage:
    python -m pyneat.tools.github_fuzz
    python -m pyneat.tools.github_fuzz --repos django/django psf/requests
    python -m pyneat.tools.github_fuzz --combinations all --max-files 50
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

__version__ = "1.0.0"


# ---------------------------------------------------------------------------
# Default repository list (top Python repos on GitHub)
# ---------------------------------------------------------------------------

DEFAULT_REPOS: List[str] = [
    # Top web frameworks
    "django/django",
    "psf/requests",
    "pallets/flask",
    "tiangolo/fastapi",
    # Data / science
    "numpy/numpy",
    "pandas-dev/pandas",
    "scikit-learn/scikit-learn",
    # Networking / infra
    "twisted/twisted",
    "apache/airflow",
    "ansible/ansible",
    # AI / SDKs
    "openai/openai-python",
    "microsoft/vscode",
    # CPython / tooling
    "psf/black",
    "pytest-dev/pytest",
    # Pattern / algo collections
    "faif/python-patterns",
    "vinta/awesome-python",
    "donnemartin/system-design-primer",
    "public-apis/public-apis",
    "TheAlgorithms/Python",
]


# ---------------------------------------------------------------------------
# Rule combination presets
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RuleCombination:
    """A named configuration of rule flags to test."""

    id: str
    name: str
    flags: dict

    def __str__(self) -> str:
        return self.name


# All combinations we'll test
RULE_COMBINATIONS: List[RuleCombination] = [
    # Base — safe rules only (default engine behaviour)
    RuleCombination(
        id="base",
        name="safe_rules_base",
        flags={},
    ),
    # + debug_clean modes
    RuleCombination(
        id="debug_safe",
        name="safe+debug_clean_safe",
        flags={"debug_clean_mode": "safe"},
    ),
    RuleCombination(
        id="debug_aggressive",
        name="safe+debug_clean_aggressive",
        flags={"debug_clean_mode": "aggressive"},
    ),
    # + conservative rules (one at a time)
    RuleCombination(
        id="unused",
        name="safe+enable_unused",
        flags={"enable_unused": True},
    ),
    RuleCombination(
        id="fstring",
        name="safe+enable_fstring",
        flags={"enable_fstring": True},
    ),
    RuleCombination(
        id="dead_code",
        name="safe+enable_dead_code",
        flags={"enable_dead_code": True},
    ),
    RuleCombination(
        id="redundant",
        name="safe+enable_redundant",
        flags={"enable_redundant": True},
    ),
    RuleCombination(
        id="dataclass",
        name="safe+enable_dataclass",
        flags={"enable_dataclass": True},
    ),
    # + destructive rules (one at a time)
    RuleCombination(
        id="import_cleaning",
        name="safe+enable_import_cleaning",
        flags={"enable_import_cleaning": True},
    ),
    RuleCombination(
        id="naming",
        name="safe+enable_naming",
        flags={"enable_naming": True},
    ),
    RuleCombination(
        id="refactoring",
        name="safe+enable_refactoring",
        flags={"enable_refactoring": True},
    ),
    RuleCombination(
        id="comment_clean",
        name="safe+enable_comment_clean",
        flags={"enable_comment_clean": True},
    ),
    # + dangerous combinations
    RuleCombination(
        id="dead+naming+refactoring",
        name="safe+dead_code+naming+refactoring",
        flags={
            "enable_dead_code": True,
            "enable_naming": True,
            "enable_refactoring": True,
        },
    ),
    RuleCombination(
        id="all_destructive",
        name="enable_all_destructive",
        flags={
            "enable_import_cleaning": True,
            "enable_naming": True,
            "enable_refactoring": True,
            "enable_comment_clean": True,
            "enable_redundant": True,
            "enable_dead_code": True,
            "debug_clean_mode": "safe",
        },
    ),
]

# Convenience subsets
COMBINATION_PRESETS = {
    "safe": [RULE_COMBINATIONS[0]],                        # base only
    "conservative": RULE_COMBINATIONS[:8],                  # base + debug + conservative
    "destructive": RULE_COMBINATIONS[8:14],                # destructive ones
    "all": RULE_COMBINATIONS,                              # everything
    "quick": [RULE_COMBINATIONS[0], RULE_COMBINATIONS[4]],  # base + dead_code
}


# ---------------------------------------------------------------------------
# FuzzConfig
# ---------------------------------------------------------------------------

@dataclass
class FuzzConfig:
    """Configuration for a fuzz test run."""

    # Repository settings
    repos: List[str] = field(default_factory=lambda: DEFAULT_REPOS[:5])
    max_files_per_repo: int = 200
    github_token: Optional[str] = None

    # Rule combinations
    combination_preset: str = "safe"   # safe | conservative | destructive | all | quick
    custom_combinations: Optional[List[str]] = None  # list of combination IDs

    # Execution
    timeout_seconds: float = 30.0
    max_workers: int = 4
    cache_dir: str = ".pyneat_fuzz_cache"

    # Output
    output_dir: str = "pyneat_fuzz_results"

    # Resume / dry-run
    resume_from: Optional[str] = None
    dry_download: bool = False
    verbose: bool = True

    def get_combinations(self) -> List[RuleCombination]:
        """Return the RuleCombination list to use for this run."""
        if self.custom_combinations:
            return [c for c in RULE_COMBINATIONS if c.id in self.custom_combinations]
        return COMBINATION_PRESETS.get(self.combination_preset, COMBINATION_PRESETS["safe"])

    def __post_init__(self):
        if self.combination_preset not in COMBINATION_PRESETS:
            raise ValueError(
                f"Unknown preset '{self.combination_preset}'. "
                f"Available: {list(COMBINATION_PRESETS.keys())}"
            )


# ---------------------------------------------------------------------------
# Result types (for programmatic use)
# ---------------------------------------------------------------------------

@dataclass
class FuzzResult:
    """Result of processing a single file with a single rule combination."""

    repo: str
    file_path: str
    combination_id: str
    status: str  # "success" | "crash" | "regression" | "no_op" | "timeout" | "unsupported"
    elapsed_ms: float

    # For crash
    exception_type: Optional[str] = None
    exception_message: Optional[str] = None
    traceback: Optional[str] = None

    # For regression
    syntax_error: Optional[str] = None
    original_snippet: Optional[str] = None
    transformed_snippet: Optional[str] = None

    # For success
    changes: List[str] = field(default_factory=list)
    line_count: int = 0

    # For semantic bug detection (successes with code changes)
    semantic_bugs: List[str] = field(default_factory=list)  # truthiness changes, etc.
    rule_conflicts: List[str] = field(default_factory=list)  # rules conflicting on same lines

    def to_dict(self) -> dict:
        d = {
            "repo": self.repo,
            "file": self.file_path,
            "combination": self.combination_id,
            "status": self.status,
            "elapsed_ms": round(self.elapsed_ms, 2),
        }
        if self.exception_type:
            d["exception_type"] = self.exception_type
            d["exception_message"] = self.exception_message
            d["traceback"] = self.traceback
        if self.syntax_error:
            d["syntax_error"] = self.syntax_error
            d["original_snippet"] = self.original_snippet
            d["transformed_snippet"] = self.transformed_snippet
        if self.changes:
            d["changes"] = self.changes
        d["line_count"] = self.line_count
        if self.semantic_bugs:
            d["semantic_bugs"] = self.semantic_bugs
        if self.rule_conflicts:
            d["rule_conflicts"] = self.rule_conflicts
        return d


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_fuzz(config: Optional[FuzzConfig] = None) -> List[FuzzResult]:
    """Run the fuzz test loop with the given config.

    Example:
        from pyneat.tools.github_fuzz import run_fuzz, FuzzConfig
        config = FuzzConfig(repos=["django/django"], max_files_per_repo=10)
        results = run_fuzz(config)
        for r in results:
            if r.status == "crash":
                print(f"CRASH in {r.repo}/{r.file}: {r.exception_message}")
    """
    from pyneat.tools.github_fuzz.fuzz_runner import _run_fuzz
    if config is None:
        config = FuzzConfig()
    return _run_fuzz(config)


__all__ = [
    "FuzzConfig",
    "FuzzResult",
    "RuleCombination",
    "RULE_COMBINATIONS",
    "COMBINATION_PRESETS",
    "DEFAULT_REPOS",
    "run_fuzz",
    "__version__",
]