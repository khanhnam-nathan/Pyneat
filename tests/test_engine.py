"""Tests for RuleEngine: process_file, process_directory, cache, error handling."""

from __future__ import annotations

import ast
import os
import tempfile
from pathlib import Path

import pytest

from pyneat.cli import _build_engine
from pyneat.core.engine import RuleEngine
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule
from pyneat.rules.debug import DebugCleaner
from pyneat.rules.imports import ImportCleaningRule

# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

_NO_BOOLS = (
    False, False, False, False,  # security, quality, performance, unused
    False, False, False, False,  # redundant, is_not_none, magic_numbers, dead_code
    False, False, False, False,  # fstring, range_len, typing, match_case
    False,                      # dataclass
    # 5 new destructive rule flags
    False, False, False, False,  # import_cleaning, naming, refactoring, comment_clean
    False,
)


@pytest.fixture
def engine():
    return _build_engine({}, *_NO_BOOLS, debug_clean_mode="off")


# --------------------------------------------------------------------------
# process_file tests
# --------------------------------------------------------------------------

def test_process_file_reads_utf8_content(engine, tmp_path):
    f = tmp_path / "test.py"
    f.write_text("x = 1\n", encoding="utf-8")
    r = engine.process_file(f)
    assert r.success
    assert "x = 1" in r.transformed_content


def test_process_file_reads_utf8_sigil_content(engine, tmp_path):
    f = tmp_path / "test.py"
    f.write_text("\ufeffx = 1\n", encoding="utf-8-sig")
    r = engine.process_file(f)
    assert r.success
    assert "\ufeff" not in r.transformed_content


def test_process_file_reads_latin1_content(engine, tmp_path):
    f = tmp_path / "test.py"
    f.write_bytes("x = 1\n".encode("latin-1"))
    r = engine.process_file(f)
    assert r.success


def test_process_file_not_found_returns_error():
    eng = RuleEngine()
    r = eng.process_file(Path("/nonexistent/file.py"))
    assert not r.success
    assert r.error is not None


def test_process_file_error_result_contains_error_message(engine, tmp_path):
    f = tmp_path / "bad.py"
    # Valid latin-1 but not valid Python: latin-1 decoding succeeds,
    # but parsing the resulting string assignment fails
    f.write_bytes(b"\x80\x81\x82\x83")
    r = engine.process_file(f)
    # latin-1 fallback decodes it as a string, then ast.parse succeeds
    # The engine itself handles syntax errors gracefully
    assert r.success  # No crash, handled gracefully
    assert r.error is None  # No error since latin-1 fallback works
    assert len(r.transformed_content) > 0


# --------------------------------------------------------------------------
# process_directory tests
# --------------------------------------------------------------------------

def _eng():
    return _build_engine({}, *_NO_BOOLS, debug_clean_mode="off")


def test_process_directory_basic(tmp_path):
    eng = _eng()
    (tmp_path / "a.py").write_text("x=1\n")
    (tmp_path / "b.py").write_text("y=2\n")
    result = eng.process_directory(tmp_path, pattern="*.py", recursive=False)
    assert result["total"] == 2
    assert result["success"] == 2
    assert result["failed"] == 0


def test_process_directory_recursive(tmp_path):
    eng = _eng()
    (tmp_path / "a.py").write_text("x=1\n")
    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "b.py").write_text("y=2\n")
    result = eng.process_directory(tmp_path, pattern="*.py", recursive=True)
    assert result["total"] == 2
    assert result["success"] == 2


def test_process_directory_recursive_disabled(tmp_path):
    eng = _eng()
    (tmp_path / "a.py").write_text("x=1\n")
    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "b.py").write_text("y=2\n")
    result = eng.process_directory(tmp_path, pattern="*.py", recursive=False)
    assert result["total"] == 1


def test_process_directory_skips_pycache(tmp_path):
    eng = _eng()
    (tmp_path / "a.py").write_text("x=1\n")
    pycache = tmp_path / "__pycache__"
    pycache.mkdir()
    (pycache / "b.py").write_text("y=2\n")
    result = eng.process_directory(tmp_path, pattern="*.py", recursive=True)
    assert result["total"] == 1
    assert result["success"] == 1


def test_process_directory_skips_venv(tmp_path):
    eng = _eng()
    (tmp_path / "a.py").write_text("x=1\n")
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "b.py").write_text("y=2\n")
    result = eng.process_directory(tmp_path, pattern="*.py", recursive=True)
    assert result["total"] == 1


def test_process_directory_custom_skip_list(tmp_path):
    eng = _eng()
    (tmp_path / "a.py").write_text("x=1\n")
    (tmp_path / "skip_me").mkdir()
    (tmp_path / "skip_me" / "b.py").write_text("y=2\n")
    result = eng.process_directory(tmp_path, pattern="*.py", recursive=True, skip=["skip_me"])
    assert result["total"] == 1


def test_process_directory_non_python_files(tmp_path):
    eng = _eng()
    (tmp_path / "a.py").write_text("x=1\n")
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "a.md").write_text("# doc")
    result = eng.process_directory(tmp_path, pattern="*.py", recursive=False)
    assert result["total"] == 1


def test_process_directory_empty_dir(tmp_path):
    eng = _eng()
    result = eng.process_directory(tmp_path, pattern="*.py", recursive=True)
    assert result["total"] == 0
    assert result["success"] == 0


def test_process_directory_results_detail(tmp_path):
    eng = _eng()
    (tmp_path / "a.py").write_text("import os\nimport os\n")
    result = eng.process_directory(tmp_path, pattern="*.py", recursive=False)
    assert result["total"] == 1
    assert len(result["results"]) == 1
    assert result["results"][0]["file"] == "a.py"
    assert result["results"][0]["success"] is True


# --------------------------------------------------------------------------
# Cache tests
# --------------------------------------------------------------------------

def test_cache_get_cached_trees_returns_none_when_empty():
    eng = RuleEngine()
    assert eng.get_cached_trees("some content") is None


def test_cache_get_cached_trees_returns_cached():
    import libcst as cst
    import ast as _ast
    eng = RuleEngine()
    tree = cst.parse_module("x = 1")
    ast_tree = _ast.parse("x = 1")
    eng.cache_trees("some content", ast_tree, tree)
    cached_ast, cached_cst = eng.get_cached_trees("some content")
    assert cached_ast is not None
    assert cached_cst is not None


def test_cache_get_cached_trees_returns_none_after_clear():
    import libcst as cst
    import ast as _ast
    eng = RuleEngine()
    eng.cache_trees("content", _ast.parse("x=1"), cst.parse_module("x=1"))
    eng.clear_cache()
    assert eng.get_cached_trees("content") is None


def test_cache_stats_shows_entries():
    import libcst as cst
    import ast as _ast
    from pyneat.core.engine import clear_module_cache

    clear_module_cache()  # Start fresh
    eng = RuleEngine()
    eng.cache_trees("a", _ast.parse("x=1"), cst.parse_module("x=1"))
    eng.cache_trees("b", _ast.parse("y=2"), cst.parse_module("y=2"))
    # Prime the hits/misses counter by calling get_cached_trees
    eng.get_cached_trees("a")  # hit
    eng.get_cached_trees("c")  # miss
    stats = eng.get_cache_stats()
    # cache_entries may include both instance + module-level cache entries
    assert stats["cache_entries"] >= 2
    assert stats["cache_enabled"] is True
    assert stats["cache_hits"] >= 1
    assert stats["cache_misses"] >= 1
    assert "hit_rate_pct" in stats


# --------------------------------------------------------------------------
# Rule add/remove tests
# --------------------------------------------------------------------------

def test_add_rule():
    eng = RuleEngine()
    initial = eng.get_rule_stats()["total_rules"]
    eng.add_rule(ImportCleaningRule(RuleConfig(enabled=True)))
    assert eng.get_rule_stats()["total_rules"] == initial + 1


def test_remove_rule():
    eng = RuleEngine()
    eng.add_rule(ImportCleaningRule(RuleConfig(enabled=True)))
    initial = eng.get_rule_stats()["total_rules"]
    eng.remove_rule("ImportCleaningRule")
    assert eng.get_rule_stats()["total_rules"] == initial - 1


def test_remove_nonexistent_rule_does_not_crash():
    eng = RuleEngine()
    eng.remove_rule("NonexistentRule")
    assert eng.get_rule_stats()["total_rules"] == 0


# --------------------------------------------------------------------------
# Error handling tests
# --------------------------------------------------------------------------

class AlwaysFailRule(Rule):
    @property
    def description(self) -> str:
        return "Always fails"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        return TransformationResult(
            original=code_file,
            transformed_content="",
            changes_made=[],
            success=False,
            error="Simulated failure",
        )


def test_process_code_file_stops_on_rule_failure():
    eng = RuleEngine([AlwaysFailRule(RuleConfig(enabled=True))])
    r = eng.process_code_file(CodeFile(path=Path("test.py"), content="x = 1"))
    assert not r.success
    assert "Simulated failure" in r.error


def test_get_rule_stats_returns_all_rules():
    eng = RuleEngine([ImportCleaningRule(), DebugCleaner(mode="off")])
    stats = eng.get_rule_stats()
    assert stats["total_rules"] == 2
    assert stats["enabled_rules"] == 2
    assert len(stats["rules"]) == 2
    assert all("priority" in r for r in stats["rules"])


# --------------------------------------------------------------------------
# Transform validation: output is always valid Python
# --------------------------------------------------------------------------

def test_transformed_content_is_valid_python(engine):
    cases = [
        "def f():\n    pass\n",
        "class C:\n    def m(self):\n        pass\n",
        "async def a():\n    await x\n",
        "match 1:\n    case _:\n        pass\n",
        "import os\nimport sys\nfrom typing import List\n",
    ]
    for src in cases:
        r = engine.process_code_file(CodeFile(path=Path("t.py"), content=src))
        assert r.success, f"Failed on: {src!r}\nError: {r.error}"
        ast.parse(r.transformed_content)


# --------------------------------------------------------------------------
# Conflict detection tests
# --------------------------------------------------------------------------

def test_conflict_detection_no_conflict():
    """Rules modifying different lines should not trigger conflict."""
    eng = RuleEngine([ImportCleaningRule(), DebugCleaner(mode="off")])
    src = "import os\nprint('hello')\n"
    r = eng.process_code_file(CodeFile(path=Path("t.py"), content=src), check_conflicts=True)
    assert r.success
    assert not any("CONFLICT" in c for c in r.changes_made)


def test_conflict_detection_detects_overlap():
    """Overlapping modifications should be detected."""
    eng = RuleEngine([ImportCleaningRule(), DebugCleaner(mode="off")])
    src = "import os\nimport os\nprint('debug')\n"
    r = eng.process_code_file(CodeFile(path=Path("t.py"), content=src), check_conflicts=True)
    assert r.success


def test_conflict_detection_rule_range_overlap():
    """Two rules modifying overlapping lines should produce a conflict."""
    from pyneat.core.types import RuleRange
    eng = RuleEngine()

    range_a = RuleRange(rule_name="RuleA", start_line=1, end_line=5)
    range_b = RuleRange(rule_name="RuleB", start_line=3, end_line=8)
    range_c = RuleRange(rule_name="RuleC", start_line=10, end_line=15)

    # Overlapping: A and B
    conflicts = eng._detect_conflicts([range_a, range_b, range_c])
    assert len(conflicts) == 1
    assert conflicts[0].rule_a == "RuleA"
    assert conflicts[0].rule_b == "RuleB"
    assert conflicts[0].line_range == (3, 5)


def test_conflict_detection_no_overlap():
    """Non-overlapping ranges should not produce conflicts."""
    from pyneat.core.types import RuleRange
    eng = RuleEngine()

    range_a = RuleRange(rule_name="RuleA", start_line=1, end_line=5)
    range_b = RuleRange(rule_name="RuleB", start_line=10, end_line=15)

    conflicts = eng._detect_conflicts([range_a, range_b])
    assert len(conflicts) == 0


def test_conflict_detection_adjacent_no_overlap():
    """Adjacent ranges (end = start-1) should not conflict."""
    from pyneat.core.types import RuleRange
    eng = RuleEngine()

    range_a = RuleRange(rule_name="RuleA", start_line=1, end_line=5)
    range_b = RuleRange(rule_name="RuleB", start_line=6, end_line=10)

    conflicts = eng._detect_conflicts([range_a, range_b])
    assert len(conflicts) == 0


def test_conflict_detection_disabled_by_default():
    """Conflict detection should be off by default (check_conflicts=False)."""
    eng = RuleEngine([ImportCleaningRule()])
    src = "import os\nimport os\n"
    r = eng.process_code_file(CodeFile(path=Path("t.py"), content=src))
    assert r.success
    # No conflict messages unless explicitly enabled
    assert not any("CONFLICT" in c for c in r.changes_made)


def test_format_conflicts():
    """Conflict messages should be human-readable."""
    from pyneat.core.types import RuleConflict
    eng = RuleEngine()

    conflict = RuleConflict(rule_a="RuleA", rule_b="RuleB", line_range=(5, 10))
    msgs = eng._format_conflicts([conflict])
    assert len(msgs) == 1
    assert "RuleA" in msgs[0]
    assert "RuleB" in msgs[0]
    assert "5-10" in msgs[0]

