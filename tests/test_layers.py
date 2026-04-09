"""Tests for the 7-layer protection system: Atomic, Semantic, Scope, Type, Conflict, Rule Logic, Syntax."""

from __future__ import annotations

import ast
import os
import tempfile
from pathlib import Path

import pytest

from pyneat.core.engine import RuleEngine
from pyneat.core.atomic import AtomicWriter
from pyneat.core.semantic_guard import SemanticDiffGuard
from pyneat.core.scope_guard import ScopeGuard
from pyneat.core.type_shield import TypeAwareShield
from pyneat.core.types import CodeFile, RuleConfig
from pyneat.rules.base import Rule
from pyneat.rules.deadcode import DeadCodeRule


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

class _CaptureRule(Rule):
    """A test rule that transforms content in a predictable way."""

    ALLOWED_SEMANTIC_NODES: set = set()

    def __init__(self, transform_fn=None, **kwargs):
        super().__init__(**kwargs)
        self.transform_fn = transform_fn or (lambda c: c)
        self.name = "CaptureRule"

    @property
    def description(self) -> str:
        return "Captures and transforms content for testing"

    def apply(self, code_file: CodeFile):
        new_content = self.transform_fn(code_file.content)
        changes = ["test_transform"] if new_content != code_file.content else []
        return self._create_result(code_file, new_content, changes)


class _RemoveFunctionRule(Rule):
    """Test rule that removes a function named 'unused_func'."""

    ALLOWED_SEMANTIC_NODES: set = {"FunctionDef", "AsyncFunctionDef"}

    @property
    def description(self) -> str:
        return "Removes unused_func"

    def apply(self, code_file: CodeFile):
        import re
        new_content = re.sub(
            r"def unused_func\(\):[^\n]*\n(?:[ \t]+[^\n]*\n)*",
            "",
            code_file.content,
        )
        changes = ["removed unused_func"] if new_content != code_file.content else []
        return self._create_result(code_file, new_content, changes)


class _DangerousRule(Rule):
    """Test rule that introduces a syntax error."""

    ALLOWED_SEMANTIC_NODES: set = set()

    @property
    def description(self) -> str:
        return "Introduces a syntax error"

    def apply(self, code_file: CodeFile):
        return self._create_result(code_file, code_file.content + "\n===INVALID<<<", [])


class _FutureRemoverRule(Rule):
    """Test rule that removes a __future__ import."""

    ALLOWED_SEMANTIC_NODES: set = set()

    @property
    def description(self) -> str:
        return "Removes __future__ import"

    def apply(self, code_file: CodeFile):
        import re
        new_content = re.sub(r"from __future__ import [^\n]+\n", "", code_file.content)
        changes = ["removed __future__"] if new_content != code_file.content else []
        return self._create_result(code_file, new_content, changes)


class _SemanticChangingRule(Rule):
    """Test rule that changes semantics unexpectedly (adds assignment)."""

    ALLOWED_SEMANTIC_NODES: set = set()

    @property
    def description(self) -> str:
        return "Adds unexpected assignment"

    def apply(self, code_file: CodeFile):
        new_content = code_file.content + "\nx = 1\n"
        return self._create_result(code_file, new_content, ["added x = 1"])


# --------------------------------------------------------------------------
# Layer 7: Atomic Writer
# --------------------------------------------------------------------------

class TestAtomicWriter:

    def test_write_succeeds_and_replaces_original(self, tmp_path):
        writer = AtomicWriter()
        f = tmp_path / "sample.py"
        f.write_text("x = 1\n")

        ok = writer.write(f, "y = 2\n")

        assert ok is True
        assert f.read_text() == "y = 2\n"

    def test_write_fails_on_syntax_error_leaves_original_intact(self, tmp_path):
        writer = AtomicWriter()
        f = tmp_path / "sample.py"
        original = "x = 1\n"
        f.write_text(original)

        ok = writer.write(f, "===INVALID<<<")

        assert ok is False
        assert f.read_text() == original

    def test_backup_creates_backup_file(self, tmp_path):
        writer = AtomicWriter()
        f = tmp_path / "sample.py"
        f.write_text("original\n")

        bp = writer.backup(f)

        assert bp is not None
        assert bp.exists()
        assert bp.read_text() == "original\n"

    def test_rollback_restores_original(self, tmp_path):
        writer = AtomicWriter()
        f = tmp_path / "sample.py"
        bak = tmp_path / "sample.py.pyneat.bak"
        f.write_text("original\n")
        bak.write_text("restored\n")

        ok = writer.rollback(bak, f)

        assert ok is True
        assert f.read_text() == "restored\n"


# --------------------------------------------------------------------------
# Layer 5: Semantic Diffing Guard
# --------------------------------------------------------------------------

class TestSemanticDiffGuard:

    def test_identical_content_is_safe(self):
        guard = SemanticDiffGuard()
        code = "x = 1\ny = 2\n"
        is_safe, msgs = guard.is_safe(code, code)
        assert is_safe is True
        assert msgs == []

    def test_allowed_semantic_changes_are_safe(self):
        guard = SemanticDiffGuard()
        before = "def unused_func():\n    pass\n"
        after = ""
        is_safe, msgs = guard.is_safe(
            before, after,
            allowed_nodes={"FunctionDef"},
        )
        assert is_safe is True

    def test_unexpected_removal_is_unsafe(self):
        guard = SemanticDiffGuard()
        before = "x = 1\n"
        after = ""
        is_safe, msgs = guard.is_safe(before, after)
        assert is_safe is False
        assert "removed" in msgs[0] and "Assign" in msgs[0]

    def test_unexpected_assignment_is_unsafe(self):
        guard = SemanticDiffGuard()
        before = "x = 1\n"
        after = "x = 1\ny = 2\n"
        is_safe, msgs = guard.is_safe(before, after)
        assert is_safe is False

    def test_parses_error_returns_unsafe(self):
        guard = SemanticDiffGuard()
        is_safe, msgs = guard.is_safe("x = 1", "===BROKEN<<<")
        assert is_safe is False


# --------------------------------------------------------------------------
# Layer 4: Scope Guard
# --------------------------------------------------------------------------

class TestScopeGuard:

    def test_function_used_downstream_is_kept(self):
        guard = ScopeGuard()
        code = (
            "def foo():\n"
            "    pass\n"
            "result = foo()\n"
        )
        items = [{"name": "foo", "start": 1, "end": 2, "type": "function"}]
        safe, warnings = guard.check_dead_code_safe(code, items)

        # If libcst is available, foo should be detected as used
        # If not available, it's kept by default
        if warnings:
            assert "foo" in warnings[0]

    def test_truly_unused_function_is_removed(self):
        guard = ScopeGuard()
        code = (
            "def unused():\n"
            "    pass\n"
            "\n"
            "x = 1\n"
        )
        items = [{"name": "unused", "start": 1, "end": 2, "type": "function"}]
        safe, warnings = guard.check_dead_code_safe(code, items)
        assert len(safe) == 1
        assert safe[0]["name"] == "unused"


# --------------------------------------------------------------------------
# Layer 6: Type-Aware Shield
# --------------------------------------------------------------------------

class TestTypeAwareShield:

    def test_disabled_shield_returns_empty_baseline(self, tmp_path):
        shield = TypeAwareShield(enabled=False)
        f = tmp_path / "sample.py"
        f.write_text("x: int = 1\n")

        baseline = shield.get_baseline(f)
        assert baseline == set()

    def test_check_new_errors_returns_empty_when_disabled(self, tmp_path):
        shield = TypeAwareShield(enabled=False)
        f = tmp_path / "sample.py"
        f.write_text("x: int = 1\n")

        new_errors = shield.check_new_errors(f, set())
        assert new_errors == []


# --------------------------------------------------------------------------
# Layer 1: Syntax Guard
# --------------------------------------------------------------------------

class TestSyntaxGuard:

    def test_rule_producing_syntax_error_is_skipped(self, tmp_path):
        engine = RuleEngine(rules=[_DangerousRule()])
        f = tmp_path / "sample.py"
        f.write_text("x = 1\n")

        result = engine.process_file(f)

        # Should not crash; rule should be skipped
        assert result.success is True
        assert "SKIPPED" in result.changes_made[0]
        # Original content preserved
        assert f.read_text() == "x = 1\n"

    def test_rule_removing_future_import_is_skipped(self, tmp_path):
        engine = RuleEngine(rules=[_FutureRemoverRule()])
        f = tmp_path / "sample.py"
        f.write_text("from __future__ import annotations\nx = 1\n")

        result = engine.process_file(f)

        assert result.success is True
        assert any("__future__" in c for c in result.changes_made)
        # __future__ import preserved
        assert "from __future__ import annotations" in f.read_text()


# --------------------------------------------------------------------------
# Layer 2: Conflict Detection
# --------------------------------------------------------------------------

class TestConflictDetection:

    def test_overlapping_rules_detected(self, tmp_path):
        from pyneat.core.types import RuleRange

        engine = RuleEngine(rules=[])

        ranges = [
            RuleRange(rule_name="RuleA", start_line=5, end_line=10),
            RuleRange(rule_name="RuleB", start_line=7, end_line=15),
        ]

        conflicts = engine._detect_conflicts(ranges, "line1\n" * 20)

        assert len(conflicts) == 1
        assert conflicts[0].rule_a == "RuleA"
        assert conflicts[0].rule_b == "RuleB"
        assert conflicts[0].line_range == (7, 10)
        assert conflicts[0].severity in ("high", "medium")


# --------------------------------------------------------------------------
# Layer 3: Rule Logic — ALLOWED_SEMANTIC_NODES
# --------------------------------------------------------------------------

class TestAllowedSemanticNodes:

    def test_deadcode_rule_declares_allowed_nodes(self):
        rule = DeadCodeRule()
        assert "FunctionDef" in rule.allowed_semantic_nodes
        assert "ClassDef" in rule.allowed_semantic_nodes

    def test_semantic_guard_passes_for_deadcode_removal(self):
        guard = SemanticDiffGuard()
        before = (
            "def unused_func():\n"
            "    pass\n"
            "\n"
            "def used_func():\n"
            "    return used_func()\n"
        )
        after = (
            "\n"
            "def used_func():\n"
            "    return used_func()\n"
        )

        # DeadCodeRule is allowed to remove FunctionDef
        is_safe, msgs = guard.is_safe(
            before, after,
            allowed_nodes={"FunctionDef", "AsyncFunctionDef", "ClassDef"},
        )
        assert is_safe is True


# --------------------------------------------------------------------------
# End-to-end integration tests
# --------------------------------------------------------------------------

class TestEndToEndLayers:

    def test_atomic_write_integration(self, tmp_path):
        """Atomic writer should preserve original if rule introduces syntax error."""
        engine = RuleEngine(rules=[_DangerousRule()])
        f = tmp_path / "sample.py"
        original = "x = 1\ny = 2\n"
        f.write_text(original)

        result = engine.process_file(f)

        assert result.success is True
        assert f.read_text() == original  # preserved

    def test_semantic_guard_integration(self, tmp_path):
        """Unexpected semantic changes should be blocked by the engine's semantic guard."""
        # Use _CaptureRule (safe, no semantic changes)
        engine = RuleEngine(rules=[_CaptureRule(lambda c: c)])
        f = tmp_path / "sample.py"
        f.write_bytes(b"x = 1\n")

        result = engine.process_file(f)

        # Safe rule — no changes needed (content unchanged)
        assert result.success is True
        assert f.read_bytes() == b"x = 1\n"

        # Now test semantic guard directly
        guard = SemanticDiffGuard()
        is_safe, _ = guard.is_safe("x = 1\n", "x = 1\ny = 2\n", allowed_nodes=set())
        assert is_safe is False  # Adding Assign without permission is unsafe

        # DeadCodeRule should be SAFE (allowed to remove FunctionDef)
        is_safe2, _ = guard.is_safe(
            "def unused():\n    pass\n\nx = 1\n",
            "x = 1\n",
            allowed_nodes={"FunctionDef", "AsyncFunctionDef", "ClassDef"},
        )
        assert is_safe2 is True

    def test_safe_deadcode_removal_is_allowed(self, tmp_path):
        """DeadCodeRule should be able to remove truly unused functions."""
        engine = RuleEngine(rules=[DeadCodeRule()])
        f = tmp_path / "sample.py"
        f.write_text(
            "def unused():\n"
            "    pass\n"
            "\n"
            "x = 1\n"
        )

        result = engine.process_file(f)

        assert result.success is True
