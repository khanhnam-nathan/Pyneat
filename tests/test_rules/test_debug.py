"""Tests for DebugCleaner."""

import pytest
from pyneat.rules.debug import DebugCleaner
from pyneat.core.types import CodeFile, RuleConfig


def apply_rule(source: str, mode: str = "safe") -> tuple[str, list[str]]:
    rule = DebugCleaner(mode=mode)
    result = rule.apply(CodeFile(path="test.py", content=source))
    return result.transformed_content, result.changes_made


class TestDebugCleanerSafe:
    def test_removes_empty_print(self):
        source = "print()"
        assert apply_rule(source)[0].strip() == ""

    def test_removes_log_level_print(self):
        source = 'print("[DEBUG] variable")'
        assert "print" not in apply_rule(source)[0]

    def test_removes_keyword_debug_print(self):
        source = 'print("debug:", x)'
        assert "print" not in apply_rule(source)[0]

    def test_removes_keyword_test_print(self):
        source = 'print("test result:", result)'
        assert "print" not in apply_rule(source)[0]

    def test_removes_console_log(self):
        source = "console.log('debug')"
        assert "console.log" not in apply_rule(source)[0]

    def test_removes_pdb_import(self):
        source = "import pdb; pdb.set_trace()"
        assert "pdb" not in apply_rule(source)[0]

    def test_removes_ipdb_import(self):
        source = "import ipdb; ipdb.set_trace()"
        assert "ipdb" not in apply_rule(source)[0]

    def test_preserves_meaningful_print(self):
        source = 'print("Hello, World!")'
        result = apply_rule(source)[0]
        assert "print" in result

    def test_preserves_user_message_print(self):
        source = 'print("Processing complete")'
        result = apply_rule(source)[0]
        assert "print" in result

    def test_removes_debug_comment(self):
        source = "# debug: remove this\nx = 1"
        result = apply_rule(source)[0]
        assert "# debug:" not in result
        assert "x = 1" in result

    def test_preserves_normal_comment(self):
        source = "# This is a normal comment\nx = 1"
        result = apply_rule(source)[0]
        assert "# This is a normal comment" in result


class TestDebugCleanerAggressive:
    def test_removes_all_prints(self):
        source = 'print("anything")'
        assert "print" not in apply_rule(source, mode="aggressive")[0]

    def test_removes_console_log_aggressive(self):
        source = "console.log('x')"
        assert "console.log" not in apply_rule(source, mode="aggressive")[0]


class TestDebugCleanerOff:
    def test_keeps_all_prints(self):
        source = 'print("debug: test")'
        result = apply_rule(source, mode="off")[0]
        assert "print" in result

    def test_keeps_debug_comments(self):
        source = "# debug comment\nx = 1"
        result = apply_rule(source, mode="off")[0]
        assert "# debug comment" in result
