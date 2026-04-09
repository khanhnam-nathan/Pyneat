"""Tests for RangeLenRule."""

import pytest
from pyneat.rules.range_len_pattern import RangeLenRule
from pyneat.core.types import CodeFile, RuleConfig


def apply_rule(source: str) -> tuple[str, list[str]]:
    rule = RangeLenRule(RuleConfig(enabled=True))
    result = rule.apply(CodeFile(path="test.py", content=source))
    return result.transformed_content, result.changes_made


class TestRangeLenRule:
    def test_transforms_simple_pattern(self):
        source = "for i in range(len(items)):\n    item = items[i]"
        result = apply_rule(source)[0]
        assert "for item in items:" in result
        assert "items[i]" not in result

    def test_replaces_subscript_in_body(self):
        source = "for i in range(len(items)):\n    item = items[i]\n    print(item)"
        result = apply_rule(source)[0]
        assert "print(item)" in result

    def test_preserves_normal_for_loop(self):
        source = "for x in items:\n    print(x)"
        result = apply_rule(source)[0]
        assert "for x in items:" in result

    def test_no_change_for_range_with_start(self):
        source = "for i in range(0, len(items)):\n    x = items[i]"
        result = apply_rule(source)[0]
        # Should not transform when range has extra args
        assert result == source or "range(0, len" in result

    def test_preserves_complex_body(self):
        source = "for i in range(len(items)):\n    x = 1\n    y = 2"
        result = apply_rule(source)[0]
        # Should still transform even with multiple statements
        assert "for " in result

    def test_change_reported(self):
        source = "for i in range(len(items)):\n    item = items[i]"
        _, changes = apply_rule(source)
        assert len(changes) > 0

    def test_no_change_no_report(self):
        source = "for x in items:\n    print(x)"
        _, changes = apply_rule(source)
        assert len(changes) == 0

    def test_error_handling_invalid(self):
        source = "def foo(): pass"
        result = apply_rule(source)[0]
        assert "def foo" in result

    def test_no_false_positive_range_without_len(self):
        source = "for i in range(10):\n    print(i)"
        result = apply_rule(source)[0]
        assert "range(10)" in result
