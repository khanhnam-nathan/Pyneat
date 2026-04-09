"""Tests for IsNotNoneRule."""

import pytest
from pyneat.rules.is_not_none import IsNotNoneRule
from pyneat.core.types import CodeFile, RuleConfig


def apply_rule(source: str) -> tuple[str, list[str]]:
    rule = IsNotNoneRule(RuleConfig(enabled=True))
    result = rule.apply(CodeFile(path="test.py", content=source))
    return result.transformed_content, result.changes_made


class TestIsNotNone:
    def test_equality_to_none(self):
        """IsNotNoneRule only handles != None comparisons, not == None."""
        source = "x == None"
        result = apply_rule(source)[0]
        assert result == source  # No change for equality

    def test_inequality_to_none(self):
        assert apply_rule("x != None")[0] == "x is not None"

    def test_none_neq_x(self):
        """Fix None != x to x is not None (PEP8)."""
        source = "None != x"
        assert apply_rule(source)[0] == "x is not None"

    def test_x_neq_none_in_condition(self):
        source = "if x != None: pass"
        assert "is not None" in apply_rule(source)[0]

    def test_multiple_comparisons(self):
        """Rule handles != None but not == None equality."""
        source = "x == None and y != None"
        result = apply_rule(source)[0]
        # Only y != None is fixed to y is not None
        assert "is not None" in result
        # x == None is left unchanged (not handled by this rule)
        assert "x == None" in result

    def test_no_change_for_is_not(self):
        source = "x is not None"
        assert apply_rule(source)[0] == source

    def test_no_change_for_is_with_none(self):
        source = "x is None"
        assert apply_rule(source)[0] == source

    def test_preserves_other_code(self):
        source = "def foo(): return x != None"
        result = apply_rule(source)[0]
        assert "is not None" in result
        assert "def foo" in result

    def test_change_reported(self):
        _, changes = apply_rule("x != None")
        assert any("is not None" in c for c in changes)

    def test_no_change_no_report(self):
        _, changes = apply_rule("x is not None")
        assert len(changes) == 0

    def test_in_assignment(self):
        source = "result = x != None"
        assert "is not None" in apply_rule(source)[0]

    def test_in_return(self):
        source = "return x != None"
        assert "is not None" in apply_rule(source)[0]
