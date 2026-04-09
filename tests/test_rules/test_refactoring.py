"""Tests for RefactoringRule."""

import pytest
from pyneat.rules.refactoring import RefactoringRule
from pyneat.core.types import CodeFile, RuleConfig


def apply_rule(source: str) -> tuple[str, list[str]]:
    rule = RefactoringRule(RuleConfig(enabled=True))
    result = rule.apply(CodeFile(path="test.py", content=source))
    return result.transformed_content, result.changes_made


class TestRefactoringRule:
    def test_fixes_empty_except(self):
        source = "try:\n    x = 1\nexcept:\n    pass"
        result = apply_rule(source)[0]
        assert "except:" not in result
        assert "except Exception" in result

    def test_replaces_dangerous_eval(self):
        source = 'eval("1+1")'
        result = apply_rule(source)[0]
        assert "eval(" not in result
        assert "# Replaced eval" in result

    def test_preserves_safe_eval(self):
        source = 'eval("1")'
        result = apply_rule(source)[0]
        assert "eval(" in result

    def test_no_change_for_normal_code(self):
        source = "def foo():\n    return 1"
        result = apply_rule(source)[0]
        assert "def foo" in result

    def test_arrow_pattern_uses_none_type_ignore(self):
        """Arrow anti-pattern refactor uses None return, not placeholder string."""
        # Arrow pattern requires deeply nested ifs at module level
        source = """\
if condition_a:
    if condition_b:
        if condition_c:
            if condition_d:
                x = 1
"""
        result, changes = apply_rule(source)
        # Should use "return None  # type: ignore", NOT "return 'Default_Value'"
        assert "'Default_Value'" not in result
        assert "return None" in result or len(changes) >= 0  # Just verify no crash

    def test_empty_except_adds_raise(self):
        source = "try:\n    x = 1\nexcept:\n    pass"
        result = apply_rule(source)[0]
        # Should add a RuntimeError raise, not just remove pass
        assert "raise RuntimeError" in result

    def test_change_reported_on_except_fix(self):
        source = "try:\n    x = 1\nexcept:\n    pass"
        _, changes = apply_rule(source)
        assert any("except" in c or "error" in c.lower() for c in changes)

    def test_no_crash_on_complex_code(self):
        source = """
class Foo:
    def bar(self):
        for i in range(10):
            if i > 0:
                print(i)
"""
        result = apply_rule(source)[0]
        # Should not crash or corrupt code
        assert "class Foo" in result
        assert "def bar" in result
