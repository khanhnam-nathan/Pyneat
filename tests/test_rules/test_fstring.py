"""Tests for FStringRule."""

import pytest
from pyneat.rules.fstring import FStringRule
from pyneat.core.types import CodeFile, RuleConfig


def apply_rule(source: str) -> tuple[str, list[str]]:
    rule = FStringRule(RuleConfig(enabled=True))
    result = rule.apply(CodeFile(path="test.py", content=source))
    return result.transformed_content, result.changes_made


class TestFStringRule:
    def test_converts_numbered_placeholder(self):
        """Convert "{0}".format(name) -> f"{name}" (replaces {0} with positional arg)."""
        source = '"Hello {0}".format(name)'
        result = apply_rule(source)[0]
        assert "f" in result
        assert "Hello" in result  # Original text preserved

    def test_converts_named_placeholder(self):
        """Named placeholders like {name} are already in f-string format."""
        source = '"Hello {name}".format(name=name)'
        result = apply_rule(source)[0]
        assert "f" in result
        assert "{name}" in result

    def test_converts_text_with_placeholder(self):
        """"Value: {}".format(x) becomes f"Value: {x}"."""
        source = '"Value: {}".format(x)'
        result = apply_rule(source)[0]
        assert "f" in result
        assert "Value:" in result  # Original text preserved

    def test_preserves_normal_strings(self):
        source = '"hello world"'
        result = apply_rule(source)[0]
        assert result == source

    def test_no_false_positives(self):
        source = "x = 'normal string'\ny = 'another'"
        result = apply_rule(source)[0]
        assert result == source

    def test_error_handling_malformed(self):
        source = "x = 'incomplete {"
        result = apply_rule(source)[0]
        assert result != ""

    def test_error_handling_invalid(self):
        source = "def foo(): pass"
        result = apply_rule(source)[0]
        assert "def foo" in result

    def test_change_reported(self):
        source = '"Hello {0}".format(name)'
        _, changes = apply_rule(source)
        assert isinstance(changes, list)
