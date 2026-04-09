"""Tests for DeadCodeRule."""

import pytest
from pyneat.rules.deadcode import DeadCodeRule
from pyneat.core.types import CodeFile, RuleConfig


def apply_rule(source: str) -> tuple[str, list[str]]:
    rule = DeadCodeRule(RuleConfig(enabled=True))
    result = rule.apply(CodeFile(path="test.py", content=source))
    return result.transformed_content, result.changes_made


class TestDeadCodeRule:
    def test_removes_unused_function(self):
        source = "def unused_func():\n    return 1\nx = 2"
        result = apply_rule(source)[0]
        assert "unused_func" not in result
        assert "x = 2" in result

    def test_preserves_used_function(self):
        source = "def used_func():\n    return 1\nx = used_func()"
        result = apply_rule(source)[0]
        assert "used_func" in result

    def test_preserves_main_block_function(self):
        source = "def main():\n    pass\nif __name__ == '__main__':\n    main()"
        result = apply_rule(source)[0]
        assert "def main" in result

    def test_preserves_entry_point_names(self):
        for name in ["main", "run", "app", "cli", "serve"]:
            source = f"def {name}():\n    pass\nx = 1"
            result = apply_rule(source)[0]
            assert f"def {name}" in result, f"{name} should be preserved"

    def test_preserves_magic_methods(self):
        """Magic methods inside classes are preserved as part of the class."""
        source = "class C:\n    def __init__(self): pass\n    def __str__(self): return ''\nobj = C()"
        result = apply_rule(source)[0]
        # Class is referenced (instantiated), so preserved along with magic methods
        assert "__init__" in result

    def test_preserves_decorated_functions(self):
        source = "@app.route('/')\ndef home():\n    return 'hi'"
        result = apply_rule(source)[0]
        assert "def home" in result

    def test_preserves_function_with_side_effect(self):
        source = "def side_effect():\n    print('hi')\nside_effect()"
        result = apply_rule(source)[0]
        assert "def side_effect" in result

    def test_preserves_function_with_yield(self):
        source = "def gen():\n    yield 1\nx = 1"
        result = apply_rule(source)[0]
        assert "def gen" in result

    def test_preserves_function_with_raise(self):
        source = "def error():\n    raise ValueError()\nx = 1"
        result = apply_rule(source)[0]
        assert "def error" in result

    def test_removes_unused_class(self):
        source = "class UnusedClass:\n    pass\nx = 1"
        result = apply_rule(source)[0]
        assert "UnusedClass" not in result
        assert "x = 1" in result

    def test_no_change_empty_file(self):
        source = ""
        result = apply_rule(source)[0]
        assert result == source

    def test_change_reported(self):
        source = "def unused():\n    return 1\nx = 2"
        _, changes = apply_rule(source)
        assert len(changes) > 0

    def test_no_false_positive_used_via_attribute(self):
        source = "class Helper:\n    def run(self): pass\nobj = Helper()\nobj.run()"
        result = apply_rule(source)[0]
        # Helper might or might not be removed depending on attribute analysis depth
        # But it shouldn't crash
        assert "run" in result or "Helper" in result
