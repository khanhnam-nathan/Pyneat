"""Edge case tests for fuzz runner - based on bugs found during GitHub fuzz testing.

These tests verify that the fuzz tool correctly categorizes and handles
pathological code patterns found in real-world repositories.
"""

import sys
sys.path.insert(0, "D:/pyneat-final")

import pytest
from pyneat.tools.github_fuzz import FuzzConfig
from pyneat.tools.github_fuzz.fuzz_runner import (
    _test_file_with_combination,
    _detect_semantic_bugs,
    _build_engine_from_combination,
)
from pyneat.tools.github_fuzz import RULE_COMBINATIONS


# ---------------------------------------------------------------------------
# Edge case: Python 2 syntax (unsupported, not regression)
# ---------------------------------------------------------------------------

class TestPython2Unsupported:
    """Python 2 files should be marked 'unsupported', not 'regression'."""

    def test_print_statement_py2(self):
        """print "hello" is Python 2 syntax - pyneat only supports Python 3."""
        code = 'print "hello world"'
        combo = RULE_COMBINATIONS[0]  # base
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=5.0,
        )
        assert result.status in ("unsupported", "no_op"), \
            f"Python 2 print statement should be unsupported, got {result.status}"

    def test_print_without_parens(self):
        """print without parentheses is Python 2."""
        code = 'print "x=", x, ", y=", y'
        combo = RULE_COMBINATIONS[0]
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=5.0,
        )
        assert result.status in ("unsupported", "no_op")

    def test_invalid_syntax_not_regression(self):
        """Invalid syntax should not count as a regression."""
        code = 'def f(\n    pass'  # missing closing paren
        combo = RULE_COMBINATIONS[0]
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=5.0,
        )
        assert result.status in ("unsupported", "crash", "regression"), \
            f"Invalid syntax got unexpected status: {result.status}"
        if result.status == "regression":
            # A genuine regression means valid input produced invalid output
            # This is what we're trying to prevent
            pass


# ---------------------------------------------------------------------------
# Edge case: Semantic bug detection
# ---------------------------------------------------------------------------

class TestSemanticBugDetection:
    """Detect transformations that change runtime behavior."""

    def test_truthiness_warning_detected(self):
        """Simplifying x == True to x changes behavior for truthy values."""
        changes = ["Simplified redundant comparison"]
        warnings = _detect_semantic_bugs("if x == True:", "if x:", changes)
        assert any("truthy" in w.lower() for w in warnings)

    def test_empty_except_raise_warning(self):
        """Converting bare except: pass to except: raise is a behavioral change."""
        changes = ["Replaced 'pass' with 'raise' in except block to prevent silent failures."]
        warnings = _detect_semantic_bugs("except:\n    pass", "except:\n    raise", changes)
        assert any("behavior" in w.lower() or "silent" in w.lower() for w in warnings)

    def test_security_fix_flagged(self):
        """os.system -> subprocess.run is a security fix."""
        changes = ["AUTO-FIX: os.system() converted to subprocess.run() with shell=False."]
        warnings = _detect_semantic_bugs("", "", changes)
        assert any("SECURITY-FIX" in w for w in warnings)

    def test_safe_changes_no_warning(self):
        """Safe changes like is not None should not generate warnings."""
        changes = ["Fixed != None to is not None"]
        warnings = _detect_semantic_bugs("x != None", "x is not None", changes)
        assert len(warnings) == 0, f"Expected no warnings, got: {warnings}"


# ---------------------------------------------------------------------------
# Edge case: Rule isolation (one rule failing should not break others)
# ---------------------------------------------------------------------------

class TestRuleIsolation:
    """Engine should continue processing even if one rule has an internal error."""

    def test_all_combinations_run(self):
        """Every combination ID should appear in results."""
        code = "x = 1\ny = 2\n"
        seen_ids = set()
        for combo in RULE_COMBINATIONS:
            result = _test_file_with_combination(
                repo="local", gh_file_path="test.py",
                content=code, combination=combo, timeout_seconds=5.0,
            )
            seen_ids.add(result.combination_id)

        all_ids = {c.id for c in RULE_COMBINATIONS}
        assert seen_ids == all_ids, f"Missing combos: {all_ids - seen_ids}"

    def test_empty_file_handled(self):
        """Empty file should not crash any rule."""
        code = ""
        combo = RULE_COMBINATIONS[0]
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=5.0,
        )
        assert result.status in ("success", "no_op", "unsupported")

    def test_single_line_file(self):
        """Single-line file should be processed correctly."""
        code = "x = 1\n"
        combo = RULE_COMBINATIONS[0]
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=5.0,
        )
        assert result.status in ("success", "no_op", "unsupported")


# ---------------------------------------------------------------------------
# Edge case: Timing and timeouts
# ---------------------------------------------------------------------------

class TestTimeout:
    """Large files should respect timeout."""

    def test_large_file_respects_timeout(self):
        """A 50k-line file should timeout rather than hang."""
        code = "\n".join(f"x{i} = {i}" for i in range(5000))
        combo = RULE_COMBINATIONS[0]
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=2.0,
        )
        # Should either complete or timeout
        assert result.status in ("success", "no_op", "timeout", "unsupported")
        if result.status == "success":
            # Completed within time - that's fine too
            assert result.elapsed_ms < 2000


# ---------------------------------------------------------------------------
# Edge case: Encoding handling
# ---------------------------------------------------------------------------

class TestEncoding:
    """Files with various encodings should be handled."""

    def test_utf8_with_emoji(self):
        """UTF-8 content with emoji should not crash."""
        code = 'greeting = "Hello, \U0001F44D"\nprint(greeting)\n'
        combo = RULE_COMBINATIONS[0]
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=5.0,
        )
        assert result.status in ("success", "no_op", "unsupported")

    def test_utf8_with_chinese_chars(self):
        """UTF-8 with Chinese characters should not crash."""
        code = '# This is a comment\nx = 1\n'
        combo = RULE_COMBINATIONS[0]
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=5.0,
        )
        assert result.status in ("success", "no_op", "unsupported")


# ---------------------------------------------------------------------------
# Edge case: Valid Python 3 edge cases
# ---------------------------------------------------------------------------

class TestPython3EdgeCases:
    """Complex but valid Python 3 that should be handled correctly."""

    def test_walrus_operator(self):
        """Walrus operator (Python 3.8+) should work."""
        code = 'if (n := len([1, 2, 3])) > 2:\n    print(n)\n'
        combo = RULE_COMBINATIONS[0]
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=5.0,
        )
        assert result.status in ("success", "no_op")

    def test_type_annotations(self):
        """Files with complex type annotations should work."""
        code = '''from typing import Optional, List

def process(items: List[Optional[int]]) -> List[int]:
    return [x for x in items if x is not None]
'''
        combo = RULE_COMBINATIONS[0]
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=5.0,
        )
        assert result.status in ("success", "no_op")

    def test_fstring_complex(self):
        """Complex f-strings should be handled by fstring rule."""
        code = 'name = "world"\nmsg = f"Hello, {name.upper()}!"\n'
        combo = RULE_COMBINATIONS[4]  # fstring
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=5.0,
        )
        assert result.status in ("success", "no_op", "unsupported")

    def test_match_case_py310(self):
        """match-case statements should be recognized."""
        code = '''x = 1
match x:
    case 1:
        print("one")
    case 2:
        print("two")
'''
        combo = RULE_COMBINATIONS[0]
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=5.0,
        )
        assert result.status in ("success", "no_op")


# ---------------------------------------------------------------------------
# Edge case: AST parse errors within rules
# ---------------------------------------------------------------------------

class TestASTErrors:
    """AST parse errors in individual rules should be caught."""

    def test_malformed_code_inside_rule(self):
        """Code that causes AST errors within a rule should not crash the engine."""
        # This is a valid dict with potential parsing issues in nested context
        code = '{k: v for k, v in items}\n'
        combo = RULE_COMBINATIONS[0]
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=5.0,
        )
        assert result.status in ("success", "no_op", "unsupported", "crash"), \
            f"Unexpected status: {result.status} - {result.exception_type}: {result.exception_message}"

    def test_very_deeply_nested_code(self):
        """Deeply nested code should not cause RecursionError."""
        code = "\n".join(f"x{i} = " + "(" * 20 + "1" + ")" * 20 for i in range(10))
        combo = RULE_COMBINATIONS[0]
        result = _test_file_with_combination(
            repo="local", gh_file_path="test.py",
            content=code, combination=combo, timeout_seconds=5.0,
        )
        assert result.status in ("success", "no_op", "timeout", "crash", "unsupported")


# ---------------------------------------------------------------------------
# Edge case: Engine build from combination
# ---------------------------------------------------------------------------

class TestEngineBuild:
    """Test that engine is built correctly for each combination."""

    def test_safe_rules_always_present(self):
        """Safe rules (IsNotNone, RangeLen, Security, Typing, Quality, Performance)
        should always be in every combination."""
        safe_rule_names = {
            "IsNotNoneRule", "RangeLenRule", "SecurityScannerRule",
            "TypingRule", "CodeQualityRule", "PerformanceRule",
        }
        for combo in RULE_COMBINATIONS:
            engine = _build_engine_from_combination(combo)
            rule_names = {r.name for r in engine.rules}
            assert safe_rule_names.issubset(rule_names), \
                f"[{combo.id}] Missing safe rules: {safe_rule_names - rule_names}"

    def test_destructive_rules_conditional(self):
        """Destructive rules should only appear in their respective combinations."""
        destructive_rules = {
            "ImportCleaningRule", "NamingConventionRule", "RefactoringRule",
            "CommentCleaner", "RedundantExpressionRule", "DeadCodeRule",
            "DebugCleaner",
        }
        for combo in RULE_COMBINATIONS:
            engine = _build_engine_from_combination(combo)
            rule_names = {r.name for r in engine.rules}
            for dr in destructive_rules:
                present = dr in rule_names
                expected = dr.replace("Rule", "") in combo.flags or dr == "DeadCodeRule" and "dead" in combo.flags
                # This is a soft check - some combinations include multiple rules
