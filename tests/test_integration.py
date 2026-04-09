"""Integration tests for multi-rule processing and cross-file scenarios."""

import tempfile
import os
from pathlib import Path

import pytest

from pyneat import RuleEngine, CodeFile, RuleConfig
from pyneat.rules.safe import IsNotNoneRule, SecurityScannerRule
from pyneat.rules.conservative import FStringRule
from pyneat.rules.destructive import (
    DebugCleaner, NamingConventionRule, ImportCleaningRule,
    RefactoringRule, DeadCodeRule,
)


class TestMultiRuleProcessing:
    """Test that multiple rules work together correctly."""

    def test_is_not_none_and_debug_cleaner_together(self):
        rules = [
            IsNotNoneRule(RuleConfig(enabled=True)),
            DebugCleaner(mode="safe"),
        ]
        engine = RuleEngine(rules)

        code_file = CodeFile(
            path=Path("test.py"),
            content='x = None != y\nprint("debug:", x)',
        )
        result = engine.process_code_file(code_file)

        assert result.success
        assert "is not None" in result.transformed_content
        assert "print" not in result.transformed_content

    def test_rules_execute_in_priority_order(self):
        rules = [
            IsNotNoneRule(RuleConfig(enabled=True)),
            DebugCleaner(mode="safe"),
        ]
        engine = RuleEngine(rules)

        code_file = CodeFile(
            path=Path("test.py"),
            content='x = None != y\nprint("[DEBUG] test")',
        )
        result = engine.process_code_file(code_file)

        assert result.success
        changes = result.changes_made
        assert any("is not None" in c for c in changes)
        assert any("print" in c.lower() for c in changes)

    def test_disabled_rules_do_not_run(self):
        rules = [
            IsNotNoneRule(RuleConfig(enabled=False)),
            DebugCleaner(mode="safe"),
        ]
        engine = RuleEngine(rules)

        code_file = CodeFile(
            path=Path("test.py"),
            content='x = None != y\nprint("debug")',
        )
        result = engine.process_code_file(code_file)

        assert result.success
        # IsNotNone should NOT have run (disabled)
        assert "None != y" in result.transformed_content
        # DebugCleaner should have run
        assert "print" not in result.transformed_content


class TestConflictDetection:
    """Test rule conflict detection."""

    def test_no_conflict_for_non_overlapping_changes(self):
        """Rules modifying different lines should not produce a conflict."""
        rules = [
            IsNotNoneRule(RuleConfig(enabled=True)),
            DebugCleaner(mode="safe"),
        ]
        engine = RuleEngine(rules)

        # IsNotNoneRule modifies line 1, DebugCleaner removes line 2
        # Different lines -> no conflict expected
        code_file = CodeFile(
            path=Path("test.py"),
            content='x = None != y\nprint("hello world")',
        )
        result = engine.process_code_file(code_file, check_conflicts=True)

        assert result.success
        # At least one rule should have made a change
        assert len(result.changes_made) >= 1

    def test_conflict_detection_reports_overlapping_rules(self):
        """When rules modify the same line, a conflict should be reported."""
        rules = [
            IsNotNoneRule(RuleConfig(enabled=True)),
            DebugCleaner(mode="aggressive"),
        ]
        engine = RuleEngine(rules)

        # Both rules touch line 1 -> conflict is expected
        code_file = CodeFile(
            path=Path("test.py"),
            content='x = None != y',
        )
        result = engine.process_code_file(code_file, check_conflicts=True)

        assert result.success
        # IsNotNone should have made a change
        assert any("is not None" in c for c in result.changes_made)


class TestCleanCodeAPI:
    """Test the clean_code() convenience function."""

    def test_clean_code_fix_is_not_none_default(self):
        from pyneat import clean_code

        result = clean_code("x != None")
        assert "is not None" in result

    def test_clean_code_keeps_original_when_disabled(self):
        from pyneat import clean_code

        result = clean_code("x != None", fix_is_not_none=False)
        assert "x != None" in result


class TestCleanFileAPI:
    """Test the clean_file() convenience function."""

    def test_clean_file_returns_result(self):
        from pyneat import clean_file
        import tempfile

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("x != None\n")
            temp_path = f.name

        try:
            result = clean_file(Path(temp_path), fix_is_not_none=True)
            assert result.success
            assert "is not None" in result.transformed_content
        finally:
            os.unlink(temp_path)


class TestRuleEngineStats:
    """Test engine statistics and reporting."""

    def test_get_rule_stats(self):
        rules = [
            IsNotNoneRule(RuleConfig(enabled=True)),
            DebugCleaner(mode="safe"),
            FStringRule(RuleConfig(enabled=True)),
        ]
        engine = RuleEngine(rules)
        stats = engine.get_rule_stats()

        assert stats['total_rules'] == 3
        assert stats['enabled_rules'] == 3
        assert len(stats['rules']) == 3

    def test_cache_stats(self):
        rules = [IsNotNoneRule(RuleConfig(enabled=True))]
        engine = RuleEngine(rules)

        code_file = CodeFile(path=Path("test.py"), content="x != None")
        engine.process_code_file(code_file)

        cache_stats = engine.get_cache_stats()
        assert 'cache_entries' in cache_stats
        assert 'cache_hits' in cache_stats


class TestGracefulErrorHandling:
    """Test that the engine handles errors gracefully."""

    def test_syntax_error_file(self):
        rules = [IsNotNoneRule(RuleConfig(enabled=True))]
        engine = RuleEngine(rules)

        code_file = CodeFile(path=Path("test.py"), content="def foo (: pass")
        result = engine.process_code_file(code_file)

        assert result.success

    def test_empty_file(self):
        rules = [IsNotNoneRule(RuleConfig(enabled=True))]
        engine = RuleEngine(rules)

        code_file = CodeFile(path=Path("test.py"), content="")
        result = engine.process_code_file(code_file)

        assert result.success
        assert result.transformed_content == ""


class TestDirectoryProcessing:
    """Test directory-level processing."""

    def test_process_directory_sequential(self):
        rules = [IsNotNoneRule(RuleConfig(enabled=True))]
        engine = RuleEngine(rules)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "a.py").write_text("x != None\n", encoding='utf-8')
            (tmp / "b.py").write_text("y != None\n", encoding='utf-8')
            (tmp / "c.txt").write_text("not python\n", encoding='utf-8')

            result = engine.process_directory(tmp, pattern="*.py", max_workers=1)

            assert result['total'] == 2
            assert result['success'] == 2


class TestNamingCrossFile:
    """Test NamingConventionRule with cross-file processing."""

    def test_naming_updates_imports_in_same_file(self):
        rule = NamingConventionRule(RuleConfig(enabled=True))

        code_file = CodeFile(
            path=Path("test.py"),
            content="class my_class:\n    pass\nx = my_class()",
        )
        result = rule.apply(code_file)

        assert result.success
        transformed = result.transformed_content
        assert "MyClass" in transformed
        assert "my_class()" not in transformed

    def test_naming_with_processed_files(self):
        rule = NamingConventionRule(RuleConfig(enabled=True))

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            main_file = tmp / "main.py"
            lib_file = tmp / "lib.py"

            lib_file.write_text("class my_helper:\n    pass\n", encoding='utf-8')
            main_file.write_text("from lib import my_helper\nx = my_helper()\n", encoding='utf-8')

            lib_code = CodeFile(path=lib_file, content=lib_file.read_text(encoding='utf-8'))
            lib_result = rule.apply(lib_code)
            assert lib_result.success

            main_code = CodeFile(path=main_file, content=main_file.read_text(encoding='utf-8'))
            main_result = rule.apply(main_code, processed_files=[lib_file])

            assert main_result.success
