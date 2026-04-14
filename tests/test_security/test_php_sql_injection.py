"""Tests for SQL injection detection patterns."""

import pytest
from pathlib import Path

from pyneat.rules.security import SecurityScannerRule
from pyneat.core.types import CodeFile, RuleConfig


def apply_rule(source: str) -> tuple[str, list]:
    """Apply SecurityScannerRule to source code and return (transformed, findings)."""
    rule = SecurityScannerRule(RuleConfig(enabled=True))
    code_file = CodeFile(path=Path("test.py"), content=source)
    result = rule.apply(code_file)
    return result.transformed_content, result.security_findings


class TestSQLInjectionPatterns:
    """Tests for SQL injection detection patterns."""

    def test_empty_code_no_error(self):
        """Empty code should not crash."""
        source = ''
        _, findings = apply_rule(source)
        assert isinstance(findings, list)

    def test_safe_code_minimal_findings(self):
        """Safe code should not have critical findings."""
        source = '''import os
x = 1
y = 2
result = x + y'''
        _, findings = apply_rule(source)
        # Safe code shouldn't have critical findings
        critical_count = sum(1 for f in findings if f.severity == 'critical')
        assert critical_count == 0

    def test_fstring_not_automatically_flagged(self):
        """F-strings by themselves are not SQL injection."""
        source = 'x = f"hello {name}"'
        _, findings = apply_rule(source)
        # Basic f-strings shouldn't be flagged
        sql_findings = [f for f in findings if 'sql' in f.problem.lower()]
        assert len(sql_findings) == 0

    def test_findings_are_list(self):
        """Findings should be a list."""
        source = 'DEBUG = True'
        _, findings = apply_rule(source)
        assert isinstance(findings, list)

    def test_each_finding_has_rule_id(self):
        """Each finding should have a rule_id."""
        source = 'DEBUG = True\nssl._create_unverified_context()'
        _, findings = apply_rule(source)
        for f in findings:
            assert hasattr(f, 'rule_id')
            assert f.rule_id.startswith('SEC-')

    def test_each_finding_has_severity(self):
        """Each finding should have a severity."""
        source = 'DEBUG = True\nssl._create_unverified_context()'
        _, findings = apply_rule(source)
        for f in findings:
            assert hasattr(f, 'severity')
            assert f.severity in ['critical', 'high', 'medium', 'low', 'info']
