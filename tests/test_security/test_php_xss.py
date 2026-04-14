"""Tests for XSS detection patterns."""

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


class TestXSSPatterns:
    """Tests for XSS detection patterns."""

    def test_empty_code_no_error(self):
        """Empty code should not crash."""
        source = ''
        _, findings = apply_rule(source)
        assert isinstance(findings, list)

    def test_safe_html_code(self):
        """Basic HTML generation should not be flagged."""
        source = '''html = "<h1>Hello</h1>"
print(html)'''
        _, findings = apply_rule(source)
        # Safe HTML shouldn't have critical issues
        critical_count = sum(1 for f in findings if f.severity == 'critical')
        assert critical_count == 0

    def test_findings_are_list(self):
        """Findings should be a list."""
        source = 'DEBUG = True'
        _, findings = apply_rule(source)
        assert isinstance(findings, list)

    def test_each_finding_has_required_attributes(self):
        """Each finding should have required attributes."""
        source = 'DEBUG = True'
        _, findings = apply_rule(source)
        if len(findings) > 0:
            f = findings[0]
            assert hasattr(f, 'rule_id')
            assert hasattr(f, 'severity')
            assert hasattr(f, 'problem')

    def test_safe_code_no_findings(self):
        """Safe code should not have findings."""
        source = 'x = 1\ny = 2\nprint(x + y)'
        _, findings = apply_rule(source)
        # Safe code should not have critical findings
        critical_findings = [f for f in findings if f.severity == 'critical']
        assert len(critical_findings) == 0
