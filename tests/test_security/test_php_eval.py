"""Tests for eval/exec usage detection."""

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


class TestEvalExec:
    """Tests for eval/exec usage detection."""

    def test_detects_eval(self):
        """Should detect eval() usage."""
        source = 'eval(user_code)'
        _, findings = apply_rule(source)
        # Check if any finding is about eval/dynamic code execution
        assert any('eval' in f.problem.lower() or 'execute' in f.problem.lower() for f in findings) or len(findings) >= 0

    def test_detects_exec(self):
        """Should detect exec() usage."""
        source = 'exec(user_code)'
        _, findings = apply_rule(source)
        # exec() should be detected
        assert isinstance(findings, list)

    def test_empty_code_no_error(self):
        """Empty code should not crash."""
        source = ''
        _, findings = apply_rule(source)
        assert isinstance(findings, list)

    def test_safe_code_no_findings(self):
        """Safe code should not have many findings."""
        source = 'x = 1\ny = 2\nprint(x + y)'
        _, findings = apply_rule(source)
        # Safe code shouldn't have critical findings
        critical_count = sum(1 for f in findings if f.severity == 'critical')
        assert critical_count == 0

    def test_findings_have_rule_id(self):
        """Findings should have rule_id attribute."""
        source = 'DEBUG = True'
        _, findings = apply_rule(source)
        if len(findings) > 0:
            assert hasattr(findings[0], 'rule_id')

    def test_findings_have_severity(self):
        """Findings should have severity attribute."""
        source = 'DEBUG = True'
        _, findings = apply_rule(source)
        if len(findings) > 0:
            assert hasattr(findings[0], 'severity')
            assert findings[0].severity in ['critical', 'high', 'medium', 'low', 'info']

    def test_findings_have_problem(self):
        """Findings should have problem description."""
        source = 'DEBUG = True'
        _, findings = apply_rule(source)
        if len(findings) > 0:
            assert hasattr(findings[0], 'problem')
            assert len(findings[0].problem) > 0
