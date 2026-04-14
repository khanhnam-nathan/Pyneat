"""Tests for pickle RCE detection (SEC-004)."""

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


class TestPickleRCE:
    """Tests for SEC-004: Pickle RCE Detection."""

    def test_detects_pickle_loads(self):
        """Should detect pickle.loads() call."""
        source = "import pickle\ndata = pickle.loads(raw_data)"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-004" for f in findings)

    def test_detects_pickle_load(self):
        """Should detect pickle.load() call."""
        source = "import pickle\nwith open('data.pkl', 'rb') as f:\n    data = pickle.load(f)"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-004" for f in findings)

    def test_severity_is_critical(self):
        """Pickle RCE should be marked as CRITICAL."""
        source = "import pickle\ndata = pickle.loads(raw_data)"
        _, findings = apply_rule(source)
        sec_004 = next((f for f in findings if f.rule_id == "SEC-004"), None)
        assert sec_004 is not None
        assert sec_004.severity == "critical"

    def test_cwe_mapping(self):
        """SEC-004 should map to CWE-502."""
        source = "import pickle\ndata = pickle.loads(raw_data)"
        _, findings = apply_rule(source)
        sec_004 = next((f for f in findings if f.rule_id == "SEC-004"), None)
        assert sec_004 is not None
        assert sec_004.cwe_id == "CWE-502"
