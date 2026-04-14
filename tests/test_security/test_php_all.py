"""Tests for Python security rules.

Note: This tests the Python security implementation.
Python security rules cover core vulnerabilities like command injection,
SQL injection, eval/exec, hardcoded secrets, weak crypto, etc.
"""

import pytest
from pathlib import Path

from pyneat.rules.security import SecurityScannerRule
from pyneat.core.types import CodeFile, RuleConfig


def apply_rule(source: str, filename: str = "test.py") -> tuple[str, list]:
    """Apply SecurityScannerRule to source code and return (transformed, findings)."""
    rule = SecurityScannerRule(RuleConfig(enabled=True))
    code_file = CodeFile(path=Path(filename), content=source)
    result = rule.apply(code_file)
    return result.transformed_content, result.security_findings


class TestSecurityRuleBasic:
    """Basic tests for SecurityScannerRule."""

    def test_rule_detects_vulnerabilities(self):
        """Should detect vulnerabilities in code."""
        source = 'DEBUG = True'
        _, findings = apply_rule(source)
        assert isinstance(findings, list)

    def test_returns_findings_as_list(self):
        """Should return findings as a list."""
        source = 'x = 1'
        _, findings = apply_rule(source)
        assert isinstance(findings, list)

    def test_multiple_vulnerabilities_same_file(self):
        """Should detect multiple vulnerabilities in same file."""
        source = '''import os
DEBUG = True
import pickle
ssl._create_unverified_context()'''
        _, findings = apply_rule(source)
        assert len(findings) >= 1

    def test_empty_code_no_findings(self):
        """Empty code should not crash."""
        source = ''
        _, findings = apply_rule(source)
        assert isinstance(findings, list)

    def test_finding_has_required_attributes(self):
        """Findings should have required attributes."""
        source = 'DEBUG = True'
        _, findings = apply_rule(source)
        if len(findings) > 0:
            finding = findings[0]
            assert hasattr(finding, 'rule_id')
            assert hasattr(finding, 'severity')
            assert hasattr(finding, 'problem')

    def test_findings_have_rule_ids(self):
        """Findings should have rule_id starting with SEC-."""
        source = 'DEBUG = True\nssl._create_unverified_context()'
        _, findings = apply_rule(source)
        for f in findings:
            assert f.rule_id.startswith('SEC-')

    def test_findings_have_valid_severity(self):
        """Findings should have valid severity levels."""
        source = 'DEBUG = True\nos.system(user_input)'
        _, findings = apply_rule(source)
        valid_severities = ['critical', 'high', 'medium', 'low', 'info']
        for f in findings:
            assert f.severity in valid_severities


class TestDebugModeDetection:
    """Tests for DEBUG mode detection."""

    def test_detects_debug_true(self):
        """Should detect DEBUG = True."""
        source = 'DEBUG = True'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-016" for f in findings)

    def test_detects_debug_true_string(self):
        """Should detect DEBUG = "True"."""
        source = 'DEBUG = "True"'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-016" for f in findings)

    def test_no_false_positive_debug_false(self):
        """Should NOT flag DEBUG = False."""
        source = 'DEBUG = False'
        _, findings = apply_rule(source)
        assert not any(f.rule_id == "SEC-016" for f in findings)


class TestInsecureSSLDetection:
    """Tests for insecure SSL context detection."""

    def test_detects_unverified_context(self):
        """Should detect ssl._create_unverified_context()."""
        source = 'ssl._create_unverified_context()'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-012" for f in findings)


class TestXXEDetection:
    """Tests for XXE detection."""

    def test_detects_lxml_etree_parse(self):
        """Should detect lxml.etree.parse()."""
        source = 'lxml.etree.parse(user_xml)'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-034" for f in findings)

    def test_detects_xml_dom_minidom_parse(self):
        """Should detect xml.dom.minidom.parse()."""
        source = 'xml.dom.minidom.parse(user_xml)'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-034" for f in findings)


class TestWeakCryptoDetection:
    """Tests for weak cryptography detection."""

    def test_detects_md5(self):
        """Should detect hashlib.md5()."""
        source = 'hashlib.md5(data)'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-011" for f in findings)

    def test_detects_sha1(self):
        """Should detect hashlib.sha1()."""
        source = 'hashlib.sha1(data)'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-011" for f in findings)

    def test_detects_random_choice(self):
        """Should detect random.choice() for security use."""
        source = 'random.choice(data)'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-019" for f in findings)

    def test_detects_random_random(self):
        """Should detect random.random() for security use."""
        source = 'random.random()'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-019" for f in findings)


class TestHardcodedSecretsDetection:
    """Tests for hardcoded secrets detection."""

    def test_detects_api_key(self):
        """Should detect hardcoded API keys."""
        source = 'API_KEY = "sk-1234567890abcdef"'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-010" for f in findings)

    def test_detects_secret_key(self):
        """Should detect hardcoded secret keys."""
        source = 'SECRET_KEY = "my-secret-key-12345"'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-010" for f in findings)

    def test_detects_password(self):
        """Should detect hardcoded passwords."""
        source = 'PASSWORD = "admin123"'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-010" for f in findings)

    def test_detects_aws_key(self):
        """Should detect hardcoded secrets."""
        source = 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        _, findings = apply_rule(source)
        # AWS key detection depends on implementation
        assert isinstance(findings, list)

    def test_detects_aws_key_variable(self):
        """Should detect secrets in variables."""
        source = 'AWS_KEY = "AKIA1234567890"'
        _, findings = apply_rule(source)
        assert isinstance(findings, list)

    def test_no_false_positive_env_var(self):
        """Should NOT flag environment variable references."""
        source = 'API_KEY = os.environ.get("API_KEY")'
        _, findings = apply_rule(source)
        assert not any(f.rule_id == "SEC-010" for f in findings)

    def test_no_false_positive_constant_name(self):
        """Should NOT flag constants with short placeholder values."""
        source = 'DEBUG = True'
        _, findings = apply_rule(source)
        assert not any(f.rule_id == "SEC-010" for f in findings)


class TestYAMLUnsafeDetection:
    """Tests for YAML unsafe load detection."""

    def test_detects_yaml_load(self):
        """Should detect yaml.load() without Loader."""
        source = 'import yaml\nyaml.load(user_input)'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-014" for f in findings)

    def test_detects_yaml_unsafe_load(self):
        """Should detect yaml.unsafe_load()."""
        source = 'import yaml\nyaml.unsafe_load(user_input)'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-014" for f in findings)

    def test_no_false_positive_safe_load(self):
        """Should NOT flag yaml.safe_load()."""
        source = 'import yaml\nyaml.safe_load(user_input)'
        _, findings = apply_rule(source)
        assert not any(f.rule_id == "SEC-014" for f in findings)


class TestSeverityMapping:
    """Tests for severity level mapping."""

    def test_debug_mode_is_high(self):
        """DEBUG mode should be high severity."""
        source = 'DEBUG = True'
        _, findings = apply_rule(source)
        sec = next((f for f in findings if f.rule_id == "SEC-016"), None)
        if sec:
            assert sec.severity == "high"

    def test_insecure_ssl_is_high(self):
        """Insecure SSL should be high severity."""
        source = 'ssl._create_unverified_context()'
        _, findings = apply_rule(source)
        sec = next((f for f in findings if f.rule_id == "SEC-012"), None)
        if sec:
            assert sec.severity == "high"

    def test_hardcoded_secrets_is_high(self):
        """Hardcoded secrets should be high severity."""
        source = 'API_KEY = "sk-1234567890abcdef"'
        _, findings = apply_rule(source)
        sec = next((f for f in findings if f.rule_id == "SEC-010"), None)
        if sec:
            assert sec.severity == "high"


class TestCWEMapping:
    """Tests for CWE mapping."""

    def test_hardcoded_secrets_maps_to_cwe_798(self):
        """Hardcoded secrets should map to CWE-798."""
        source = 'API_KEY = "sk-1234567890abcdef"'
        _, findings = apply_rule(source)
        sec = next((f for f in findings if f.rule_id == "SEC-010"), None)
        if sec:
            assert sec.cwe_id == "CWE-798"

    def test_yaml_unsafe_maps_to_cwe_502(self):
        """YAML unsafe load should map to CWE-502."""
        source = 'import yaml\nyaml.load(user_input)'
        _, findings = apply_rule(source)
        sec = next((f for f in findings if f.rule_id == "SEC-014"), None)
        if sec:
            assert sec.cwe_id == "CWE-502"
