"""Tests for weak cryptography detection (SEC-011, SEC-019)."""

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


class TestWeakCrypto:
    """Tests for SEC-011: Weak Cryptography Detection."""

    def test_detects_hashlib_md5(self):
        """Should detect hashlib.md5() for cryptographic purposes."""
        source = "import hashlib\nhashlib.md5(data)"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-011" for f in findings)

    def test_detects_hashlib_sha1(self):
        """Should detect hashlib.sha1() for cryptographic purposes."""
        source = "import hashlib\nhashlib.sha1(data)"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-011" for f in findings)

    def test_severity_is_high(self):
        """Weak crypto should be marked as HIGH."""
        source = "import hashlib\nhashlib.md5(data)"
        _, findings = apply_rule(source)
        sec_011 = next((f for f in findings if f.rule_id == "SEC-011"), None)
        assert sec_011 is not None
        assert sec_011.severity == "high"

    def test_cwe_mapping(self):
        """SEC-011 should map to CWE-327."""
        source = "import hashlib\nhashlib.md5(data)"
        _, findings = apply_rule(source)
        sec_011 = next((f for f in findings if f.rule_id == "SEC-011"), None)
        assert sec_011 is not None
        assert sec_011.cwe_id == "CWE-327"


class TestInsecureRandom:
    """Tests for SEC-019: Insecure Random Number Generation."""

    def test_detects_random_choice(self):
        """Should detect random.choice() for security purposes."""
        source = "import random\ntoken = random.choice(chars)"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-019" for f in findings)

    def test_detects_random_choices(self):
        """Should detect random.choices() for security purposes."""
        source = "import random\ntoken = random.choices(chars, k=32)"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-019" for f in findings)

    def test_detects_random_random(self):
        """Should detect random.random() for security purposes."""
        source = "import random\ntoken = random.random()"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-019" for f in findings)

    def test_detects_random_randint(self):
        """Should detect random.randint() for security purposes."""
        source = "import random\ntoken = random.randint(0, 100)"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-019" for f in findings)

    def test_severity_is_high(self):
        """Insecure random should be marked as HIGH."""
        source = "import random\ntoken = random.choice(chars)"
        _, findings = apply_rule(source)
        sec_019 = next((f for f in findings if f.rule_id == "SEC-019"), None)
        assert sec_019 is not None
        assert sec_019.severity == "high"

    def test_cwe_mapping(self):
        """SEC-019 should map to CWE-338."""
        source = "import random\ntoken = random.choice(chars)"
        _, findings = apply_rule(source)
        sec_019 = next((f for f in findings if f.rule_id == "SEC-019"), None)
        assert sec_019 is not None
        assert sec_019.cwe_id == "CWE-338"
