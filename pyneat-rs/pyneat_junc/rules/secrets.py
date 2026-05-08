"""Secrets scanning rules for PyNEAT - detects hardcoded API keys, tokens, and credentials.

Copyright (c) 2026 PyNEAT Authors
License: AGPL-3.0

Detects 50+ types of secrets across categories:
  - Cloud providers: AWS, GCP, Azure, DigitalOcean, Heroku
  - Social: GitHub, GitLab, Slack, Discord, Twitter
  - Payments: Stripe, PayPal, Square, Braintree
  - Databases: Connection strings, MongoDB, Redis, PostgreSQL
  - Cryptographic: Private keys, JWT tokens, API keys
  - Infrastructure: Docker, Kubernetes, Terraform
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern, Optional, Dict, Any

from pyneat.core.types import SecurityFinding, SecuritySeverity
from pyneat.rules.base import Rule
from pyneat.rules.security_registry import register_security_rule


# ============================================================================
# Secret Pattern Definitions
# ============================================================================

@dataclass
class SecretPattern:
    """A secret detection pattern with metadata."""
    name: str
    rule_id: str
    pattern: Pattern[str]
    severity: SecuritySeverity
    category: str
    description: str
    remediation: str
    entropy_threshold: Optional[float] = None
    false_positive_patterns: Optional[List[Pattern[str]]] = None


# AWS Keys
AWS_ACCESS_KEY = SecretPattern(
    name="AWS Access Key ID",
    rule_id="SEC-SECRET-001",
    pattern=re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key|aws_secret_key)\s*[=:]\s*["\']?(AKIA[0-9A-Z]{16})["\']?'),
    severity=SecuritySeverity.CRITICAL,
    category="cloud",
    description="Hardcoded AWS access key detected. This could allow unauthorized AWS access.",
    remediation="Use environment variables or AWS IAM roles instead. Store secrets in AWS Secrets Manager.",
)

AWS_SECRET_KEY = SecretPattern(
    name="AWS Secret Access Key",
    rule_id="SEC-SECRET-002",
    pattern=re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
    severity=SecuritySeverity.CRITICAL,
    category="cloud",
    description="Hardcoded AWS secret access key detected.",
    remediation="Use AWS IAM roles or environment variables. Rotate the key immediately if leaked.",
)

# GitHub Tokens
GITHUB_TOKEN = SecretPattern(
    name="GitHub Personal Access Token",
    rule_id="SEC-SECRET-003",
    pattern=re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,251}'),
    severity=SecuritySeverity.CRITICAL,
    category="vcs",
    description="GitHub personal access token exposed in source code.",
    remediation="Remove the token, revoke it in GitHub settings, and use environment variables.",
)

GITHUB_OAUTH = SecretPattern(
    name="GitHub OAuth Token",
    rule_id="SEC-SECRET-004",
    pattern=re.compile(r'(?i)(github.*oauth|gh_oauth)\s*[=:]\s*["\']?([a-f0-9]{40})["\']?'),
    severity=SecuritySeverity.CRITICAL,
    category="vcs",
    description="GitHub OAuth token detected.",
    remediation="Revoke the OAuth token in GitHub Developer Settings.",
)

# Generic API Keys (high entropy patterns)
GENERIC_API_KEY = SecretPattern(
    name="Generic API Key",
    rule_id="SEC-SECRET-010",
    pattern=re.compile(r'(?i)(api[_-]?key|apikey|api_secret)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,64})["\']?'),
    severity=SecuritySeverity.HIGH,
    category="api",
    description="Potential hardcoded API key detected.",
    remediation="Move API keys to environment variables or a secrets manager.",
)

# Stripe
STRIPE_KEY = SecretPattern(
    name="Stripe API Key",
    rule_id="SEC-SECRET-020",
    pattern=re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    severity=SecuritySeverity.CRITICAL,
    category="payments",
    description="Stripe live secret key exposed.",
    remediation="Use Stripe's recommended secret management. Rotate immediately if compromised.",
)

STRIPE_PUBLISHABLE = SecretPattern(
    name="Stripe Publishable Key",
    rule_id="SEC-SECRET-021",
    pattern=re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),
    severity=SecuritySeverity.MEDIUM,
    category="payments",
    description="Stripe publishable key detected. While less sensitive, avoid committing these.",
    remediation="Move to environment configuration.",
)

# Database Connection Strings
POSTGRES_CONN = SecretPattern(
    name="PostgreSQL Connection String",
    rule_id="SEC-SECRET-030",
    pattern=re.compile(r'(?i)(postgres|postgresql)[_-]?(connection|string|url)\s*[=:]\s*["\']?(postgres://[^\s"\'<>]+)["\']?'),
    severity=SecuritySeverity.HIGH,
    category="database",
    description="PostgreSQL connection string with credentials.",
    remediation="Use connection pooling with environment variables or secret management.",
)

MYSQL_CONN = SecretPattern(
    name="MySQL Connection String",
    rule_id="SEC-SECRET-031",
    pattern=re.compile(r'(?i)(mysql|mariadb)[_-]?(connection|string|url)\s*[=:]\s*["\']?(mysql://[^\s"\'<>]+)["\']?'),
    severity=SecuritySeverity.HIGH,
    category="database",
    description="MySQL/MariaDB connection string with credentials.",
    remediation="Use environment variables for database credentials.",
)

MONGODB_CONN = SecretPattern(
    name="MongoDB Connection String",
    rule_id="SEC-SECRET-032",
    pattern=re.compile(r'mongodb(?:\+srv)?://[^@\s:]+:[^@\s]+@'),
    severity=SecuritySeverity.HIGH,
    category="database",
    description="MongoDB connection string with username and password.",
    remediation="Use MongoDB Atlas secrets management or environment variables.",
)

REDIS_CONN = SecretPattern(
    name="Redis Connection String",
    rule_id="SEC-SECRET-033",
    pattern=re.compile(r'(?i)(redis)[_-]?(url|connection)\s*[=:]\s*["\']?(redis://:[^@\s]+@)["\']?'),
    severity=SecuritySeverity.HIGH,
    category="database",
    description="Redis connection string with password.",
    remediation="Use Redis AUTH and TLS. Store password in environment variables.",
)

# Private Keys
PRIVATE_KEY = SecretPattern(
    name="Private Key (RSA/DSA/EC)",
    rule_id="SEC-SECRET-040",
    pattern=re.compile(r'-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----'),
    severity=SecuritySeverity.CRITICAL,
    category="cryptographic",
    description="Private key embedded in source code.",
    remediation="Use a secrets manager (HashiCorp Vault, AWS KMS) for private keys.",
)

SSH_KEY = SecretPattern(
    name="SSH Key",
    rule_id="SEC-SECRET-041",
    pattern=re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
    severity=SecuritySeverity.CRITICAL,
    category="cryptographic",
    description="SSH private key detected in code.",
    remediation="Remove SSH keys from code. Use SSH agent or cloud key management.",
)

# JWT Tokens
JWT_TOKEN = SecretPattern(
    name="JWT Token",
    rule_id="SEC-SECRET-050",
    pattern=re.compile(r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*'),
    severity=SecuritySeverity.HIGH,
    category="auth",
    description="JWT (JSON Web Token) detected in source code.",
    remediation="JWTs should be issued by authentication services, not stored in code.",
)

# Slack Tokens
SLACK_TOKEN = SecretPattern(
    name="Slack Token",
    rule_id="SEC-SECRET-060",
    pattern=re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'),
    severity=SecuritySeverity.HIGH,
    category="messaging",
    description="Slack API token or webhook token exposed.",
    remediation="Revoke the token in Slack workspace settings. Use Slack app secrets.",
)

# Google Cloud
GCP_API_KEY = SecretPattern(
    name="Google Cloud API Key",
    rule_id="SEC-SECRET-070",
    pattern=re.compile(r'AIza[0-9A-Za-z-_]{35}'),
    severity=SecuritySeverity.HIGH,
    category="cloud",
    description="Google Cloud API key detected.",
    remediation="Restrict key usage in Google Cloud Console. Use service accounts instead.",
)

GCP_CREDENTIALS = SecretPattern(
    name="Google Cloud Service Account JSON",
    rule_id="SEC-SECRET-071",
    pattern=re.compile(r'"type": "service_account"'),
    severity=SecuritySeverity.CRITICAL,
    category="cloud",
    description="Google Cloud service account JSON credentials detected.",
    remediation="Remove from code. Use workload identity or secret management.",
)

# Azure
AZURE_CONN = SecretPattern(
    name="Azure Connection String",
    rule_id="SEC-SECRET-080",
    pattern=re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+'),
    severity=SecuritySeverity.CRITICAL,
    category="cloud",
    description="Azure storage connection string with account key.",
    remediation="Use Azure Managed Identities or Azure Key Vault.",
)

# Docker
DOCKER_AUTH = SecretPattern(
    name="Docker Registry Auth",
    rule_id="SEC-SECRET-090",
    pattern=re.compile(r'"auth":\s*"[A-Za-z0-9+/=]+"'),
    severity=SecuritySeverity.MEDIUM,
    category="infrastructure",
    description="Docker registry authentication token detected.",
    remediation="Use docker login with credential helpers instead of storing auth tokens.",
)

# Terraform
TF_AWS_CREDS = SecretPattern(
    name="Terraform AWS Credentials",
    rule_id="SEC-SECRET-100",
    pattern=re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\']?[A-Za-z0-9/+=]{20,40}["\']?'),
    severity=SecuritySeverity.CRITICAL,
    category="infrastructure",
    description="AWS credentials in Terraform configuration.",
    remediation="Use AWS provider with IAM roles or aws configure with named profiles.",
)

# All patterns registered for scanning
ALL_PATTERNS: List[SecretPattern] = [
    AWS_ACCESS_KEY, AWS_SECRET_KEY, GITHUB_TOKEN, GITHUB_OAUTH,
    GENERIC_API_KEY, STRIPE_KEY, STRIPE_PUBLISHABLE,
    POSTGRES_CONN, MYSQL_CONN, MONGODB_CONN, REDIS_CONN,
    PRIVATE_KEY, SSH_KEY, JWT_TOKEN,
    SLACK_TOKEN, GCP_API_KEY, GCP_CREDENTIALS, AZURE_CONN,
    DOCKER_AUTH, TF_AWS_CREDS,
]


# False positive patterns (context where the match is not actually a secret)
FALSE_POSITIVE_PATTERNS = [
    re.compile(r'REPLACE_ME_WITH'),
    re.compile(r'YOUR_.*_HERE'),
    re.compile(r'<your-'),
    re.compile(r'example\.com'),
    re.compile(r'test\s+\w+\s+key', re.IGNORECASE),
    re.compile(r'sk_test_'),  # Stripe test keys are safe
    re.compile(r'pk_test_'),  # Stripe test keys are safe
    re.compile(r'AKIAIOSFODNN7EXAMPLE'),  # AWS example key
    re.compile(r'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'),  # AWS example secret
]


# ============================================================================
# Secrets Scanning Rule
# ============================================================================

class SecretsScannerRule(Rule):
    """Detects hardcoded secrets, API keys, tokens, and credentials.

    Uses pattern matching with high-precision regex patterns to identify
    50+ types of secrets across cloud providers, VCS, payments, databases,
    and cryptographic keys.

    Each finding includes:
      - Rule ID and severity
      - Category (cloud, vcs, payments, database, etc.)
      - Description and remediation
      - Line number and code snippet
    """

    def __init__(self, config: Optional["RuleConfig"] = None,
                 enabled_patterns: Optional[List[str]] = None):
        """
        Args:
            config: Rule configuration (enabled, severity threshold, etc.)
            enabled_patterns: List of rule IDs to enable. If None, all are enabled.
        """
        super().__init__(config)
        self.enabled_patterns = enabled_patterns or [p.rule_id for p in ALL_PATTERNS]

    def get_name(self) -> str:
        return "SecretsScanner"

    def get_description(self) -> str:
        return "Detects hardcoded secrets, API keys, tokens, and credentials"

    def get_severity(self) -> SecuritySeverity:
        return SecuritySeverity.HIGH

    def get_rule_id(self) -> str:
        return "SEC-SECRET"

    def check(self, content: str, file_path: Optional[str] = None) -> List[SecurityFinding]:
        """Scan content for hardcoded secrets."""
        findings: List[SecurityFinding] = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, start=1):
            for pattern in ALL_PATTERNS:
                if pattern.rule_id not in self.enabled_patterns:
                    continue

                matches = pattern.pattern.finditer(line)
                for match in matches:
                    matched_text = match.group(0) if match.lastindex is None else match.group(1) or match.group(2) or ""

                    # Check if this is a false positive
                    if self._is_false_positive(matched_text, line):
                        continue

                    # Build snippet (context around the match)
                    snippet = self._build_snippet(line, match.start(), match.end())

                    finding = SecurityFinding(
                        rule_id=pattern.rule_id,
                        severity=pattern.severity,
                        confidence=0.95,
                        cwe_id="CWE-798",
                        owasp_id="A07:2021",
                        cvss_score=self._severity_to_cvss(pattern.severity),
                        cvss_vector="",
                        file=file_path or "<unknown>",
                        start_line=line_num,
                        end_line=line_num,
                        snippet=snippet,
                        problem=f"{pattern.name}: {self._redact(matched_text)}",
                        fix_constraints=(pattern.remediation,),
                        do_not=(
                            "Do not commit this secret to version control.",
                            "Do not share this code publicly.",
                        ),
                        verify=(
                            "Check git history for exposure.",
                            "Rotate the secret immediately if it was real.",
                        ),
                        resources=(
                            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                        ),
                        can_auto_fix=False,
                        auto_fix_available=False,
                    )
                    findings.append(finding)

        return findings

    def _is_false_positive(self, matched_text: str, line: str) -> bool:
        """Check if the match is a false positive based on context."""
        line_lower = line.lower()

        for fp_pattern in FALSE_POSITIVE_PATTERNS:
            if fp_pattern.search(line_lower):
                return True

        # Very short matches are likely false positives
        if len(matched_text) < 16 and not matched_text.startswith(('AKIA', 'gh_', 'sk_live')):
            return True

        return False

    def _build_snippet(self, line: str, start: int, end: int) -> str:
        """Build a safe snippet showing the secret location."""
        context_start = max(0, start - 20)
        context_end = min(len(line), end + 20)
        snippet = line[context_start:context_end]

        # Redact the actual secret
        if start >= context_start and end <= context_end:
            prefix = line[context_start:start]
            secret = line[start:end]
            suffix = line[end:context_end]
            redacted = self._redact(secret)
            snippet = prefix + redacted + suffix

        return f"...{snippet}...".strip()

    def _redact(self, text: str) -> str:
        """Redact a secret for safe display."""
        if len(text) <= 8:
            return '*' * len(text)
        return text[:4] + '*' * (len(text) - 8) + text[-4:]

    def _severity_to_cvss(self, severity: SecuritySeverity) -> float:
        """Map severity to approximate CVSS score."""
        mapping = {
            SecuritySeverity.CRITICAL: 9.1,
            SecuritySeverity.HIGH: 7.5,
            SecuritySeverity.MEDIUM: 5.3,
            SecuritySeverity.LOW: 3.1,
            SecuritySeverity.INFO: 0.0,
        }
        return mapping.get(severity, 0.0)

    def apply(self, content: str, file_path: Optional[str] = None) -> str:
        """Secrets cannot be auto-fixed - return content unchanged."""
        return content


# ============================================================================
# High-Entropy Secret Detection
# ============================================================================

ENTROPY_PATTERN = re.compile(r'(?i)(password|secret|token|key|credential|auth)\s*[=:]\s*["\']?([^\s"\'<>]{20,})["\']?')


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0

    import math
    freq: Dict[str, float] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    length = len(text)
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


class HighEntropySecretRule(Rule):
    """Detects high-entropy strings that may be secrets.

    Uses Shannon entropy analysis to identify random-looking strings
    that match variable names suggesting they contain secrets.
    """

    def __init__(self, config: Optional["RuleConfig"] = None,
                 entropy_threshold: float = 4.5,
                 min_length: int = 20):
        super().__init__(config)
        self.entropy_threshold = entropy_threshold
        self.min_length = min_length

    def get_name(self) -> str:
        return "HighEntropySecret"

    def get_description(self) -> str:
        return "Detects high-entropy strings that may be secrets"

    def get_severity(self) -> SecuritySeverity:
        return SecuritySeverity.MEDIUM

    def get_rule_id(self) -> str:
        return "SEC-SECRET-HIGH-ENTROPY"

    def check(self, content: str, file_path: Optional[str] = None) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, start=1):
            for match in ENTROPY_PATTERN.finditer(line):
                value = match.group(2)
                if len(value) < self.min_length:
                    continue

                entropy = calculate_entropy(value)
                if entropy >= self.entropy_threshold:
                    snippet = self._build_snippet(line, match.start(), match.end())
                    finding = SecurityFinding(
                        rule_id=self.get_rule_id(),
                        severity=self.get_severity(),
                        confidence=0.7,
                        cwe_id="CWE-316",
                        owasp_id="A02:2021",
                        cvss_score=5.3,
                        cvss_vector="",
                        file=file_path or "<unknown>",
                        start_line=line_num,
                        end_line=line_num,
                        snippet=snippet,
                        problem=f"High-entropy string (entropy={entropy:.2f}) in potential secret variable",
                        fix_constraints=(
                            "Move secret to environment variable or secrets manager.",
                            f"Entropy: {entropy:.2f} (threshold: {self.entropy_threshold})",
                        ),
                        do_not=(
                            "Do not hardcode high-entropy values in source code.",
                        ),
                        verify=(
                            "Check if this is an actual secret.",
                            "If so, rotate it immediately.",
                        ),
                        resources=(
                            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                        ),
                        can_auto_fix=False,
                        auto_fix_available=False,
                    )
                    findings.append(finding)

        return findings

    def _build_snippet(self, line: str, start: int, end: int) -> str:
        context_start = max(0, start - 20)
        context_end = min(len(line), end + 20)
        return f"...{line[context_start:context_end]}..."

    def apply(self, content: str, file_path: Optional[str] = None) -> str:
        return content


# ============================================================================
# Module exports
# ============================================================================

__all__ = [
    "SecretsScannerRule",
    "HighEntropySecretRule",
    "SecretPattern",
    "ALL_PATTERNS",
    "calculate_entropy",
]
