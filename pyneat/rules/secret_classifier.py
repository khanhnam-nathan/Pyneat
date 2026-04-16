"""Secret classifier for distinguishing test data from production secrets.

Detects and classifies hardcoded secrets based on variable names, value patterns,
and context. This helps reduce false positives in security scanning.

Copyright (c) 2026 PyNEAT Authors
License: AGPL-3.0
"""

import re
from enum import Enum
from typing import Tuple, Optional


class SecretType(Enum):
    """Classification of secret types."""
    TEST_SECRET = "test_secret"
    PRODUCTION_SECRET = "production_secret"
    PLACEHOLDER = "placeholder"
    UNKNOWN = "unknown"


# Test/development indicators in variable names
TEST_VAR_PATTERNS = [
    "test", "mock", "fake", "dummy", "sample", "example",
    "dev", "debug", "localhost", "placeholder", "todo",
    "sandbox", "staging", "ci", "unit",
]

# Production indicators in variable names
PROD_VAR_PATTERNS = [
    "prod", "production", "live", "real", "primary", "master",
    "production", "release",
]

# Placeholder values commonly used in test/dev
PLACEHOLDER_VALUES = {
    "changeme", "your-secret", "your_secret", "example-key", "example_key",
    "test-token", "test_token", "xxx", "abc", "password123", "secret123",
    "changeme123", "demo", "demo123",
}

# Credential format patterns (real secrets)
CREDENTIAL_PATTERNS = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"[A-Za-z0-9/+=]{40}", "AWS Secret Key (potential)"),
    # GitHub
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"github_pat_[a-zA-Z0-9_]{22,}", "GitHub Fine-grained PAT"),
    # GitLab
    (r"glpat-[a-zA-Z0-9\-]{20}", "GitLab Personal Access Token"),
    # OpenAI
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
    # Slack
    (r"xox[baprs]-[a-zA-Z0-9\-]{10,}", "Slack Token"),
    # Stripe
    (r"sk_live_[a-zA-Z0-9]{24}", "Stripe Secret Key"),
    (r"pk_live_[a-zA-Z0-9]{24}", "Stripe Public Key"),
    # Database
    (r"postgres(ql)?://[^\s]+", "Database URL"),
    (r"mysql://[^\s]+", "MySQL URL"),
    (r"mongodb://[^\s]+", "MongoDB URL"),
    (r"redis://[^\s]+", "Redis URL"),
    # JWT
    (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT Token"),
    # Private keys
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key"),
    # Generic API keys (at least 20 chars)
    (r"api[_-]?key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]", "API Key"),
]


def classify_secret(
    var_name: str,
    value: str,
    context: Optional[dict] = None
) -> Tuple[SecretType, float]:
    """Classify a detected secret as test, production, or placeholder.

    Args:
        var_name: Name of the variable containing the secret
        value: The secret value
        context: Optional context dict with keys like 'is_test_file', 'file_path'

    Returns:
        Tuple of (SecretType, confidence) where confidence is 0.0-1.0
    """
    context = context or {}
    var_lower = var_name.lower()
    value_lower = value.lower()

    # Check for test variable name patterns
    test_count = sum(1 for p in TEST_VAR_PATTERNS if p in var_lower)
    prod_count = sum(1 for p in PROD_VAR_PATTERNS if p in var_lower)

    # Strong test indicators
    if test_count >= 2 and prod_count == 0:
        return (SecretType.TEST_SECRET, 0.92)

    # Strong production indicators
    if prod_count >= 1:
        return (SecretType.PRODUCTION_SECRET, 0.90)

    # Check for placeholder values
    if value_lower in PLACEHOLDER_VALUES:
        return (SecretType.PLACEHOLDER, 0.95)

    # Check if value looks like a placeholder pattern
    if _is_placeholder_pattern(value):
        return (SecretType.PLACEHOLDER, 0.90)

    # Check for real credential format
    for pattern, cred_type in CREDENTIAL_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            # This looks like a real credential
            return (SecretType.PRODUCTION_SECRET, 0.85)

    # Check for base64-like patterns (potential encoded secrets)
    if _is_base64_encoded(value):
        return (SecretType.PRODUCTION_SECRET, 0.75)

    # Check value length (production secrets are typically longer)
    if len(value) >= 32:
        return (SecretType.PRODUCTION_SECRET, 0.70)

    # Check context (test file vs production file)
    if context.get('is_test_file'):
        return (SecretType.TEST_SECRET, 0.80)

    # Check file path patterns
    file_path = context.get('file_path', '')
    if 'test' in file_path.lower() or '/tests/' in file_path:
        return (SecretType.TEST_SECRET, 0.75)

    if 'config' in file_path.lower() or 'settings' in file_path.lower():
        # Config files might have real secrets
        if len(value) >= 20:
            return (SecretType.PRODUCTION_SECRET, 0.65)
        return (SecretType.UNKNOWN, 0.50)

    return (SecretType.UNKNOWN, 0.50)


def _is_placeholder_pattern(value: str) -> bool:
    """Check if value looks like a placeholder pattern."""
    value_lower = value.lower()

    # Common placeholder patterns
    placeholder_patterns = [
        r"^test\d*$",
        r"^fake\d*$",
        r"^mock\d*$",
        r"^example\d*$",
        r"^sample\d*$",
        r"^xxx+$",
        r"^abc+$",
        r"^<[^>]+>$",  # <placeholder>
    ]

    for pattern in placeholder_patterns:
        if re.match(pattern, value_lower):
            return True

    # Very short values (< 5 chars) are likely placeholders
    if len(value) < 5:
        return True

    return False


def _is_base64_encoded(value: str) -> bool:
    """Check if value looks like base64 encoded data."""
    if not value:
        return False

    # Base64 regex pattern
    pattern = r"^[A-Za-z0-9+/]+={0,2}$"

    # Must be at least 16 chars to be considered (avoids false positives)
    if len(value) < 16:
        return False

    # Must match base64 pattern and not be too simple
    if re.match(pattern, value) and not re.match(r"^[A-Za-z]+$", value):
        return True

    return False


def get_fix_hint(var_name: str, secret_type: SecretType) -> str:
    """Get a fix hint based on the secret type.

    Args:
        var_name: Variable name containing the secret
        secret_type: Classification of the secret

    Returns:
        Fix hint string
    """
    env_var = var_name.upper()

    if secret_type == SecretType.PLACEHOLDER:
        return f"Use a real secret value in production, or remove this {var_name} assignment"

    if secret_type == SecretType.TEST_SECRET:
        return f"OK for test/development. For production, use: {var_name} = os.environ.get('{env_var}')"

    return f"Use environment variables: {var_name} = os.environ.get('{env_var}')"


def get_severity_for_type(secret_type: SecretType) -> str:
    """Get severity level based on secret type.

    Args:
        secret_type: Classification of the secret

    Returns:
        Severity string
    """
    from pyneat.core.types import SecuritySeverity

    mapping = {
        SecretType.PRODUCTION_SECRET: SecuritySeverity.HIGH,
        SecretType.PLACEHOLDER: SecuritySeverity.LOW,
        SecretType.TEST_SECRET: SecuritySeverity.MEDIUM,
        SecretType.UNKNOWN: SecuritySeverity.MEDIUM,
    }

    return mapping.get(secret_type, SecuritySeverity.MEDIUM)


# Example usage and tests
if __name__ == "__main__":
    test_cases = [
        ("test_api_key", "changeme"),
        ("test_token", "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        ("api_key", "AKIAIOSFODNN7EXAMPLE"),
        ("stripe_key", "live_xxxx_yyyy_aaaa_bbbb_cccc_dddd"),
        ("prod_password", "secret123"),
        ("stripe_key2", "live_xxxx_yyyy_aaaa_bbbb_cccc_dddd"),
        ("MY_KEY", "live_xxxx_yyyy_aaaa_bbbb_cccc_dddd"),
        ("debug_token", "JWT_TOKEN_PLACEHOLDER_NOT_VALID"),
    ]

    print("Secret Classification Tests:")
    print("=" * 60)
    for var_name, value in test_cases:
        secret_type, confidence = classify_secret(var_name, value)
        print(f"{var_name}: {secret_type.value} ({confidence:.0%})")
        print(f"  Value: {value[:30]}...")
        print()
