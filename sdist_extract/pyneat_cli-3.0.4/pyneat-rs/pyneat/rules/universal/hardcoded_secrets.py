"""Detect hardcoded passwords, API keys, and tokens in any language.

This is a universal rule — works on all languages that PyNeat supports.
Uses pattern-based detection on source code strings.
"""

import re
from typing import List, Dict, Any

from pyneat.rules.universal.base import UniversalRule


# Patterns that indicate hardcoded secrets
SECRET_PATTERNS = [
    r'\bpassword\s*[=:]\s*["\'][^"\']{3,}["\']',
    r'\bpasswd\s*[=:]\s*["\'][^"\']{3,}["\']',
    r'\bpwd\s*[=:]\s*["\'][^"\']{3,}["\']',
    r'\bsecret\s*[=:]\s*["\'][^"\']{3,}["\']',
    r'\bapi_key\s*[=:]\s*["\'][^"\']{3,}["\']',
    r'\bapikey\s*[=:]\s*["\'][^"\']{3,}["\']',
    r'\baccess_token\s*[=:]\s*["\'][^"\']{3,}["\']',
    r'\bauth_token\s*[=:]\s*["\'][^"\']{3,}["\']',
    r'\brefresh_token\s*[=:]\s*["\'][^"\']{3,}["\']',
    r'\bprivate_key\s*[=:]\s*["\'][^"\']{3,}["\']',
    r'\bsecret_key\s*[=:]\s*["\'][^"\']{3,}["\']',
    r'\bbearer\s+["\'][^"\']{5,}["\']',
    r'\baws_access_key\s*[=:]\s*["\'][^"\']{3,}["\']',
    r'\baws_secret\s*[=:]\s*["\'][^"\']{3,}["\']',
]

# Patterns that indicate safe env lookups (not hardcoded)
ENV_LOOKUP_PATTERNS = [
    "os.environ", "os.getenv", "getenv", "process.env",
    "System.getenv", "ENV[", " Bun", "std::env",
]


class HardcodedSecretsRule(UniversalRule):
    """Detect hardcoded passwords, API keys, and tokens in any language.

    Severity: HIGH
    """

    @property
    def rule_id(self) -> str:
        return "UNI-001"

    @property
    def description(self) -> str:
        return "Detect hardcoded passwords, API keys, and tokens"

    def analyze(self, code: str, ln_ast: dict) -> List[dict]:
        findings = []

        for pattern in SECRET_PATTERNS:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                value = match.group()

                # Filter out env lookups
                if any(env in value for env in ENV_LOOKUP_PATTERNS):
                    continue

                # Find line number
                line_num = code[:match.start()].count('\n') + 1

                # Extract the secret name
                secret_match = re.search(r'\b(password|passwd|pwd|secret|api_key|apikey|token|key)\b', value, re.IGNORECASE)
                secret_name = secret_match.group() if secret_match else "secret"

                findings.append({
                    "rule_id": self.rule_id,
                    "start": match.start(),
                    "end": match.end(),
                    "severity": "high",
                    "problem": f"Potential hardcoded {secret_name} on line {line_num}",
                    "fix_hint": f"Replace hardcoded {secret_name} with environment variable lookup",
                    "auto_fix_available": False,
                    "replacement": "",
                })

        return findings
