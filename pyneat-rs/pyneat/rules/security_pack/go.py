"""Go-specific security rules (GO-SEC-001 to GO-SEC-048).

Copyright (c) 2026 PyNEAT Authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, contact: khanhnam.copywriting@gmail.com

This module contains Go-specific security rules that complement the
language-agnostic security_pack rules. Includes gosec-complementary rules
covering G101-G601 patterns.
"""

from pyneat.core.types import SecuritySeverity

__all__ = ["GO_SECURITY_RULES", "get_go_rules_by_severity"]


# Go Critical Security Rules
GO_CRITICAL_RULES = [
    {
        "rule_id": "GO-SEC-002",
        "name": "Command Injection",
        "severity": SecuritySeverity.CRITICAL,
        "description": "os/exec with user-controlled command — command injection vulnerability",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "GO-SEC-003",
        "name": "SQL Injection",
        "severity": SecuritySeverity.CRITICAL,
        "description": "database/sql with string concatenation or fmt.Sprintf in queries",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "GO-SEC-034",
        "name": "Insecure Deserialization",
        "severity": SecuritySeverity.CRITICAL,
        "description": "gob decoder, go-toml, or ugorji/go codec with untrusted input",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
    },
    {
        "rule_id": "GO-SEC-038",
        "name": "G106: exec.Command without context",
        "severity": SecuritySeverity.CRITICAL,
        "description": "exec.Command without context — subprocess cannot be cancelled or timed out",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "GO-SEC-039",
        "name": "G204: Subprocess with user-controlled execution",
        "severity": SecuritySeverity.CRITICAL,
        "description": "exec.Command with shell invocation — user input can enable command injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
]


# Go High Security Rules
GO_HIGH_RULES = [
    {
        "rule_id": "GO-SEC-001",
        "name": "Hardcoded Secrets",
        "severity": SecuritySeverity.HIGH,
        "description": "Hardcoded passwords, API keys, tokens, or AWS credentials in Go source",
        "cwe": "CWE-798",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "GO-SEC-004",
        "name": "Path Traversal",
        "severity": SecuritySeverity.HIGH,
        "description": "File operations with user-controlled paths — ../ or absolute path bypass",
        "cwe": "CWE-22",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "GO-SEC-005",
        "name": "YAML Unsafe Load",
        "severity": SecuritySeverity.HIGH,
        "description": "yaml.Unmarshal with untrusted data — YAML deserialization RCE risk",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
    },
    {
        "rule_id": "GO-SEC-006",
        "name": "Insecure TLS Configuration",
        "severity": SecuritySeverity.HIGH,
        "description": "TLS config with InsecureSkipVerify, MinVersion < TLS 1.2, or weak ciphers",
        "cwe": "CWE-295",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "GO-SEC-008",
        "name": "SSRF",
        "severity": SecuritySeverity.HIGH,
        "description": "HTTP requests to user-controlled URLs or internal IPs (169.254.169.254)",
        "cwe": "CWE-918",
        "owasp": "A10:2021",
    },
    {
        "rule_id": "GO-SEC-011",
        "name": "Weak Cryptography",
        "severity": SecuritySeverity.HIGH,
        "description": "MD5, SHA1, DES, RC4 usage for security purposes",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "GO-SEC-040",
        "name": "G302: World-writable file",
        "severity": SecuritySeverity.HIGH,
        "description": "File created with world-readable or group-writable permissions (0o777, 0o666)",
        "cwe": "CWE-276",
        "owasp": "A05:2021",
    },
    {
        "rule_id": "GO-SEC-041",
        "name": "G304: Path traversal via user input",
        "severity": SecuritySeverity.HIGH,
        "description": "filepath.Join/ioutil.ReadFile with user-controlled path component",
        "cwe": "CWE-22",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "GO-SEC-042",
        "name": "G305: filepath.Join path traversal",
        "severity": SecuritySeverity.HIGH,
        "description": "filepath.Join with path traversal sequences (../) — incomplete sanitization",
        "cwe": "CWE-22",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "GO-SEC-044",
        "name": "G501: Blacklisted import crypto/md5",
        "severity": SecuritySeverity.HIGH,
        "description": "Import of crypto/md5 — MD5 is broken for cryptographic purposes",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "GO-SEC-045",
        "name": "G502: Blacklisted import crypto/des",
        "severity": SecuritySeverity.HIGH,
        "description": "Import of crypto/des — DES uses 56-bit key, easily brute-forced",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "GO-SEC-046",
        "name": "G503: Blacklisted import crypto/rc4",
        "severity": SecuritySeverity.HIGH,
        "description": "Import of crypto/rc4 — RC4 has severe cryptographic weaknesses",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
    },
]


# Go Medium Security Rules
GO_MEDIUM_RULES = [
    {
        "rule_id": "GO-SEC-007",
        "name": "Eval Pattern",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Dangerous use of fmt.Sprint with dynamically constructed code",
        "cwe": "CWE-95",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "GO-SEC-009",
        "name": "Verbose Error Messages",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Error messages exposing stack traces, internal paths, or sensitive data",
        "cwe": "CWE-209",
        "owasp": "A05:2021",
    },
    {
        "rule_id": "GO-SEC-010",
        "name": "Missing Input Validation",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Function parameters not validated for type, range, or format",
        "cwe": "CWE-20",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "GO-SEC-012",
        "name": "Race Condition",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Shared map access without synchronization — data race vulnerability",
        "cwe": "CWE-362",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "GO-SEC-013",
        "name": "Missing Context Deadline",
        "severity": SecuritySeverity.MEDIUM,
        "description": "HTTP requests or DB operations without context timeout",
        "cwe": "CWE-400",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "GO-SEC-014",
        "name": "Regex DoS",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Catastrophic backtracking in regex — ReDoS vulnerability",
        "cwe": "CWE-1333",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "GO-SEC-015",
        "name": "Integer Overflow",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Arithmetic on int/uint without overflow checking",
        "cwe": "CWE-190",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "GO-SEC-043",
        "name": "G307: Deferred Close returning error is ignored",
        "severity": SecuritySeverity.MEDIUM,
        "description": "defer resp.Body.Close() — error return value is discarded",
        "cwe": "CWE-754",
        "owasp": "A05:2021",
    },
    {
        "rule_id": "GO-SEC-047",
        "name": "G504: CGI with query parameters",
        "severity": SecuritySeverity.MEDIUM,
        "description": "net/http/cgi passes query params as command-line args — command injection risk",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
    },
]


# Go Low/Info Security Rules
GO_LOW_RULES = [
    {
        "rule_id": "GO-SEC-048",
        "name": "G601: Reflect model exposure",
        "severity": SecuritySeverity.LOW,
        "description": "reflect.ValueOf on model struct can expose unexported fields via JSON serialization",
        "cwe": "CWE-915",
        "owasp": "A05:2021",
    },
    {
        "rule_id": "GO-SEC-016",
        "name": "Unsafe Reflection",
        "severity": SecuritySeverity.LOW,
        "description": "reflect.DeepEqual or reflect.TypeOf on untrusted type assertions",
        "cwe": "CWE-470",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "GO-SEC-017",
        "name": "Insecure Random",
        "severity": SecuritySeverity.LOW,
        "description": "math/rand used for security-sensitive randomness",
        "cwe": "CWE-338",
        "owasp": "A02:2021",
    },
]


# Combined Go rules for convenience
GO_SECURITY_RULES = (
    GO_CRITICAL_RULES
    + GO_HIGH_RULES
    + GO_MEDIUM_RULES
    + GO_LOW_RULES
)


def get_go_rules_by_severity(severity: str) -> list:
    """Return Go security rules for a specific severity level."""
    mapping = {
        SecuritySeverity.CRITICAL: GO_CRITICAL_RULES,
        SecuritySeverity.HIGH: GO_HIGH_RULES,
        SecuritySeverity.MEDIUM: GO_MEDIUM_RULES,
        SecuritySeverity.LOW: GO_LOW_RULES,
    }
    return mapping.get(severity, [])
