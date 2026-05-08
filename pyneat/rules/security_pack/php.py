"""PHP-specific security rules (PHP-SEC-001 to PHP-SEC-038).

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

This module contains PHP-specific security rules that complement the
language-agnostic security_pack rules.
"""

from pyneat.core.types import SecuritySeverity

__all__ = ["PHP_SECURITY_RULES", "get_php_rules_by_severity"]


# PHP Critical Security Rules
PHP_CRITICAL_RULES = [
    {
        "rule_id": "PHP2-SEC-001",
        "name": "SQL Injection",
        "severity": SecuritySeverity.CRITICAL,
        "description": "SQL Injection via mysqli_query, mysql_query, pg_query with user input",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "PHP2-SEC-003",
        "name": "Command Injection",
        "severity": SecuritySeverity.CRITICAL,
        "description": "Command injection via exec, system, shell_exec, passthru with user input",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "PHP2-SEC-007",
        "name": "Dangerous Eval Usage",
        "severity": SecuritySeverity.HIGH,
        "description": "eval(), assert(), create_function(), preg_replace() with code execution",
        "cwe": "CWE-95",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "PHP2-SEC-032",
        "name": "Weak JWT Verification",
        "severity": SecuritySeverity.CRITICAL,
        "description": "JWT::decode with null/empty key - no signature verification",
        "cwe": "CWE-345",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "PHP2-SEC-036",
        "name": "SQL Injection via PDO String Interpolation",
        "severity": SecuritySeverity.CRITICAL,
        "description": "$pdo->query() and $pdo->exec() with string interpolation",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "PHP2-SEC-037",
        "name": "PHP Object Injection (Unserialize)",
        "severity": SecuritySeverity.CRITICAL,
        "description": "unserialize() with user input - can trigger RCE via magic methods",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
    },
    {
        "rule_id": "PHP2-SEC-038",
        "name": "Remote File Inclusion (RFI)",
        "severity": SecuritySeverity.CRITICAL,
        "description": "include, require, fopen with user-controlled URLs",
        "cwe": "CWE-98",
        "owasp": "A03:2021",
    },
]


# PHP High Security Rules
PHP_HIGH_RULES = [
    {
        "rule_id": "PHP2-SEC-004",
        "name": "Path Traversal / LFI",
        "severity": SecuritySeverity.HIGH,
        "description": "include, file_get_contents with user input and path traversal sequences",
        "cwe": "CWE-22",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "PHP2-SEC-005",
        "name": "Weak Password Hashing",
        "severity": SecuritySeverity.MEDIUM,
        "description": "md5(), sha1(), crypt() for password hashing - insecure algorithms",
        "cwe": "CWE-328",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "PHP2-SEC-006",
        "name": "Hardcoded Secrets",
        "severity": SecuritySeverity.HIGH,
        "description": "Hardcoded passwords, API keys, tokens, AWS credentials in code",
        "cwe": "CWE-798",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "PHP2-SEC-009",
        "name": "Unvalidated Redirect",
        "severity": SecuritySeverity.MEDIUM,
        "description": "header() with user-controlled Location - open redirect vulnerability",
        "cwe": "CWE-601",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "PHP2-SEC-012",
        "name": "Insecure CORS Configuration",
        "severity": SecuritySeverity.MEDIUM,
        "description": "CORS allowing all origins (* wildcard) or credentials with wildcard",
        "cwe": "CWE-942",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "PHP2-SEC-013",
        "name": "Information Disclosure",
        "severity": SecuritySeverity.LOW,
        "description": "phpinfo(), var_dump() exposure, stack traces in production",
        "cwe": "CWE-200",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "PHP2-SEC-019",
        "name": "Insecure File Upload",
        "severity": SecuritySeverity.HIGH,
        "description": "File upload without proper validation - arbitrary file upload vulnerability",
        "cwe": "CWE-434",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "PHP2-SEC-028",
        "name": "Loose Comparison",
        "severity": SecuritySeverity.MEDIUM,
        "description": "== instead of === in authentication - type juggling vulnerability",
        "cwe": "CWE-697",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "PHP2-SEC-029",
        "name": "Missing CSRF Protection",
        "severity": SecuritySeverity.MEDIUM,
        "description": "State-changing operations without CSRF token validation",
        "cwe": "CWE-352",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "PHP2-SEC-031",
        "name": "SSRF (Server-Side Request Forgery)",
        "severity": SecuritySeverity.HIGH,
        "description": "HTTP requests with user-controlled URLs - internal service access",
        "cwe": "CWE-918",
        "owasp": "A10:2021",
    },
    {
        "rule_id": "PHP2-SEC-033",
        "name": "Laravel SQL Injection",
        "severity": SecuritySeverity.CRITICAL,
        "description": "Laravel raw queries with user input - ORM bypass via whereRaw",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "PHP2-SEC-034",
        "name": "Server-Side Template Injection (SSTI)",
        "severity": SecuritySeverity.CRITICAL,
        "description": "Template rendering with user input - Twig, Blade injection",
        "cwe": "CWE-1336",
        "owasp": "A03:2021",
    },
]


# PHP Medium Security Rules
PHP_MEDIUM_RULES = [
    {
        "rule_id": "PHP2-SEC-002",
        "name": "Cross-Site Scripting (XSS)",
        "severity": SecuritySeverity.MEDIUM,
        "description": "echo, print with user input without htmlspecialchars sanitization",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "PHP2-SEC-008",
        "name": "Session Fixation",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Session without regeneration - attacker can fixate session ID",
        "cwe": "CWE-384",
        "owasp": "A05:2021",
    },
    {
        "rule_id": "PHP2-SEC-010",
        "name": "Weak Random Number Generation",
        "severity": SecuritySeverity.MEDIUM,
        "description": "mt_rand(), rand() for security-sensitive randomness",
        "cwe": "CWE-338",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "PHP2-SEC-011",
        "name": "Missing HTTPS/SSL",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Sensitive operations over HTTP without SSL/TLS encryption",
        "cwe": "CWE-319",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "PHP2-SEC-014",
        "name": "XXE (XML External Entity)",
        "severity": SecuritySeverity.HIGH,
        "description": "XML parsing with DTD processing enabled - XXE injection",
        "cwe": "CWE-611",
        "owasp": "A05:2021",
    },
    {
        "rule_id": "PHP2-SEC-015",
        "name": "LDAP Injection",
        "severity": SecuritySeverity.HIGH,
        "description": "LDAP queries with user-controlled filter parameters",
        "cwe": "CWE-90",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "PHP2-SEC-016",
        "name": "Mass Assignment",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Direct assignment of user input to model properties",
        "cwe": "CWE-915",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "PHP2-SEC-020",
        "name": "Verbose Error Handling",
        "severity": SecuritySeverity.LOW,
        "description": "Production errors showing stack traces and file paths",
        "cwe": "CWE-11",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "PHP2-SEC-021",
        "name": "Missing Input Validation",
        "severity": SecuritySeverity.MEDIUM,
        "description": "User input used without validation or sanitization",
        "cwe": "CWE-20",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "PHP2-SEC-022",
        "name": "SameSite Cookie Missing",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Cookies without SameSite attribute - CSRF vulnerability",
        "cwe": "CWE-16",
        "owasp": "A05:2021",
    },
    {
        "rule_id": "PHP2-SEC-023",
        "name": "PHAR Deserialization",
        "severity": SecuritySeverity.HIGH,
        "description": "File operations that auto-deserialize PHAR archives - RCE vector",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
    },
    {
        "rule_id": "PHP2-SEC-024",
        "name": "Type Juggling",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Loose comparison (==) exploitation via type juggling",
        "cwe": "CWE-190",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "PHP2-SEC-025",
        "name": "Dependency Vulnerability",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Known vulnerable dependencies in composer.json",
        "cwe": "CWE-1104",
        "owasp": "A06:2021",
    },
    {
        "rule_id": "PHP2-SEC-030",
        "name": "Weak Password Hash Cost",
        "severity": SecuritySeverity.MEDIUM,
        "description": "password_hash with insufficient cost factor - fast hashing",
        "cwe": "CWE-916",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "PHP2-SEC-035",
        "name": "extract() Overwrite",
        "severity": SecuritySeverity.MEDIUM,
        "description": "extract() on user input - variable overwrite vulnerability",
        "cwe": "CWE-471",
        "owasp": "A04:2021",
    },
]


# PHP Low/Info Security Rules
PHP_LOW_RULES = [
    {
        "rule_id": "PHP2-SEC-017",
        "name": "Open Redirect",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Redirect to user-controlled URL without validation",
        "cwe": "CWE-601",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "PHP2-SEC-018",
        "name": "Weak Cryptography",
        "severity": SecuritySeverity.HIGH,
        "description": "DES, RC4, MD5 for encryption - deprecated algorithms",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
    },
]


# Combined PHP rules for convenience
PHP_SECURITY_RULES = (
    PHP_CRITICAL_RULES
    + PHP_HIGH_RULES
    + PHP_MEDIUM_RULES
    + PHP_LOW_RULES
)


def get_php_rules_by_severity(severity: str) -> list:
    """Return PHP security rules for a specific severity level."""
    mapping = {
        SecuritySeverity.CRITICAL: PHP_CRITICAL_RULES,
        SecuritySeverity.HIGH: PHP_HIGH_RULES,
        SecuritySeverity.MEDIUM: PHP_MEDIUM_RULES,
        SecuritySeverity.LOW: PHP_LOW_RULES,
    }
    return mapping.get(severity, [])
