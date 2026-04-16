# PyNeat - AI Code Cleaner.
#
# Copyright (C) 2026 PyNEAT Authors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# For commercial licensing, contact: khanhnam.copywriting@gmail.com

"""Go security rules - regex-based detection.

Detects the most common and dangerous security vulnerabilities in Go code
without requiring a Go parser.

Supported languages: go

Usage:
    from pyneat.rules.go.security import GoSecurityRule
"""

import re
from typing import List, Set

from pyneat.core.types import (
    CodeFile, TransformationResult,
    SecurityFinding, SecuritySeverity,
)
from pyneat.rules.base import Rule


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _line_no(content: str, byte_offset: int) -> int:
    return content[:byte_offset].count('\n') + 1


def _snippet(lines: List[str], line_no: int, match_text: str, width: int = 80) -> str:
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()[:width]
    return match_text[:width]


# --------------------------------------------------------------------------
# Finding Factory
# --------------------------------------------------------------------------

def _f(
    rule_id: str,
    line_no: int,
    snippet_text: str,
    problem: str,
    severity: SecuritySeverity,
    cwe_id: str,
    cwe_name: str,
    owasp_id: str,
    owasp_name: str,
    cvss_base: float,
    cvss_vector: str,
    fix_constraints: tuple,
    do_not: tuple,
    verify: tuple,
    resources: tuple,
) -> SecurityFinding:
    return SecurityFinding(
        rule_id=rule_id,
        severity=severity,
        confidence=0.85,
        cwe_id=cwe_id,
        owasp_id=owasp_id,
        cvss_score=cvss_base,
        cvss_vector=cvss_vector,
        file="",
        start_line=line_no,
        end_line=line_no,
        snippet=snippet_text,
        problem=problem,
        fix_constraints=fix_constraints,
        do_not=do_not,
        verify=verify,
        resources=resources,
        can_auto_fix=False,
        auto_fix_available=False,
        auto_fix_before=None,
        auto_fix_after=None,
        auto_fix_diff=None,
    )


# --------------------------------------------------------------------------
# Pattern Definitions
# --------------------------------------------------------------------------

# Command Injection (CRITICAL) - exec.Command with string concatenation
_CMD_INJECTION_PATTERNS = [
    (r'exec\.Command\s*\(',
     'exec.Command() call - verify all arguments are sanitized'),
]

# SQL Injection (CRITICAL) - fmt.Sprintf in SQL context
_SQL_INJECTION_PATTERNS = [
    (r'fmt\.Sprintf\s*\(\s*["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\']',
     'fmt.Sprintf building SQL query - SQL injection risk'),
    (r'\.Raw\s*\(\s*["\'][^"\']*["\']\s*\+',
     'db.Raw with string concat - SQL injection risk'),
    (r'\.Query\s*\([^)]+\+\s*[^)]+\)',
     'db.Query with string concat - SQL injection risk'),
    (r'\.Exec\s*\([^)]+\+\s*[^)]+\)',
     'db.Exec with string concat - SQL injection risk'),
]

# Hardcoded Secrets (HIGH)
_SECRET_PATTERNS = [
    (r'["\']sk[-_](?:live|test|prod)[-_][a-zA-Z0-9]{20,}["\']',
     'Hardcoded secret key detected'),
    (r'["\']ghp[a-zA-Z0-9]{36}["\']',
     'Hardcoded GitHub token detected'),
    (r'["\']AKIA[0-9A-Z]{16}["\']',
     'Hardcoded AWS access key detected'),
    (r'password\s*[=:]\s*["\'][^"\']{8,}["\']',
     'Hardcoded password in variable'),
    (r'Password\s*[=:]\s*["\'][^"\']{8,}["\']',
     'Hardcoded Password in struct field'),
    (r'apiKey\s*[=:]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
     'Hardcoded API key detected'),
    (r'api_key\s*[=:]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
     'Hardcoded api_key detected'),
    (r'secret\s*[=:]\s*["\'][a-zA-Z0-9_\-]{8,}["\']',
     'Hardcoded secret detected'),
    (r'token\s*[=:]\s*["\'][a-zA-Z0-9_\-\.]{16,}["\']',
     'Hardcoded token detected'),
    (r'Bearer\s+[a-zA-Z0-9_\-\.]+',
     'Hardcoded Bearer token in string'),
]

# Path Traversal (HIGH)
_PATH_PATTERNS = [
    (r'ioutil\.ReadFile\s*\([^)]*\+',
     'ioutil.ReadFile with concat - path traversal risk'),
    (r'ioutil\.ReadFile\s*\(\s*fmt\.Sprintf',
     'ioutil.ReadFile with Sprintf - path traversal risk'),
    (r'os\.Open\s*\([^)]*\+',
     'os.Open with concatenation - path traversal risk'),
    (r'http\.ServeFile\s*\([^)]*\+',
     'http.ServeFile with concatenation - path traversal risk'),
    (r'os\.Create\s*\([^)]*\+',
     'os.Create with concatenation - path traversal risk'),
    (r'os\.Remove\s*\([^)]*\+',
     'os.Remove with concatenation - path traversal risk'),
]

# Weak Crypto (MEDIUM)
_CRYPTO_PATTERNS = [
    (r'md5\.(?:Sum|New)\s*\(',
     'MD5 is cryptographically broken - use SHA-256+'),
    (r'sha1\.(?:Sum|New)\s*\(',
     'SHA1 is deprecated - use SHA-256+'),
    (r'rand\.Intn\s*\(',
     'rand.Intn is not cryptographically secure - use crypto/rand'),
    (r'crypto\/md5',
     'Import of md5 package - use crypto/sha256'),
    (r'crypto\/sha1',
     'Import of sha1 package - use crypto/sha256'),
    (r'rsa\.GenerateKey\s*\(\s*rand\.Reader\s*,\s*\d{1,3}\d{2}',
     'RSA key size < 2048 bits - use 2048 or 4096'),
    (r'jwt\.WithClaims\s*\([^)]*\.Verify\s*:\s*false',
     'JWT verification disabled - tokens can be forged'),
    (r'SigningMethodNone',
     'JWT none algorithm - tokens signed without signature verification'),
]

# SSRF (HIGH)
_SSRF_PATTERNS = [
    (r'http\.Get\s*\(\s*[^)]+\+\s*[^)]+\)',
     'http.Get with concatenation - SSRF risk'),
    (r'http\.Post\s*\(\s*[^)]+\+\s*[^)]+\)',
     'http.Post with concatenation - SSRF risk'),
    (r'http\.Client\{[^}]*\}\s*\.\s*Get\s*\(',
     'http.Client.Get with user-controlled URL - SSRF risk'),
    (r'http\.DefaultClient\.Get\s*\([^)]+\+\s*',
     'http.DefaultClient.Get with concat - SSRF risk'),
]

# Insecure Cookie / Session (MEDIUM)
_COOKIE_PATTERNS = [
    (r'http\.Cookie\s*\{[^}]*Secure\s*:\s*false[^}]*\}',
     'Cookie with Secure=false - transmitted over HTTP'),
    (r'http\.SetCookie\s*\([^,]+,\s*&http\.Cookie\{[^}]*Secure\s*:\s*false',
     'Cookie set without Secure flag - session hijacking risk'),
    (r'http\.Cookie\s*\{[^}]*HttpOnly\s*:\s*false[^}]*\}',
     'Cookie with HttpOnly=false - XSS can steal cookies'),
]

# Information Disclosure (LOW)
_INFO_PATTERNS = [
    (r'log\.Print(?:ln|f)?\s*\([^)]*(?:password|secret|token|key|credential)',
     'Log contains sensitive keyword - information disclosure'),
    (r'fmt\.Print(?:ln|f)?\s*\([^)]*(?:password|secret|token)',
     'Print contains sensitive keyword - information disclosure'),
    (r'panic\s*\([^)]*(?:password|secret|token)',
     'Panic message contains sensitive data - information disclosure'),
    (r'log\.Fatal(?:ln|f)?\s*\([^)]*(?:password|secret)',
     'Fatal log contains sensitive data'),
]


# --------------------------------------------------------------------------
# Rule Class
# --------------------------------------------------------------------------

class GoSecurityRule(Rule):
    """Detects 8 categories of Go security vulnerabilities.

    Detects:
      - Command Injection (exec.Command with concat) [CRITICAL]
      - SQL Injection (fmt.Sprintf in queries) [CRITICAL]
      - Hardcoded Secrets (API keys, tokens, passwords) [HIGH]
      - Path Traversal (ioutil.ReadFile, os.Open with concat) [HIGH]
      - Weak Crypto (MD5, SHA1, rand.Intn, small RSA) [MEDIUM]
      - SSRF (http.Get/Post with user-controlled URL) [HIGH]
      - Insecure Cookie (missing Secure/HttpOnly flags) [MEDIUM]
      - Information Disclosure (logging sensitive data) [LOW]

    Uses regex-based detection optimized for Go syntax.
    Supports: go.
    """

    ALLOWED_SEMANTIC_NODES: Set[str] = set()

    def __init__(self, config=None):
        super().__init__(config)
        self._findings: List[SecurityFinding] = []

    @property
    def supported_languages(self) -> List[str]:
        return ["go"]

    @property
    def description(self) -> str:
        return (
            "Detects Go security vulnerabilities: command injection, SQL injection, "
            "hardcoded secrets, path traversal, weak crypto, SSRF, insecure cookies, "
            "information disclosure"
        )

    def apply(self, code_file: CodeFile) -> TransformationResult:
        self._findings = []
        content = code_file.content
        lines = content.split('\n')

        self._scan_cmd_injection(content, lines)
        self._scan_sql_injection(content, lines)
        self._scan_secrets(content, lines)
        self._scan_path_traversal(content, lines)
        self._scan_weak_crypto(content, lines)
        self._scan_ssrf(content, lines)
        self._scan_insecure_cookie(content, lines)
        self._scan_info_disclosure(content, lines)

        changes = [
            f"[{f.rule_id}] {f.problem} (line {f.start_line})"
            for f in self._findings
        ]

        return TransformationResult(
            original=code_file,
            transformed_content=content,
            changes_made=changes,
            success=True,
            security_findings=self._findings.copy(),
        )

    def _scan_cmd_injection(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CMD_INJECTION_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "GO-SEC-001", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-78", "OS Command Injection",
                        "A03", "Injection",
                        9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Use exec.Command with separate arguments (no shell)",
                         "Pass user input as arguments, not concatenated strings",
                         "Use shlex.Quote for shell escaping if shell is required"),
                        ("Do NOT use string formatting to build command arguments",
                         "Do NOT use os/exec with shell=True equivalent patterns"),
                        ("Test: '; ls', '$(whoami)', '`id`'",
                         "Audit all exec.Command calls with dynamic arguments"),
                        ("https://owasp.org/www-community/attacks/Command_Injection",
                         "https://cwe.mitre.org/data/definitions/78.html"),
                    ))

    def _scan_sql_injection(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SQL_INJECTION_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "GO-SEC-002", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-89", "SQL Injection",
                        "A03", "Injection",
                        9.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Use parameterized queries: db.Query('SELECT * FROM users WHERE id = $1', id)",
                         "Use GORM's parameterized methods: db.Where('name = ?', name)",
                         "Use an ORM layer that handles escaping automatically"),
                        ("Do NOT use fmt.Sprintf to build SQL queries",
                         "Do NOT concatenate user input into SQL strings"),
                        ("Test: ' OR '1'='1, ' OR 1=1--",
                         "Use sqlmap or Burp Suite for testing",
                         "Review all database calls for parameterization"),
                        ("https://owasp.org/www-community/attacks/SQL_Injection",
                         "https://cwe.mitre.org/data/definitions/89.html",
                         "https://go.dev/doc/database/sql-access"),
                    ))

    def _scan_secrets(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SECRET_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "GO-SEC-003", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-798", "Use of Hard-coded Credentials",
                        "A07", "Identification and Authentication Failures",
                        7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use os.Getenv() to read secrets from environment variables",
                         "Use a secrets manager: AWS Secrets Manager, HashiCorp Vault",
                         "Use viper or standard library flag/env for config"),
                        ("Do NOT commit credentials to version control",
                         "Do NOT hardcode passwords, API keys, or tokens in source code"),
                        ("Run: git log --all -S 'sk-live' -- . (find leaked secrets)",
                         "Use: goroutine/secretScanner, Gitleaks, TruffleHog",
                         "Enable secret scanning in GitHub/GitLab settings"),
                        ("https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                         "https://cwe.mitre.org/data/definitions/798.html"),
                    ))

    def _scan_path_traversal(self, content: str, lines: List[str]) -> None:
        for pat, problem in _PATH_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "GO-SEC-004", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-22", "Path Traversal",
                        "A01", "Broken Access Control",
                        8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use path.Clean() and filepath.Clean() to normalize paths",
                         "Implement whitelist-based path restrictions",
                         "Use filepath.EvalSymlinks() to resolve traversal attempts"),
                        ("Do NOT use string concatenation to build file paths",
                         "Do NOT trust user input for file paths without validation"),
                        ("Test: ../../../etc/passwd, %2e%2e%2f%2e%2e%2fetc%2fpasswd",
                         "Verify file stays within allowed directory after cleaning"),
                        ("https://owasp.org/www-community/attacks/Path_Traversal",
                         "https://cwe.mitre.org/data/definitions/22.html"),
                    ))

    def _scan_weak_crypto(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CRYPTO_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "GO-SEC-005", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.MEDIUM,
                        "CWE-327", "Use of Weak Cryptographic Algorithm",
                        "A02", "Cryptographic Failures",
                        7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use crypto/sha256 or crypto/sha512 for hashing",
                         "Use crypto/rand for random number generation",
                         "Use RSA with 2048+ bit keys minimum"),
                        ("Do NOT use MD5 or SHA1 for security purposes",
                         "Do NOT use math/rand for cryptographic randomness",
                         "Do NOT use RSA keys smaller than 2048 bits"),
                        ("Audit all crypto usage with gocrypto audit",
                         "Replace weak hashes with SHA-256+"),
                        ("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Cryptography/01-Testing_for_Weak_Cryptography",
                         "https://cwe.mitre.org/data/definitions/327.html"),
                    ))

    def _scan_ssrf(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SSRF_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "GO-SEC-006", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-918", "Server-Side Request Forgery",
                        "A10", "Server-Side Request Forgery",
                        8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Validate and whitelist allowed domains/IPs",
                         "Use URL parsing to check for dangerous protocols",
                         "Block access to cloud metadata (169.254.169.254)"),
                        ("Do NOT allow user control of any URL component",
                         "Do NOT rely on URL parsing alone without allowlist"),
                        ("Test: file:///etc/passwd, http://169.254.169.254/",
                         "Use Burp Collaborator for SSRF testing"),
                        ("https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                         "https://cwe.mitre.org/data/definitions/918.html"),
                    ))

    def _scan_insecure_cookie(self, content: str, lines: List[str]) -> None:
        for pat, problem in _COOKIE_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "GO-SEC-007", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.MEDIUM,
                        "CWE-614", "Sensitive Cookie Without HttpOnly Flag",
                        "A05", "Security Misconfiguration",
                        6.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Always set Secure: true for session cookies",
                         "Always set HttpOnly: true to prevent XSS cookie theft",
                         "Set SameSite=Lax or SameSite=Strict"),
                        ("Do NOT set Secure: false in production",
                         "Do NOT set HttpOnly: false for session cookies"),
                        ("Test cookie headers in browser devtools",
                         "Verify Secure flag is set when testing over HTTPS"),
                        ("https://cwe.mitre.org/data/definitions/614.html",
                         "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"),
                    ))

    def _scan_info_disclosure(self, content: str, lines: List[str]) -> None:
        for pat, problem in _INFO_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "GO-SEC-008", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.LOW,
                        "CWE-532", "Information Exposure Through Log",
                        "A09", "Security Logging and Monitoring Failures",
                        3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        ("Use structured logging with redaction",
                         "Redact sensitive fields before logging",
                         "Use log levels (Debug, Info, Warn, Error) controlled by env"),
                        ("Do NOT log passwords, tokens, or API keys",
                         "Do NOT log full request/response objects in production"),
                        ("Search codebase: grep -r 'log.*password\\|log.*secret'",
                         "Review all log.Print* calls before production"),
                        ("https://cwe.mitre.org/data/definitions/532.html"),
                    ))

    def _is_real_code(self, lines: List[str], line_no: int) -> bool:
        idx = line_no - 1
        if idx < 0 or idx >= len(lines):
            return False
        stripped = lines[idx].strip()
        if stripped.startswith('//'):
            return False
        if stripped.startswith('/*') or stripped.startswith('*'):
            return False
        if stripped.startswith('/**'):
            return False
        return True
