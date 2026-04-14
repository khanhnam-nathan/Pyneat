"""PyNeat - AI Code Cleaner.

Copyright (C) 2026 PyNEAT Authors

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

"""PHP security rules - regex-based detection.

Detects the most common and dangerous security vulnerabilities in PHP code
without requiring a PHP parser.

Supported languages: php

Usage:
    from pyneat.rules.php.security import PHPSecurityRule
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
# Pattern Definitions - PHP specific
# PHP uses . (dot) for string concatenation, NOT + (plus)
# --------------------------------------------------------------------------

# SQL Injection (CRITICAL)
_SQL_PATTERNS = [
    (r'->query\s*\([^,)]*\.\s*\)', 'PDO/statement query with concat - SQL injection risk'),
    (r'(?:mysqli_query|pg_query|sqlite_query)\s*\([^,)]*\.\s*\)', 'db query with concat - SQL injection risk'),
    (r'SELECT.+\.\s*\$', 'SQL keyword with PHP dot concat - SQL injection risk'),
]

# Unsafe Deserialization (CRITICAL)
_UNSERIALIZE_PATTERNS = [
    (r'\bunserialize\s*\(\s*\$', 'unserialize() with variable - object injection RCE risk'),
    (r'__wakeup\s*\(\s*\)', '__wakeup magic method - potential deserialization gadget'),
    (r'__destruct\s*\(\s*\)', '__destruct magic method - potential deserialization gadget'),
]

# Command Injection (CRITICAL)
_CMD_PATTERNS = [
    (r'\bsystem\s*\(', 'system() call - verify all arguments are sanitized'),
    (r'\bexec\s*\(', 'exec() call - verify all arguments are sanitized'),
    (r'\bshell_exec\s*\(', 'shell_exec() call - verify all arguments are sanitized'),
    (r'\bpopen\s*\(', 'popen() call - verify arguments are sanitized'),
    (r'\bproc_open\s*\(', 'proc_open() call - verify arguments are sanitized'),
    (r'\bpassthru\s*\(', 'passthru() call - verify arguments are sanitized'),
]

# XSS (HIGH)
_XSS_PATTERNS = [
    (r'\becho\s+\$_(?:GET|POST|REQUEST|COOKIE)', 'echo with user input - reflected XSS risk'),
    (r'\bprint\s+\$_(?:GET|POST|REQUEST|COOKIE)', 'print with user input - reflected XSS risk'),
    (r'\bheader\s*\([^)]*\.\s*\$', 'header() with concat - CRLF injection risk'),
]

# Path Traversal / File Inclusion (HIGH)
_PATH_PATTERNS = [
    # include/require with variable
    (r'(?:include|require)\s*\(\s*\$', 'include/require with variable - LFI/RFI risk'),
    # include/require with concat
    (r'(?:include|require)\s*\([^)]*\.\s*\)', 'include/require with concat - path traversal risk'),
    # file operations with concat
    (r'file_get_contents\s*\([^)]*(?:\\.|\.)[^)]*\)', 'file_get_contents with dynamic path - path traversal risk'),
    (r'file_put_contents\s*\([^)]*\.\s*\)', 'file_put_contents with concat - arbitrary write risk'),
]

# Hardcoded Secrets (HIGH)
_SECRET_PATTERNS = [
    (r'["\047]sk[-_](?:live|test|prod)[-_][a-zA-Z0-9]{20,}["\047]', 'Hardcoded secret key detected'),
    (r'["\047]AKIA[0-9A-Z]{16}["\047]', 'Hardcoded AWS access key detected'),
    (r'["\047]ghp[a-zA-Z0-9]{36}["\047]', 'Hardcoded GitHub token detected'),
    (r'define\s*\(\s*["\047](?:PASSWORD|SECRET|API_KEY|TOKEN)["\047]', 'define() with sensitive constant name'),
    (r'["\047]mysql://[^:]+:[^@]+@', 'Connection string with embedded password detected'),
]

# Weak Crypto (MEDIUM)
_CRYPTO_PATTERNS = [
    (r'\bmd5\s*\(\s*\$', 'md5() with variable - use password_hash() for passwords'),
    (r'\bsha1\s*\(\s*\$', 'sha1() is deprecated for security purposes'),
]


# --------------------------------------------------------------------------
# Rule Class
# --------------------------------------------------------------------------

class PHPSecurityRule(Rule):
    """Detects 8 categories of PHP security vulnerabilities.

    Detects:
      - Code Injection (eval, create_function, preg_replace /e) [CRITICAL]
      - SQL Injection (mysqli_query, PDO::query with concat) [CRITICAL]
      - Unsafe Deserialization (unserialize with user input) [CRITICAL]
      - Command Injection (system, exec, shell_exec with user input) [CRITICAL]
      - XSS (echo, print with user input, header injection) [HIGH]
      - Path Traversal / LFI (include, file_get_contents with user input) [HIGH]
      - Hardcoded Secrets (API keys, tokens, passwords) [HIGH]
      - Weak Crypto (md5, sha1 for passwords) [MEDIUM]

    Supports: php.
    """

    ALLOWED_SEMANTIC_NODES: Set[str] = set()

    def __init__(self, config=None):
        super().__init__(config)
        self._findings: List[SecurityFinding] = []

    @property
    def supported_languages(self) -> List[str]:
        return ["php"]

    @property
    def description(self) -> str:
        return (
            "Detects PHP security vulnerabilities: code injection, SQL injection, "
            "unsafe deserialization, command injection, XSS, path traversal, "
            "hardcoded secrets, weak crypto"
        )

    def apply(self, code_file: CodeFile) -> TransformationResult:
        self._findings = []
        content = code_file.content
        lines = content.split('\n')

        self._scan_code_injection(content, lines)
        self._scan_sql_injection(content, lines)
        self._scan_unserialize(content, lines)
        self._scan_cmd_injection(content, lines)
        self._scan_xss(content, lines)
        self._scan_path_traversal(content, lines)
        self._scan_secrets(content, lines)
        self._scan_weak_crypto(content, lines)

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

    def _scan_code_injection(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CODE_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "PHP-SEC-001", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-94", "Code Injection",
                        "A03", "Injection",
                        9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Avoid eval(), create_function(), and dynamic code execution",
                         "Use switch statements or function maps instead of eval()",
                         "Sanitize and validate all user input"),
                        ("Do NOT use eval() with any user-controlled data",
                         "Do NOT use preg_replace /e modifier",
                         "Do NOT use assert() with user input in PHP 7+"),
                        ("Test with: ${phpinfo()}, ${system('ls')}",
                         "Use PHP CodeSniffer to ban eval()",
                         "Set disable_functions in php.ini"),
                        ("https://owasp.org/www-community/attacks/Code_Injection",
                         "https://cwe.mitre.org/data/definitions/94.html"),
                    ))

    def _scan_sql_injection(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SQL_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "PHP-SEC-002", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-89", "SQL Injection",
                        "A03", "Injection",
                        9.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Use prepared statements with mysqli_prepare() or PDO::prepare()",
                         "Use an ORM: Eloquent, Doctrine, Propel",
                         "Escape input with mysqli_real_escape_string() only as last resort"),
                        ("Do NOT concatenate user input into SQL queries",
                         "Do NOT use mysqli_query() with string interpolation"),
                        ("Test: ' OR '1'='1, ' OR 1=1--",
                         "Use SQLmap for automated testing"),
                        ("https://owasp.org/www-community/attacks/SQL_Injection",
                         "https://cwe.mitre.org/data/definitions/89.html"),
                    ))

    def _scan_unserialize(self, content: str, lines: List[str]) -> None:
        for pat, problem in _UNSERIALIZE_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "PHP-SEC-003", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-502", "Deserialization of Untrusted Data",
                        "A08", "Software and Data Integrity Failures",
                        9.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Use json_decode() instead of unserialize() for data exchange",
                         "Use signed cookies with hmac_verify()",
                         "Enable php.ini: session.cookie_httponly=1, session.use_strict_mode=1"),
                        ("Do NOT use unserialize() on data from untrusted sources",
                         "Do NOT use __wakeup/__destruct without review"),
                        ("Test with PHP Object Injection payloads (POP chain)",
                         "Use PHPStan with phpstan/phpstan-phpunit"),
                        ("https://cwe.mitre.org/data/definitions/502.html",
                         "https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection"),
                    ))

    def _scan_cmd_injection(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CMD_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "PHP-SEC-004", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-78", "OS Command Injection",
                        "A03", "Injection",
                        9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Avoid shell execution functions: system(), exec(), shell_exec()",
                         "Use PHP built-in functions: glob(), opendir(), readdir() for file operations",
                         "Use escapeshellarg() and escapeshellcmd() if shell is unavoidable"),
                        ("Do NOT pass user input to any shell execution function",
                         "Do NOT use backticks `` operator with user input"),
                        ("Test: ; ls, $(whoami), `id`",
                         "Audit all shell execution calls"),
                        ("https://owasp.org/www-community/attacks/Command_Injection",
                         "https://cwe.mitre.org/data/definitions/78.html"),
                    ))

    def _scan_xss(self, content: str, lines: List[str]) -> None:
        for pat, problem in _XSS_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "PHP-SEC-005", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-79", "Cross-site Scripting (XSS)",
                        "A03", "Injection",
                        8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                        ("Use htmlspecialchars() or htmlentities() to escape output",
                         "Use a template engine: Twig (auto-escapes by default)",
                         "Set CSP header: Content-Security-Policy: default-src 'self'"),
                        ("Do NOT echo or print user input without escaping",
                         "Do NOT use $_GET/$_POST directly in HTML output"),
                        ("Test: <script>alert(1)</script>, <img src=x onerror=alert(1)>",
                         "Use OWASP ZAP or Burp Suite for XSS scanning"),
                        ("https://owasp.org/www-community/attacks/xss/",
                         "https://cwe.mitre.org/data/definitions/79.html"),
                    ))

    def _scan_path_traversal(self, content: str, lines: List[str]) -> None:
        for pat, problem in _PATH_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "PHP-SEC-006", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-22", "Path Traversal",
                        "A01", "Broken Access Control",
                        8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use allowlist for include/require - map inputs to file list",
                         "Use basename() and realpath() to sanitize file paths",
                         "Store uploaded files outside webroot with random names"),
                        ("Do NOT use user input directly in include/require paths",
                         "Do NOT trust file extensions for security"),
                        ("Test: ?page=../../../../etc/passwd",
                         "Verify included files stay within allowed directory"),
                        ("https://owasp.org/www-community/attacks/Path_Traversal",
                         "https://cwe.mitre.org/data/definitions/22.html"),
                    ))

    def _scan_secrets(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SECRET_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "PHP-SEC-007", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-798", "Use of Hard-coded Credentials",
                        "A07", "Identification and Authentication Failures",
                        7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use environment variables: getenv('API_KEY')",
                         "Use PHP-DI or dotenv for configuration management",
                         "Use secrets managers for production: AWS SM, HashiCorp Vault"),
                        ("Do NOT commit credentials to version control",
                         "Do NOT hardcode passwords or API keys in source"),
                        ("Run: git log -S 'password=' -- . (find leaks)",
                         "Use: PHP secrets detection, Gitleaks"),
                        ("https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                         "https://cwe.mitre.org/data/definitions/798.html"),
                    ))

    def _scan_weak_crypto(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CRYPTO_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "PHP-SEC-008", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.MEDIUM,
                        "CWE-327", "Use of Weak Cryptographic Algorithm",
                        "A02", "Cryptographic Failures",
                        7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use password_hash() and password_verify() for passwords",
                         "Use hash_equals() for timing-safe comparison",
                         "Use random_bytes() for cryptographic random"),
                        ("Do NOT use md5() or sha1() for password hashing",
                         "Do NOT use crypt() without proper salt"),
                        ("Use PHP Security Library: defuse/php-encryption",
                         "Check: password_get_info() on hashes"),
                        ("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Cryptography/01-Testing_for_Weak_Cryptography",
                         "https://cwe.mitre.org/data/definitions/327.html"),
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
        return True


# Additional patterns referenced in _scan_code_injection
_CODE_PATTERNS = [
    (r'\beval\s*\(\s*\$', 'eval() with variable - code injection risk'),
    (r'\bcreate_function\s*\(', 'create_function() is equivalent to eval - code injection risk'),
    (r'\bassert\s*\(\s*\$', 'assert() with variable - code injection risk (PHP 7 deprecation)'),
    (r'\bcall_user_func\s*\(\s*\$', 'call_user_func() with variable - code injection risk'),
    (r'\bcall_user_func_array\s*\(\s*\$', 'call_user_func_array() with variable - code injection risk'),
    (r'\bpreg_replace\s*\([\s\S]*?\/e', 'preg_replace with /e modifier - code injection risk'),
    (r'\bmb_ereg_replace\s*\([^)]*e[^)]*\$', 'mb_ereg_replace with e flag - code injection risk'),
]
