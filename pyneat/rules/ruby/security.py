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

"""Ruby security rules - regex-based detection.

Detects the most common and dangerous security vulnerabilities in Ruby code
without requiring a Ruby parser.

Supported languages: ruby

Usage:
    from pyneat.rules.ruby.security import RubySecurityRule
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
# Pattern Definitions - Ruby specific
# Ruby uses #{...} for interpolation, backticks for shell, + for concat
# --------------------------------------------------------------------------

# SQL Injection (CRITICAL)
_SQL_PATTERNS = [
    # Ruby uses " for strings, not '
    # .where("...#{...}...") - double quotes contain interpolation
    (r'\.where\s*\([^)]*"[^"]*#\{', 'ActiveRecord .where with interpolation - SQL injection risk'),
    (r'\.order\s*\([^)]*"[^"]*#\{', 'ActiveRecord .order with interpolation - SQL injection risk'),
    (r'\.joins\s*\([^)]*"[^"]*#\{', 'ActiveRecord .joins with interpolation - SQL injection risk'),
    (r'find_by_sql\s*\([^)]*"[^"]*#\{', 'find_by_sql with interpolation - SQL injection risk'),
    (r'connection\.(?:execute|exec|update)\s*\([^)]*"[^"]*#\{', 'db execute with interpolation - SQL injection risk'),
]

# Code Injection (CRITICAL)
_CODE_PATTERNS = [
    (r'\beval\s*\(', 'eval() call - code injection risk (verify input is trusted)'),
    (r'\beval\s*\([^)]*#\{', 'eval() with interpolation - code injection risk'),
    (r'\bsend\s*\([^)]*#\{', 'send() with dynamic method from user input - code injection risk'),
    (r'\bpublic_send\s*\([^)]*#\{', 'public_send with dynamic method - code injection risk'),
    (r'\binstance_eval\s*\(', 'instance_eval() - code injection risk'),
    (r'\bclass_eval\s*\(', 'class_eval() - code injection risk'),
]

# Command Injection (CRITICAL)
_CMD_PATTERNS = [
    (r'`[^`]*#\{', 'Backtick command with interpolation - command injection risk'),
    (r'\b(?:system|exec|spawn)\s*\([^)]*#\{', 'Shell method with interpolation - command injection risk'),
    (r'%x\[', '%x[] backtick syntax - command injection risk'),
]

# Path Traversal / File Access (HIGH)
_PATH_PATTERNS = [
    (r'File\.(?:read|write|open|readlines)\s*\([^)]*\+', 'File operation with concatenation - path traversal risk'),
    (r'FileUtils\.(?:cp|mv|rm|chmod)\s*\([^)]*\+', 'FileUtils operation with concatenation - path traversal risk'),
    (r'\bread_file\s*\([^)]*\+', 'read_file with concatenation - path traversal risk'),
]

# Hardcoded Secrets (HIGH)
_SECRET_PATTERNS = [
    (r'["\047]sk[-_](?:live|test|prod)[-_][a-zA-Z0-9]{20,}["\047]', 'Hardcoded secret key detected'),
    (r'["\047]AKIA[0-9A-Z]{16}["\047]', 'Hardcoded AWS access key detected'),
    (r'["\047]ghp[a-zA-Z0-9]{36}["\047]', 'Hardcoded GitHub token detected'),
    (r'password\s*[=:]\s*["\047][^"\047]{8,}["\047]', 'Hardcoded password detected'),
    (r'secret\s*[=:]\s*["\047][a-zA-Z0-9_\-]{8,}["\047]', 'Hardcoded secret detected'),
]

# Weak Crypto (MEDIUM)
_CRYPTO_PATTERNS = [
    (r'Digest::MD5\b', 'MD5 is cryptographically broken - use SHA-256+'),
    (r'Digest::SHA1\b', 'SHA1 is deprecated - use SHA-256+'),
    (r'OpenSSL::Cipher\.new\s*\([^)]*["\x27\x22]des[-_]?ecb["\x27\x22]', 'DES cipher detected - use AES-256'),
    (r'OpenSSL::Cipher\.new\s*\([^)]*["\047]rc4["\047]', 'RC4 encryption - use AES-256'),
    (r'["\047](?:des[-_]?ecb|rc4)["\047]', 'Weak cipher mode detected - use AES-256'),
]

# XSS (HIGH)
_XSS_PATTERNS = [
    (r'\braw\s*\([^)]*#\{', 'raw() with interpolation - XSS risk'),
    (r'\.html_safe\b', '.html_safe disables escaping - XSS risk'),
    (r'render\s+(?:text|inline|plain)\s*,\s*(?:text|content):\s*params', 'render with user content - verify XSS protection'),
]


# --------------------------------------------------------------------------
# Rule Class
# --------------------------------------------------------------------------

class RubySecurityRule(Rule):
    """Detects 7 categories of Ruby security vulnerabilities.

    Detects:
      - SQL Injection (find_by_sql, .where, .order with interpolation) [CRITICAL]
      - Code Injection (eval, send, instance_eval, class_eval) [CRITICAL]
      - Command Injection (backticks, system(), exec(), spawn(), %x[]) [CRITICAL]
      - Path Traversal (File.read/open, FileUtils with concat) [HIGH]
      - Hardcoded Secrets (API keys, tokens, passwords) [HIGH]
      - Weak Crypto (MD5, SHA1, DES, RC4, ECB mode) [MEDIUM]
      - XSS (raw(), .html_safe, render with user content) [HIGH]

    Supports: ruby.
    """

    ALLOWED_SEMANTIC_NODES: Set[str] = set()

    def __init__(self, config=None):
        super().__init__(config)
        self._findings: List[SecurityFinding] = []

    @property
    def supported_languages(self) -> List[str]:
        return ["ruby"]

    @property
    def description(self) -> str:
        return (
            "Detects Ruby security vulnerabilities: SQL injection, code injection, "
            "command injection, path traversal, hardcoded secrets, weak crypto, XSS"
        )

    def apply(self, code_file: CodeFile) -> TransformationResult:
        self._findings = []
        content = code_file.content
        lines = content.split('\n')

        self._scan_sql(content, lines)
        self._scan_code_injection(content, lines)
        self._scan_cmd_injection(content, lines)
        self._scan_path_traversal(content, lines)
        self._scan_secrets(content, lines)
        self._scan_weak_crypto(content, lines)
        self._scan_xss(content, lines)

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

    def _scan_sql(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SQL_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUBY-SEC-001", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-89", "SQL Injection",
                        "A03", "Injection",
                        9.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Use parameterized queries: Model.where(user_id: params[:id])",
                         "Use ActiveRecord scopes with sanitized inputs",
                         "Avoid raw SQL unless absolutely necessary"),
                        ("Do NOT interpolate user input into SQL strings",
                         "Do NOT use find_by_sql with string concatenation"),
                        ("Test: ' OR '1'='1 in query parameters",
                         "Use Bullet gem to detect N+1 and missing indexes",
                         "Run: bundle audit for vulnerable gems"),
                        ("https://owasp.org/www-community/attacks/SQL_Injection",
                         "https://cwe.mitre.org/data/definitions/89.html"),
                    ))

    def _scan_code_injection(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CODE_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUBY-SEC-002", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-94", "Code Injection",
                        "A03", "Injection",
                        9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Avoid eval() entirely - use case statements or dispatch tables",
                         "Use send() only with allowlisted method names",
                         "Validate method names with regex before send()"),
                        ("Do NOT use eval() with user input",
                         "Do NOT use instance_eval/class_eval with untrusted input"),
                        ("Test: #{`ls`}, #{system('whoami')}",
                         "Use RuboCop to ban eval() in your codebase"),
                        ("https://owasp.org/www-community/attacks/Code_Injection",
                         "https://cwe.mitre.org/data/definitions/94.html"),
                    ))

    def _scan_cmd_injection(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CMD_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUBY-SEC-003", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-78", "OS Command Injection",
                        "A03", "Injection",
                        9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Use Ruby's built-in file operations instead of shell commands",
                         "Use Dir.glob() instead of `ls`",
                         "Use Shellwords.escape() if shell invocation is unavoidable"),
                        ("Do NOT pass user input to system(), exec(), or backticks",
                         "Do NOT use string interpolation in shell commands"),
                        ("Test: #{`whoami`}, #{system('rm -rf /')}",
                         "Use Brakeman SAST for Rails apps"),
                        ("https://owasp.org/www-community/attacks/Command_Injection",
                         "https://cwe.mitre.org/data/definitions/78.html"),
                    ))

    def _scan_path_traversal(self, content: str, lines: List[str]) -> None:
        for pat, problem in _PATH_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUBY-SEC-004", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-22", "Path Traversal",
                        "A01", "Broken Access Control",
                        8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use File.expand_path() and verify path stays within allowed directory",
                         "Use allowlist-based file access control",
                         "Validate filename with basename() and reject paths with .."),
                        ("Do NOT use user input directly in file paths",
                         "Do NOT rely on path string manipulation alone"),
                        ("Test: ../../../etc/passwd in file name parameter",
                         "Verify resolved path stays within allowed directory"),
                        ("https://owasp.org/www-community/attacks/Path_Traversal",
                         "https://cwe.mitre.org/data/definitions/22.html"),
                    ))

    def _scan_secrets(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SECRET_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUBY-SEC-005", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-798", "Use of Hard-coded Credentials",
                        "A07", "Identification and Authentication Failures",
                        7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use ENV['API_KEY'] or Rails credentials (config/credentials.yml.enc)",
                         "Use a secrets manager: AWS SM, HashiCorp Vault",
                         "Use dotenv-rails for local development"),
                        ("Do NOT hardcode credentials in source files",
                         "Do NOT commit secrets to version control"),
                        ("Run: git log -S 'password=' -- .",
                         "Use: brakeman, bundler-audit, Gitleaks",
                         "Add .env to .gitignore"),
                        ("https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                         "https://cwe.mitre.org/data/definitions/798.html"),
                    ))

    def _scan_weak_crypto(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CRYPTO_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUBY-SEC-006", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.MEDIUM,
                        "CWE-327", "Use of Weak Cryptographic Algorithm",
                        "A02", "Cryptographic Failures",
                        7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use SHA-256 or SHA-3 for hashing (Digest::SHA256)",
                         "Use AES-256-GCM or ChaCha20 for encryption",
                         "Use SecureRandom for random number generation"),
                        ("Do NOT use MD5 or SHA1 for security purposes",
                         "Do NOT use ECB mode - use CBC or GCM",
                         "Do NOT use RC4 or DES"),
                        ("Use Ruby's SecureRandom for cryptographic randomness",
                         "Use: bundle audit for vulnerable crypto gems"),
                        ("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Cryptography/01-Testing_for_Weak_Cryptography",
                         "https://cwe.mitre.org/data/definitions/327.html"),
                    ))

    def _scan_xss(self, content: str, lines: List[str]) -> None:
        for pat, problem in _XSS_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUBY-SEC-007", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-79", "Cross-site Scripting (XSS)",
                        "A03", "Injection",
                        8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                        ("Use <%= ERB helper %> with proper escaping (default in Rails)",
                         "Use sanitize() helper for user-controlled HTML",
                         "Use Content Security Policy (CSP) headers"),
                        ("Do NOT use raw() or .html_safe without review",
                         "Do NOT use <%= raw(params[:x]) %>"),
                        ("Test: <script>alert(1)</script> in input fields",
                         "Use OWASP ZAP or Burp Suite for XSS scanning"),
                        ("https://owasp.org/www-community/attacks/xss/",
                         "https://cwe.mitre.org/data/definitions/79.html"),
                    ))

    def _is_real_code(self, lines: List[str], line_no: int) -> bool:
        idx = line_no - 1
        if idx < 0 or idx >= len(lines):
            return False
        stripped = lines[idx].strip()
        if stripped.startswith('#'):
            return False
        return True
