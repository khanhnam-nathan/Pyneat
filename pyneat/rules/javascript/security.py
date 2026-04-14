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

"""JavaScript/TypeScript security rules - regex-based detection.

Detects the most common and dangerous security vulnerabilities in JavaScript
and TypeScript code without requiring a full JS parser.

Supported languages: javascript, typescript

Usage:
    from pyneat.rules.javascript.security import JSSecurityRule
"""

import re
from typing import List, Set, Optional

from pyneat.core.types import (
    CodeFile, RuleConfig, TransformationResult,
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
# Security Finding Factory
# --------------------------------------------------------------------------

def _make_finding(
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

# Code Injection patterns (CRITICAL)
_CODE_INJECTION_PATTERNS = [
    (r'\beval\s*\(', 'eval() executes arbitrary JavaScript code'),
    (r'\beval\s*\(.*?\$', 'eval() with template literal - possible injection'),
    (r'new\s+Function\s*\(', 'new Function() is equivalent to eval()'),
    (r'vm\s*\.\s*runIn', 'vm.runIn* executes code in VM context'),
    (r'vm\s*\.\s*compileFunction\s*\(', 'vm.compileFunction() creates executable code'),
    (r'process\.binding\s*\(', 'process.binding exposes internal modules'),
]

# SQL Injection patterns (CRITICAL)
_SQL_INJECTION_PATTERNS = [
    (r'\.query\s*\(\s*`[^`]*\$\{', '.query() with template literal - SQL injection risk'),
    (r'\.query\s*\(\s*["\'][^"\']*\+', '.query() with string concatenation - SQL injection risk'),
    (r'execute\s*\(\s*["\'][^"\']*\+', 'execute() with string concatenation - SQL injection risk'),
    (r'WHERE\s+\w+\s*=\s*["\'][^"\']*\$\{', 'SQL WHERE clause with template interpolation'),
    (r'SELECT\s+.*FROM.*\+', 'SQL query built with string concatenation'),
]

# SSRF patterns (HIGH) - no space required after opening paren
_SSRF_PATTERNS = [
    (r'fetch\s*\(\s*`[^`]*\$\{', 'fetch() with template literal - SSRF risk'),
    (r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*`[^`]*\$\{', 'axios with template literal URL - SSRF risk'),
    (r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*\$\{', 'axios with dynamic URL - SSRF risk'),
    (r'request\s*\(\s*\{[^}]*url\s*:\s*\$\{', 'request() with dynamic URL - SSRF risk'),
    (r'undici\s*\.\s*request\s*\([^)]*origin\s*:', 'undici origin can be overridden - SSRF risk'),
    (r'http\.get\s*\(\s*\$\{', 'http.get() with dynamic URL - SSRF risk'),
]

# Path Traversal patterns (HIGH) - no space required
_PATH_TRAVERSAL_PATTERNS = [
    (r'readFile(?:Sync)?\s*\(\s*`[^`]*\$\{', 'fs.readFile with dynamic path - path traversal risk'),
    (r'readFile(?:Sync)?\s*\(\s*\$\{', 'fs.readFile with dynamic path - path traversal risk'),
    (r'require\s*\(\s*`[^`]*\$\{', 'require() with dynamic path - path traversal risk'),
    (r'require\s*\(\s*\$\{', 'require() with dynamic path - path traversal risk'),
    (r'import\s*\(\s*`[^`]*\$\{', 'dynamic import() with path - path traversal risk'),
    (r'import\s*\(\s*\$\{', 'dynamic import() with path - path traversal risk'),
]

# XSS / DOM Injection patterns (HIGH)
_XSS_PATTERNS = [
    (r'innerHTML\s*=\s*[^;]*\$\{', 'innerHTML assignment with template literal - XSS risk'),
    (r'innerHTML\s*=\s*[^;]*\+', 'innerHTML assignment with concatenation - XSS risk'),
    (r'\.html\s*\(\s*[^)]*\$\{', '.html() with template literal - XSS risk'),
    (r'\.html\s*\(\s*[^)]*\+', '.html() with concatenation - XSS risk'),
    (r'document\s*\.\s*write\s*\(', 'document.write() can inject HTML/JS - XSS risk'),
    (r'document\s*\.\s*writeln\s*\(', 'document.writeln() can inject HTML/JS - XSS risk'),
    (r'dangerouslySetInnerHTML\s*=', 'dangerouslySetInnerHTML bypasses React escaping - XSS risk'),
]

# Hardcoded Secrets patterns (HIGH)
_SECRET_PATTERNS = [
    (r'(?:api[_-]?key|API[_-]?KEY)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
     'Hardcoded API key detected'),
    (r'["\']sk[-_](?:live|test|prod)[-_][a-zA-Z0-9]{20,}["\']',
     'Hardcoded secret key detected'),
    (r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
     'Hardcoded password detected'),
    (r'(?:secret|SECRET)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{8,}["\']',
     'Hardcoded secret detected'),
    (r'(?:auth[_-]?token|ACCESS[_-]?TOKEN)\s*[=:]\s*["\'][a-zA-Z0-9_\-\.]{16,}["\']',
     'Hardcoded auth token detected'),
    (r'Bearer\s+[a-zA-Z0-9_\-\.]+', 'Hardcoded Bearer token detected'),
    (r'ghp?_[a-zA-Z0-9]{36}', 'Hardcoded GitHub token detected'),
    (r'AKIA[0-9A-Z]{16}', 'Hardcoded AWS access key detected'),
    (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', 'Hardcoded private key detected'),
]

# Weak Crypto patterns (MEDIUM)
_WEAK_CRYPTO_PATTERNS = [
    (r'createHash\s*\(\s*["\']md5["\']\s*\)', 'MD5 is cryptographically broken - use SHA-256+'),
    (r'createHash\s*\(\s*["\']sha1["\']\s*\)', 'SHA1 is deprecated - use SHA-256+'),
    (r'createCipher\s*\(', 'createCipher uses weak DES - use crypto.createCipheriv'),
    (r'createDecipher\s*\(', 'createDecipher uses weak DES - use crypto.createDecipheriv'),
    (r'Math\s*\.\s*random\s*\(\s*\)', 'Math.random() is not cryptographically secure'),
    (r'\.sign\s*\(\s*["\']HS256["\']', 'HS256 JWT signing - ensure key is strong enough (256+ bits)'),
    (r'verify\s*:\s*false', 'JWT verification disabled - tokens can be forged'),
]

# Insecure TLS patterns (HIGH)
_TLS_PATTERNS = [
    (r'rejectUnauthorized\s*:\s*false', 'TLS certificate verification disabled - MITM attack risk'),
    (r'\.rejectUnauthorized\s*=\s*false', 'TLS certificate verification disabled globally'),
    (r'secure\s*:\s*false\s*[,}]', 'Cookie secure flag disabled - transmitted over HTTP'),
]

# Prototype Pollution patterns (HIGH)
_PROTOTYPE_POLLUTION_PATTERNS = [
    (r'__proto__', '__proto__ assignment - prototype pollution risk'),
    (r'constructor\s*\.\s*prototype', 'constructor.prototype modification - prototype pollution risk'),
    (r'Object\s*\.\s*assign\s*\([^,]+req', 'Object.assign merging req data - prototype pollution risk'),
    (r'\[\s*\$\{[^}]+\]\s*=\s*', 'Dynamic key assignment with user input - prototype pollution risk'),
]

# Information Disclosure patterns (LOW)
_INFO_DISCLOSURE_PATTERNS = [
    (r'console\s*\.\s*(?:log|debug|info)\s*\(\s*["\'][^"\']*(?:password|secret|token|key)',
     'Console log contains sensitive keyword'),
    (r'console\s*\.\s*(?:log|debug|info)\s*\(\s*(?:req|res|process)\s*\)', 'Console log of full request/response object - information disclosure'),
]


# --------------------------------------------------------------------------
# Rule Class
# --------------------------------------------------------------------------

class JSSecurityRule(Rule):
    """Detects 10 categories of JavaScript/TypeScript security vulnerabilities.

    Detects:
      - Code Injection (eval, new Function, vm.runIn*) [CRITICAL]
      - SQL Injection (template literals in queries) [CRITICAL]
      - SSRF (dynamic URLs in fetch/axios/request) [HIGH]
      - Path Traversal (dynamic paths in fs operations) [HIGH]
      - XSS / DOM Injection (innerHTML, dangerouslySetInnerHTML) [HIGH]
      - Hardcoded Secrets (API keys, tokens, passwords) [HIGH]
      - Weak Crypto (MD5, SHA1, Math.random) [MEDIUM]
      - Insecure TLS (rejectUnauthorized: false) [HIGH]
      - Prototype Pollution (__proto__, constructor.prototype) [HIGH]
      - Information Disclosure (console logging sensitive data) [LOW]

    Uses regex-based detection optimized for JavaScript/TypeScript syntax.
    Supports: javascript, typescript.
    """

    ALLOWED_SEMANTIC_NODES: Set[str] = set()

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self._findings: List[SecurityFinding] = []

    @property
    def rule_id(self) -> str:
        return "JS-SEC-ALL"

    @property
    def description(self) -> str:
        return (
            "Detects JavaScript/TypeScript security vulnerabilities: "
            "code injection, SQLi, SSRF, path traversal, XSS, "
            "hardcoded secrets, weak crypto, insecure TLS, prototype pollution"
        )

    @property
    def supported_languages(self) -> List[str]:
        return ["javascript", "typescript"]

    def apply(self, code_file: CodeFile) -> TransformationResult:
        self._findings = []
        content = code_file.content
        lines = content.split('\n')

        self._scan_code_injection(content, lines)
        self._scan_sql_injection(content, lines)
        self._scan_ssrf(content, lines)
        self._scan_path_traversal(content, lines)
        self._scan_xss(content, lines)
        self._scan_hardcoded_secrets(content, lines)
        self._scan_weak_crypto(content, lines)
        self._scan_insecure_tls(content, lines)
        self._scan_prototype_pollution(content, lines)
        self._scan_info_disclosure(content, lines)

        changes = []
        for f in self._findings:
            changes.append(
                f"[{f.rule_id}] {f.problem} (line {f.start_line})"
            )

        return TransformationResult(
            original=code_file,
            transformed_content=content,
            changes_made=changes,
            success=True,
            security_findings=self._findings.copy(),
        )

    # --------------------------------------------------------------------------
    # Detection Methods
    # --------------------------------------------------------------------------

    def _scan_code_injection(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CODE_INJECTION_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code_line(lines, line_no):
                    self._findings.append(_make_finding(
                        rule_id="JS-SEC-001",
                        line_no=line_no,
                        snippet_text=_snippet(lines, line_no, m.group()),
                        problem=problem,
                        severity=SecuritySeverity.CRITICAL,
                        cwe_id="CWE-94",
                        cwe_name="Code Injection",
                        owasp_id="A03",
                        owasp_name="Injection",
                        cvss_base=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        fix_constraints=(
                            "Avoid eval(), new Function(), vm.runIn* entirely",
                            "Use JSON.parse() for safe data parsing",
                            "Use sandboxed iframes or Web Workers for untrusted code",
                        ),
                        do_not=(
                            "Do NOT rely on simple string sanitization before eval()",
                            "Do NOT assume 'use strict' makes eval() safe",
                        ),
                        verify=(
                            "Confirm no eval/new Function/vm calls in codebase",
                            "Use Content Security Policy (CSP) to block eval()",
                            "Run: npm audit --production",
                        ),
                        resources=(
                            "https://owasp.org/www-community/attacks/Code_Injection",
                            "https://cwe.mitre.org/data/definitions/94.html",
                            "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval",
                        ),
                    ))

    def _scan_sql_injection(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SQL_INJECTION_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code_line(lines, line_no):
                    self._findings.append(_make_finding(
                        rule_id="JS-SEC-002",
                        line_no=line_no,
                        snippet_text=_snippet(lines, line_no, m.group()),
                        problem=problem,
                        severity=SecuritySeverity.CRITICAL,
                        cwe_id="CWE-89",
                        cwe_name="SQL Injection",
                        owasp_id="A03",
                        owasp_name="Injection",
                        cvss_base=9.9,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        fix_constraints=(
                            "Use parameterized queries / prepared statements",
                            "Use an ORM (Sequelize, TypeORM, Prisma) with query builder",
                            "Escape special characters with a library specific to your DB driver",
                        ),
                        do_not=(
                            "Do NOT concatenate user input into SQL strings",
                            "Do NOT use template literals with ${} in SQL queries",
                        ),
                        verify=(
                            "Test with payloads: ' OR '1'='1, ' OR 1=1--",
                            "Use SQLmap for automated injection testing",
                        ),
                        resources=(
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cwe.mitre.org/data/definitions/89.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        ),
                    ))

    def _scan_ssrf(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SSRF_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code_line(lines, line_no):
                    self._findings.append(_make_finding(
                        rule_id="JS-SEC-003",
                        line_no=line_no,
                        snippet_text=_snippet(lines, line_no, m.group()),
                        problem=problem,
                        severity=SecuritySeverity.HIGH,
                        cwe_id="CWE-918",
                        cwe_name="Server-Side Request Forgery",
                        owasp_id="A10",
                        owasp_name="Server-Side Request Forgery",
                        cvss_base=8.6,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        fix_constraints=(
                            "Validate and whitelist allowed domains/IPs",
                            "Use URL parsing to ensure no protocol override (data:, javascript:)",
                            "Block access to cloud metadata endpoints (169.254.169.254)",
                        ),
                        do_not=(
                            "Do NOT rely on URL parsing alone without allowlist",
                            "Do NOT allow user control of any URL component without validation",
                        ),
                        verify=(
                            "Test with: file:///etc/passwd, http://169.254.169.254/",
                            "Use SSRFmap or Burp Collaborator for testing",
                        ),
                        resources=(
                            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                            "https://cwe.mitre.org/data/definitions/918.html",
                        ),
                    ))

    def _scan_path_traversal(self, content: str, lines: List[str]) -> None:
        for pat, problem in _PATH_TRAVERSAL_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code_line(lines, line_no):
                    self._findings.append(_make_finding(
                        rule_id="JS-SEC-004",
                        line_no=line_no,
                        snippet_text=_snippet(lines, line_no, m.group()),
                        problem=problem,
                        severity=SecuritySeverity.HIGH,
                        cwe_id="CWE-22",
                        cwe_name="Path Traversal",
                        owasp_id="A01",
                        owasp_name="Broken Access Control",
                        cvss_base=8.6,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        fix_constraints=(
                            "Use path.resolve() and path.normalize() to sanitize paths",
                            "Implement whitelist-based access control for allowed paths",
                            "Use realpath() to resolve symlinks and detect traversal attempts",
                        ),
                        do_not=(
                            "Do NOT rely on string replacement of '../' alone",
                            "Do NOT assume encoded paths (%2e%2e%2f) are safe",
                        ),
                        verify=(
                            "Test with: ../../../etc/passwd, %2e%2e%2f%2e%2e%2fetc%2fpasswd",
                        ),
                        resources=(
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://cwe.mitre.org/data/definitions/22.html",
                        ),
                    ))

    def _scan_xss(self, content: str, lines: List[str]) -> None:
        for pat, problem in _XSS_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code_line(lines, line_no):
                    self._findings.append(_make_finding(
                        rule_id="JS-SEC-005",
                        line_no=line_no,
                        snippet_text=_snippet(lines, line_no, m.group()),
                        problem=problem,
                        severity=SecuritySeverity.HIGH,
                        cwe_id="CWE-79",
                        cwe_name="Cross-site Scripting (XSS)",
                        owasp_id="A03",
                        owasp_name="Injection",
                        cvss_base=8.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                        fix_constraints=(
                            "Use textContent instead of innerHTML for user data",
                            "Use React's default escaping (avoid dangerouslySetInnerHTML)",
                            "Sanitize HTML with DOMPurify before insertion",
                            "Use Content Security Policy (CSP) to mitigate XSS",
                        ),
                        do_not=(
                            "Do NOT use innerHTML with any user-controlled content",
                        ),
                        verify=(
                            "Test with: <script>alert(1)</script>, <img src=x onerror=alert(1)>",
                            "Use automated scanners: Burp, OWASP ZAP, XSStrike",
                        ),
                        resources=(
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cwe.mitre.org/data/definitions/79.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        ),
                    ))

    def _scan_hardcoded_secrets(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SECRET_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code_line(lines, line_no):
                    self._findings.append(_make_finding(
                        rule_id="JS-SEC-006",
                        line_no=line_no,
                        snippet_text=_snippet(lines, line_no, m.group()),
                        problem=problem,
                        severity=SecuritySeverity.HIGH,
                        cwe_id="CWE-798",
                        cwe_name="Use of Hard-coded Credentials",
                        owasp_id="A07",
                        owasp_name="Identification and Authentication Failures",
                        cvss_base=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        fix_constraints=(
                            "Move all secrets to environment variables (process.env.SECRET)",
                            "Use a secrets manager: AWS Secrets Manager, HashiCorp Vault, Azure Key Vault",
                            "Use .env files with .gitignore (never commit .env)",
                        ),
                        do_not=(
                            "Do NOT commit .env files to version control",
                            "Do NOT hardcode API keys, tokens, or passwords in source code",
                        ),
                        verify=(
                            "Run: git log --all --source --remotes -- .env (check for leaks)",
                            "Use: npm run audit or Snyk to detect leaked secrets",
                        ),
                        resources=(
                            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                            "https://cwe.mitre.org/data/definitions/798.html",
                            "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning",
                        ),
                    ))

    def _scan_weak_crypto(self, content: str, lines: List[str]) -> None:
        for pat, problem in _WEAK_CRYPTO_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code_line(lines, line_no):
                    self._findings.append(_make_finding(
                        rule_id="JS-SEC-007",
                        line_no=line_no,
                        snippet_text=_snippet(lines, line_no, m.group()),
                        problem=problem,
                        severity=SecuritySeverity.MEDIUM,
                        cwe_id="CWE-327",
                        cwe_name="Use of Weak Cryptographic Algorithm",
                        owasp_id="A02",
                        owasp_name="Cryptographic Failures",
                        cvss_base=7.4,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        fix_constraints=(
                            "Use crypto.randomBytes() for cryptographic random numbers",
                            "Use SHA-256 or stronger for hashing (SHA-3 recommended)",
                            "Use AES-256-GCM for symmetric encryption",
                        ),
                        do_not=(
                            "Do NOT use MD5 or SHA1 for security purposes",
                            "Do NOT use Math.random() for any security-relevant randomness",
                        ),
                        verify=(
                            "Use npm audit to check for vulnerable crypto dependencies",
                        ),
                        resources=(
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Cryptography/01-Testing_for_Weak_Cryptography",
                            "https://cwe.mitre.org/data/definitions/327.html",
                        ),
                    ))

    def _scan_insecure_tls(self, content: str, lines: List[str]) -> None:
        for pat, problem in _TLS_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code_line(lines, line_no):
                    self._findings.append(_make_finding(
                        rule_id="JS-SEC-008",
                        line_no=line_no,
                        snippet_text=_snippet(lines, line_no, m.group()),
                        problem=problem,
                        severity=SecuritySeverity.HIGH,
                        cwe_id="CWE-295",
                        cwe_name="Improper Certificate Validation",
                        owasp_id="A02",
                        owasp_name="Cryptographic Failures",
                        cvss_base=7.4,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        fix_constraints=(
                            "Always set rejectUnauthorized: true (default)",
                            "Use TLS 1.2 or higher (disable TLS 1.0/1.1)",
                        ),
                        do_not=(
                            "Do NOT set rejectUnauthorized: false in production",
                        ),
                        verify=(
                            "Use sslyze or testssl.sh to check TLS configuration",
                        ),
                        resources=(
                            "https://cwe.mitre.org/data/definitions/295.html",
                            "https://wiki.mozilla.org/Security/Server_Side_TLS",
                        ),
                    ))

    def _scan_prototype_pollution(self, content: str, lines: List[str]) -> None:
        for pat, problem in _PROTOTYPE_POLLUTION_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code_line(lines, line_no):
                    self._findings.append(_make_finding(
                        rule_id="JS-SEC-009",
                        line_no=line_no,
                        snippet_text=_snippet(lines, line_no, m.group()),
                        problem=problem,
                        severity=SecuritySeverity.HIGH,
                        cwe_id="CWE-1321",
                        cwe_name="Improperly Controlled Modification of Object Prototype Attributes",
                        owasp_id="A03",
                        owasp_name="Injection",
                        cvss_base=8.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                        fix_constraints=(
                            "Avoid merging user objects directly with Object.assign()",
                            "Use Object.create(null) to create objects without prototype",
                            "Use schema validation (Joi, Yup) for untrusted input",
                            "Use Map instead of plain objects for user-provided keys",
                        ),
                        do_not=(
                            "Do NOT use __proto__ or constructor.prototype in production code",
                            "Do NOT merge request objects without sanitizing keys",
                        ),
                        verify=(
                            "Test with: {\"__proto__\": {\"isAdmin\": true}}, {\"constructor\": {\"prototype\": {\"foo\": \"bar\"}}}",
                        ),
                        resources=(
                            "https://github.com/HoLyVieR/prototype-pollution-nsec18",
                            "https://cwe.mitre.org/data/definitions/1321.html",
                        ),
                    ))

    def _scan_info_disclosure(self, content: str, lines: List[str]) -> None:
        for pat, problem in _INFO_DISCLOSURE_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code_line(lines, line_no):
                    self._findings.append(_make_finding(
                        rule_id="JS-SEC-010",
                        line_no=line_no,
                        snippet_text=_snippet(lines, line_no, m.group()),
                        problem=problem,
                        severity=SecuritySeverity.LOW,
                        cwe_id="CWE-532",
                        cwe_name="Information Exposure Through Debug Logs",
                        owasp_id="A09",
                        owasp_name="Security Logging and Monitoring Failures",
                        cvss_base=3.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        fix_constraints=(
                            "Use a structured logging library (pino, winston, morgan)",
                            "Redact sensitive fields from logs before output",
                            "Set log level from environment (LOG_LEVEL=info in production)",
                        ),
                        do_not=(
                            "Do NOT log full req/res objects in production",
                            "Do NOT log passwords, tokens, or API keys",
                        ),
                        verify=(
                            "Review all console.log/warn/error statements before production",
                        ),
                        resources=(
                            "https://cwe.mitre.org/data/definitions/532.html",
                        ),
                    ))

    # --------------------------------------------------------------------------
    # Utilities
    # --------------------------------------------------------------------------

    def _is_real_code_line(self, lines: List[str], line_no: int) -> bool:
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
        if stripped.startswith('*'):
            return False

        # Skip lines that are pure string literals
        single_string = re.match(r'^\s*["\'].*["\']\s*[,;]?\s*$', stripped)
        if single_string:
            return False

        return True
