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

"""C# security rules - regex-based detection.

Detects the most common and dangerous security vulnerabilities in C# code
without requiring a C# parser.

Supported languages: csharp

Usage:
    from pyneat.rules.csharp.security import CSharpSecurityRule
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

# Unsafe Deserialization (CRITICAL) - BinaryFormatter is the most dangerous
_DESERIALIZATION_PATTERNS = [
    (r'BinaryFormatter',
     'BinaryFormatter detected - RCE risk (CA2350/CA2351)'),
    (r'NetDataContractSerializer',
     'NetDataContractSerializer - unsafe deserialization'),
    (r'LosFormatter',
     'LosFormatter - unsafe deserialization'),
    (r'DataContractSerializer',
     'DataContractSerializer - verify input source is trusted'),
]

# SQL Injection (CRITICAL)
_SQL_PATTERNS = [
    (r'"\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+[^{}\(\)]*(?:\+\s*[^"]+)+',
     'SQL query string built with string concatenation - SQL injection risk'),
]

# Path Traversal (HIGH)
_PATH_PATTERNS = [
    (r'File\.ReadAll(?:Text|Bytes|Lines)\s*\(',
     'File.ReadAll* with dynamic path - path traversal risk'),
    (r'File\.Open(?:Read|Write)?\s*\(',
     'File.Open* with dynamic path - verify path safety'),
    (r'Path\.Combine\s*\([^)]+',
     'Path.Combine - verify paths are validated'),
    (r'Server\.MapPath\s*\(',
     'Server.MapPath - verify path does not contain user-controlled data'),
]

# LDAP Injection (MEDIUM)
_LDAP_PATTERNS = [
    (r'DirectorySearcher\s*\(',
     'DirectorySearcher instantiation - verify filter is parameterized'),
    (r'DirectoryEntry\s*\(',
     'DirectoryEntry instantiation - verify DN is validated'),
]

# Hardcoded Secrets (HIGH)
_SECRET_PATTERNS = [
    (r'["\047]sk[-_](?:live|test|prod)[-_][a-zA-Z0-9]{20,}["\047]',
     'Hardcoded secret key detected'),
    (r'["\047]AKIA[0-9A-Z]{16}["\047]',
     'Hardcoded AWS access key detected'),
    (r'Password\s*[=:]\s*["\047][^"\047]{8,}["\047]',
     'Hardcoded Password detected'),
    (r'ConnectionString\s*[=:]\s*["\047][^"\047]{20,}["\047]',
     'Hardcoded connection string detected'),
    (r'ghp[a-zA-Z0-9]{36}',
     'Hardcoded GitHub token detected'),
    (r'Bearer\s+[a-zA-Z0-9_\-\.]+',
     'Hardcoded Bearer token detected'),
]

# Weak Crypto (MEDIUM)
_CRYPTO_PATTERNS = [
    (r'MD5CryptoServiceProvider',
     'MD5 is cryptographically broken - use SHA-256+'),
    (r'SHA1CryptoServiceProvider',
     'SHA1 is deprecated - use SHA-256+'),
    (r'DESCryptoServiceProvider',
     'DES encryption is weak - use AES-256'),
    (r'TripleDESCryptoServiceProvider',
     'TripleDES is weak - use AES-256'),
    (r'RC2CryptoServiceProvider',
     'RC2 is deprecated - use AES-256'),
    (r'RijndaelManaged',
     'RijndaelManaged - use AES explicitly (AES = Rijndael with fixed block size)'),
]

# XSS (HIGH)
_XSS_PATTERNS = [
    (r'Response\.Write\s*\([^)]*\+',
     'Response.Write with concat - XSS risk'),
    (r'@Html\.Raw\s*\(',
     '@Html.Raw() bypasses encoding - XSS risk'),
    (r'MarkupString\s*\(',
     'MarkupString - verify content is sanitized'),
    (r'\.InnerHtml\s*=\s*[^;]*\+',
     'InnerHtml assignment with concat - XSS risk'),
]


# --------------------------------------------------------------------------
# Rule Class
# --------------------------------------------------------------------------

class CSharpSecurityRule(Rule):
    """Detects 7 categories of C# security vulnerabilities.

    Detects:
      - Unsafe Deserialization (BinaryFormatter, NetDataContractSerializer) [CRITICAL]
      - SQL Injection (SqlCommand with concat) [CRITICAL]
      - Path Traversal (File.*, Path.Combine, Server.MapPath) [HIGH]
      - LDAP Injection (DirectorySearcher with concat) [MEDIUM]
      - Hardcoded Secrets (passwords, connection strings, tokens) [HIGH]
      - Weak Crypto (MD5, SHA1, DES, 3DES) [MEDIUM]
      - XSS (@Html.Raw, Response.Write, InnerHtml) [HIGH]

    Supports: csharp.
    """

    ALLOWED_SEMANTIC_NODES: Set[str] = set()

    def __init__(self, config=None):
        super().__init__(config)
        self._findings: List[SecurityFinding] = []

    @property
    def supported_languages(self) -> List[str]:
        return ["csharp"]

    @property
    def description(self) -> str:
        return (
            "Detects C# security vulnerabilities: unsafe deserialization, SQL injection, "
            "path traversal, LDAP injection, hardcoded secrets, weak crypto, XSS"
        )

    def apply(self, code_file: CodeFile) -> TransformationResult:
        self._findings = []
        content = code_file.content
        lines = content.split('\n')

        self._scan_deserialization(content, lines)
        self._scan_sql(content, lines)
        self._scan_path(content, lines)
        self._scan_ldap(content, lines)
        self._scan_secrets(content, lines)
        self._scan_crypto(content, lines)
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

    def _scan_deserialization(self, content: str, lines: List[str]) -> None:
        for pat, problem in _DESERIALIZATION_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "CSHARP-SEC-001", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-502", "Deserialization of Untrusted Data",
                        "A08", "Software and Data Integrity Failures",
                        9.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Use System.Text.Json or Newtonsoft.Json for JSON serialization",
                         "Avoid BinaryFormatter entirely - use DataContractSerializer or JSON serializers",
                         "Implement type name whitelist for deserialization",
                         "Enable CA2350/CA2351 analyzer rules in project"),
                        ("Do NOT use BinaryFormatter for untrusted data",
                         "Do NOT deserialize without type verification",
                         "Do NOT use LosFormatter or NetDataContractSerializer with untrusted input"),
                        ("Test with ysoserial.net payloads for known gadget chains",
                         "Use .NET SonarQube rules S5753, S5754",
                         "Run: dotnet analyze --rule CA2350, CA2351"),
                        ("https://cwe.mitre.org/data/definitions/502.html",
                         "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"),
                    ))

    def _scan_sql(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SQL_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "CSHARP-SEC-002", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-89", "SQL Injection",
                        "A03", "Injection",
                        9.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Use parameterized queries: SqlCommand with @parameters",
                         "Use an ORM: Entity Framework with LINQ, Dapper with params",
                         "Use stored procedures with parameters"),
                        ("Do NOT concatenate user input into SQL strings",
                         "Do NOT use string interpolation in SQL queries"),
                        ("Test: ' OR '1'='1, ' OR 1=1--",
                         "Use SQLmap for automated testing",
                         "Enable SAST rules S3649, S2077"),
                        ("https://owasp.org/www-community/attacks/SQL_Injection",
                         "https://cwe.mitre.org/data/definitions/89.html"),
                    ))

    def _scan_path(self, content: str, lines: List[str]) -> None:
        for pat, problem in _PATH_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "CSHARP-SEC-003", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-22", "Path Traversal",
                        "A01", "Broken Access Control",
                        8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use Path.GetFullPath() and Path.GetFileName() to validate",
                         "Implement whitelist-based path access control",
                         "Use Path.GetDirectoryName() to ensure path stays within allowed area"),
                        ("Do NOT concatenate user input into file paths",
                         "Do NOT trust file names from untrusted sources"),
                        ("Test: ../../../etc/passwd, ..\\..\\..\\windows\\system32\\config\\sam",
                         "Verify resolved path stays within expected directory"),
                        ("https://owasp.org/www-community/attacks/Path_Traversal",
                         "https://cwe.mitre.org/data/definitions/22.html"),
                    ))

    def _scan_ldap(self, content: str, lines: List[str]) -> None:
        for pat, problem in _LDAP_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "CSHARP-SEC-004", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.MEDIUM,
                        "CWE-90", "LDAP Injection",
                        "A03", "Injection",
                        7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use parameterized LDAP queries with escape sequences",
                         "Escape special DN characters: , + = \" \\ < > ; null",
                         "Use PrincipalContext with safe query methods"),
                        ("Do NOT concatenate user input into LDAP search filters",
                         "Do NOT use string formatting for DN construction"),
                        ("Test with LDAP injection payloads: * ( ) \\ / null",
                         "Use Burp Suite LDAP Scanner"),
                        ("https://cwe.mitre.org/data/definitions/90.html",
                         "https://owasp.org/www-community/attacks/LDAP_Injection"),
                    ))

    def _scan_secrets(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SECRET_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "CSHARP-SEC-005", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-798", "Use of Hard-coded Credentials",
                        "A07", "Identification and Authentication Failures",
                        7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use ConfigurationManager.AppSettings or UserSecrets for dev",
                         "Use Azure Key Vault, AWS Secrets Manager, or HashiCorp Vault for prod",
                         "Use ASP.NET Core Data Protection API for sensitive data"),
                        ("Do NOT hardcode passwords, connection strings, or API keys",
                         "Do NOT commit secrets to version control"),
                        ("Run: git log -S 'password=' -- .",
                         "Use: OWASP ESAPI, Microsoft.Security.Recommendations",
                         "Enable secret scanning in Azure DevOps/GitHub"),
                        ("https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                         "https://cwe.mitre.org/data/definitions/798.html"),
                    ))

    def _scan_crypto(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CRYPTO_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "CSHARP-SEC-006", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.MEDIUM,
                        "CWE-327", "Use of Weak Cryptographic Algorithm",
                        "A02", "Cryptographic Failures",
                        7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption",
                         "Use SHA-256 or SHA-3 for hashing",
                         "Use RSA with 2048+ bit keys minimum"),
                        ("Do NOT use MD5, SHA1, DES, 3DES, or RC2 in security contexts",
                         "Do NOT use RijndaelManaged directly - use AES"),
                        ("Use .NET SonarQube rules S5542 (weak encryption), S4787 (deprecated APIs)",
                         "Review all cryptographic usage against NIST guidelines"),
                        ("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Cryptography/01-Testing_for_Weak_Cryptography",
                         "https://cwe.mitre.org/data/definitions/327.html"),
                    ))

    def _scan_xss(self, content: str, lines: List[str]) -> None:
        for pat, problem in _XSS_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "CSHARP-SEC-007", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-79", "Cross-site Scripting (XSS)",
                        "A03", "Injection",
                        8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                        ("Use @Model.Property ( Razor auto-escapes)",
                         "For React/Blazor: use safe rendering methods",
                         "Use AntiXss library or OWASP Encoder"),
                        ("Do NOT use @Html.Raw() with untrusted input",
                         "Do NOT use Response.Write with raw user data"),
                        ("Test: <script>alert(1)</script>, <img src=x onerror=alert(1)>",
                         "Use OWASP ZAP, Burp Suite for XSS scanning"),
                        ("https://owasp.org/www-community/attacks/xss/",
                         "https://cwe.mitre.org/data/definitions/79.html"),
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
