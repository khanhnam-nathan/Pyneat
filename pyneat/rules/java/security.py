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

"""Java security rules - regex-based detection.

Detects the most common and dangerous security vulnerabilities in Java code
without requiring a Java parser.

Supported languages: java

Usage:
    from pyneat.rules.java.security import JavaSecurityRule
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

# SQL Injection (CRITICAL)
_SQL_PATTERNS = [
    # SQL string built with + concatenation
    (r'"\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+[^{}]*(?:\+\s*[^"]+)+',
     'SQL query string built with concatenation - SQL injection risk'),
    (r'"\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+[^"]*\+\s*[a-zA-Z_]',
     'SQL query string built with concatenation - SQL injection risk'),
    # executeQuery/executeUpdate with variable that may be built with concat
    (r'\.\s*execute(?:Query|Update)\s*\(\s*sql\s*\)',
     'executeQuery(sql) - verify sql was not built with string concatenation'),
    (r'\.\s*execute(?:Query|Update)\s*\(\s*(?:query|q)\s*\)',
     'executeQuery with dynamic variable - verify no SQL injection'),
]

# Unsafe Deserialization (CRITICAL)
_DESERIALIZATION_PATTERNS = [
    (r'ObjectInputStream\s*\(',
     'ObjectInputStream deserializes untrusted data - RCE risk'),
    (r'XMLDecoder\s*\(',
     'XMLDecoder deserializes untrusted XML - RCE risk'),
    (r'XStream\s*\(\s*\)',
     'XStream default instantiation - XML deserialization RCE risk'),
    (r'\.fromXML\s*\(',
     'XStream.fromXML() - XML deserialization RCE risk'),
    (r'\.readObject\s*\(\s*\)',
     'readObject() called - potential unsafe deserialization'),
]

# XXE (CRITICAL)
_XXE_PATTERNS = [
    (r'DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)',
     'DocumentBuilderFactory without XXE protection - XXE risk'),
    (r'SAXParserFactory\s*\.\s*newInstance\s*\(\s*\)',
     'SAXParserFactory without XXE protection - XXE risk'),
    (r'SAXBuilder\s*\(\s*\)',
     'SAXBuilder default instantiation - XXE risk'),
    (r'SAXReader\s*\(\s*\)',
     'SAXReader default - XXE risk'),
    (r'XMLInputFactory\s*\.\s*newInstance\s*\(\s*\)',
     'XMLInputFactory without XXE protection - XXE risk'),
]

# Path Traversal (HIGH)
_PATH_PATTERNS = [
    (r'FileInputStream\s*\([^)]*\+',
     'FileInputStream with concatenation - path traversal risk'),
    (r'FileReader\s*\([^)]*\+',
     'FileReader with concatenation - path traversal risk'),
    (r'Paths\.get\s*\([^)]*\+',
     'Paths.get with concatenation - path traversal risk'),
    (r'Path\s*\.\s*get\s*\([^)]*\+',
     'Path.get with concatenation - path traversal risk'),
    (r'new\s+File\s*\([^)]*\+',
     'new File() with concatenation - path traversal risk'),
]

# Command Injection (CRITICAL)
_CMD_PATTERNS = [
    (r'\.exec\s*\([^)]*\+',
     'Method.exec() with concatenation - command injection risk'),
    (r'ProcessBuilder\s*\([^)]*\+',
     'ProcessBuilder with concatenation - command injection risk'),
    (r'ProcessImpl\s*\.\s*start\s*\(',
     'ProcessImpl.start() - verify arguments are sanitized'),
]

# Hardcoded Secrets (HIGH)
_SECRET_PATTERNS = [
    (r'["\047]sk[-_](?:live|test|prod)[-_][a-zA-Z0-9]{20,}["\047]',
     'Hardcoded secret key'),
    (r'["\047]AKIA[0-9A-Z]{16}["\047]',
     'Hardcoded AWS access key'),
    (r'private\s+static\s+final\s+String\s+(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY)\s*=',
     'Private static final String with sensitive name - verify value is not hardcoded'),
    (r'public\s+static\s+final\s+String\s+(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY)\s*=',
     'Public static final String with sensitive name - verify value is not hardcoded'),
    (r'private\s+String\s+(?:password|passwd|pwd|secret|token|apiKey)\s*=\s*"[^"]{6,}"',
     'Private field with sensitive name containing hardcoded value'),
    (r'ghp_[a-zA-Z0-9]{36}',
     'Hardcoded GitHub token'),
    (r'"(?:jwt_secret|jwtSecret|auth_token|access_token)["\s]*[=:][\s]*"[^"]{8,}"',
     'Hardcoded token literal'),
]

# Weak Crypto (MEDIUM)
_CRYPTO_PATTERNS = [
    (r'MessageDigest\s*\.\s*getInstance\s*\(\s*["\047]MD5["\047]',
     'MD5 is cryptographically broken - use SHA-256+'),
    (r'MessageDigest\s*\.\s*getInstance\s*\(\s*["\047]SHA-?1["\047]',
     'SHA1 is deprecated - use SHA-256+'),
    (r'DES(?:KeySpec|Cipher|Crypt)',
     'DES encryption - use AES-256'),
    (r'TripleDES',
     '3DES is weak - use AES-256'),
    (r'SealedObject',
     'SealedObject with weak cipher - verify encryption algorithm'),
    (r'SecretKeySpec\s*\([^)]*(?:DES|RC4|ARC4)',
     'Weak cipher algorithm in SecretKeySpec'),
]

# LDAP Injection (MEDIUM) - only DirContext specific
_LDAP_PATTERNS = [
    (r'DirContext\s*\.\s*search\s*\([^)]*\+',
     'LDAP search with string concat - LDAP injection risk'),
    (r'SearchControls\s*\([^)]*\+',
     'SearchControls with dynamic filter - LDAP injection risk'),
]


# --------------------------------------------------------------------------
# Rule Class
# --------------------------------------------------------------------------

class JavaSecurityRule(Rule):
    """Detects 8 categories of Java security vulnerabilities.

    Detects:
      - SQL Injection (Statement, executeQuery with concat) [CRITICAL]
      - Unsafe Deserialization (ObjectInputStream, XStream, readObject) [CRITICAL]
      - XXE (DocumentBuilderFactory, SAXParserFactory defaults) [CRITICAL]
      - Path Traversal (FileInputStream, Paths.get with concat) [HIGH]
      - Command Injection (Runtime.exec, ProcessBuilder) [CRITICAL]
      - Hardcoded Secrets (passwords, API keys, tokens) [HIGH]
      - Weak Crypto (MD5, SHA1, DES, 3DES) [MEDIUM]
      - LDAP Injection (DirContext.search with concat) [MEDIUM]

    Uses regex-based detection optimized for Java syntax.
    Supports: java.
    """

    ALLOWED_SEMANTIC_NODES: Set[str] = set()

    def __init__(self, config=None):
        super().__init__(config)
        self._findings: List[SecurityFinding] = []

    @property
    def supported_languages(self) -> List[str]:
        return ["java"]

    @property
    def description(self) -> str:
        return (
            "Detects Java security vulnerabilities: SQL injection, unsafe deserialization, "
            "XXE, path traversal, command injection, hardcoded secrets, weak crypto, "
            "LDAP injection"
        )

    def apply(self, code_file: CodeFile) -> TransformationResult:
        self._findings = []
        content = code_file.content
        lines = content.split('\n')

        self._scan_sql(content, lines)
        self._scan_deserialization(content, lines)
        self._scan_xxe(content, lines)
        self._scan_path(content, lines)
        self._scan_cmd(content, lines)
        self._scan_secrets(content, lines)
        self._scan_crypto(content, lines)
        self._scan_ldap(content, lines)

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
                        "JAVA-SEC-001", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-89", "SQL Injection",
                        "A03", "Injection",
                        9.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Use PreparedStatement with parameterized queries",
                         "Use an ORM (Hibernate, JPA) with parameterized queries",
                         "Validate and escape all user input before SQL use"),
                        ("Do NOT concatenate user input into SQL strings",
                         "Do NOT use Statement instead of PreparedStatement"),
                        ("Test: ' OR '1'='1, ' OR 1=1--",
                         "Use SQLmap for automated testing"),
                        ("https://owasp.org/www-community/attacks/SQL_Injection",
                         "https://cwe.mitre.org/data/definitions/89.html"),
                    ))

    def _scan_deserialization(self, content: str, lines: List[str]) -> None:
        for pat, problem in _DESERIALIZATION_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "JAVA-SEC-002", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-502", "Deserialization of Untrusted Data",
                        "A08", "Software and Data Integrity Failures",
                        9.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Use JSON serializers (Jackson, Gson) instead of Java serialization",
                         "For ObjectInputStream: use a custom ObjectInputStream with class filtering",
                         "Enable Check炸禁止-JNI for JNI deserialization",
                         "Use XStream with security framework (xstream secure provider)"),
                        ("Do NOT deserialize untrusted data with ObjectInputStream",
                         "Do NOT use XStream with default settings",
                         "Do NOT allow arbitrary class loading in deserialization"),
                        ("Test with ysoserial payloads for known gadget chains",
                         "Use Java Deserialization Scanner (Burp extension)",
                         "Run: findsecbugs plugin for SpotBugs"),
                        ("https://cwe.mitre.org/data/definitions/502.html",
                         "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"),
                    ))

    def _scan_xxe(self, content: str, lines: List[str]) -> None:
        for pat, problem in _XXE_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "JAVA-SEC-003", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-611", "XML External Entity (XXE)",
                        "A05", "Security Misconfiguration",
                        9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("For DocumentBuilderFactory: call setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
                         "Disable DTD processing: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)",
                         "For SAXParserFactory: call setFeature(XMLConstants.ACCESS_EXTERNAL_DTD, '')",
                         "Use DOM4J with safe settings or StAX with proper configuration"),
                        ("Do NOT use default XML parsers without secure configuration",
                         "Do NOT allow external entities in XML input"),
                        ("Test with XXE payloads: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
                         "Use OWASP ZAP or Burp Suite for XXE testing"),
                        ("https://cwe.mitre.org/data/definitions/611.html",
                         "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"),
                    ))

    def _scan_path(self, content: str, lines: List[str]) -> None:
        for pat, problem in _PATH_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "JAVA-SEC-004", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-22", "Path Traversal",
                        "A01", "Broken Access Control",
                        8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use realpath() or Path.toRealPath() to resolve symlinks",
                         "Implement whitelist-based path validation",
                         "Use Path.normalize() after joining paths"),
                        ("Do NOT use user input directly in file paths",
                         "Do NOT rely on string replacement of '../' alone"),
                        ("Test: ../../../etc/passwd, ..\\..\\..\\windows\\system32\\config\\sam",
                         "Verify file stays within allowed directory after normalization"),
                        ("https://owasp.org/www-community/attacks/Path_Traversal",
                         "https://cwe.mitre.org/data/definitions/22.html"),
                    ))

    def _scan_cmd(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CMD_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "JAVA-SEC-005", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-78", "OS Command Injection",
                        "A03", "Injection",
                        9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Use ProcessBuilder with array form (no shell invocation)",
                         "Avoid Runtime.exec() with string concatenation",
                         "Validate and whitelist allowed commands"),
                        ("Do NOT pass user input directly to command execution APIs",
                         "Do NOT use string formatting to build commands"),
                        ("Test: ; ls, $(whoami), `id`",
                         "Review all Runtime.exec and ProcessBuilder calls"),
                        ("https://owasp.org/www-community/attacks/Command_Injection",
                         "https://cwe.mitre.org/data/definitions/78.html"),
                    ))

    def _scan_secrets(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SECRET_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "JAVA-SEC-006", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-798", "Use of Hard-coded Credentials",
                        "A07", "Identification and Authentication Failures",
                        7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use environment variables: System.getenv('SECRET_KEY')",
                         "Use a secrets manager: AWS Secrets Manager, HashiCorp Vault",
                         "Use Java framework config (Spring: @Value, Micronaut: @Property)"),
                        ("Do NOT hardcode passwords, API keys, or tokens in source code",
                         "Do NOT commit credentials to version control"),
                        ("Run: git log -S 'password=' -- . (find leaked secrets)",
                         "Use: OWASP ESAPI encryptor, CredScan, Gitleaks"),
                        ("https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                         "https://cwe.mitre.org/data/definitions/798.html"),
                    ))

    def _scan_crypto(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CRYPTO_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "JAVA-SEC-007", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.MEDIUM,
                        "CWE-327", "Use of Weak Cryptographic Algorithm",
                        "A02", "Cryptographic Failures",
                        7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use AES-256-GCM for encryption (javax.crypto.Cipher with 'AES/GCM/NoPadding')",
                         "Use SHA-256+ for hashing (java.security.MessageDigest with 'SHA-256')",
                         "Use RSA with 2048+ bit keys minimum"),
                        ("Do NOT use MD5 or SHA1 for security purposes",
                         "Do NOT use DES or 3DES - use AES instead",
                         "Do NOT use ECB mode for block ciphers"),
                        ("Use OWASP Cryptographic Storage Cheat Sheet",
                         "Use Java Cryptography Architecture (JCA) with strong algorithms",
                         "Run: SonarQube S5547, S4792 rules"),
                        ("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Cryptography/01-Testing_for_Weak_Cryptography",
                         "https://cwe.mitre.org/data/definitions/327.html"),
                    ))

    def _scan_ldap(self, content: str, lines: List[str]) -> None:
        for pat, problem in _LDAP_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "JAVA-SEC-008", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.MEDIUM,
                        "CWE-90", "LDAP Injection",
                        "A03", "Injection",
                        7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use parameterized LDAP queries ( javax.naming.directory.DirContext.search with filters)",
                         "Escape special DN characters: , + = \" \\ < > ; or null",
                         "Use an LDAP library that handles escaping automatically"),
                        ("Do NOT concatenate user input into LDAP search filters",
                         "Do NOT use string formatting for DN construction"),
                        ("Test with LDAP injection payloads: * ( ) \\ / null",
                         "Use Burp Suite LDAP Scanner"),
                        ("https://cwe.mitre.org/data/definitions/90.html",
                         "https://owasp.org/www-community/attacks/LDAP_Injection"),
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
