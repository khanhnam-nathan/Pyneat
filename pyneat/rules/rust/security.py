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

"""Rust security rules - regex-based detection.

Detects the most common security vulnerabilities in Rust code
without requiring a Rust parser.

Supported languages: rust

Usage:
    from pyneat.rules.rust.security import RustSecurityRule
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

# unsafe Code (HIGH) - Rust's memory safety guarantee is broken by unsafe
_UNSAFE_PATTERNS = [
    (r'\bunsafe\s*\{',
     'unsafe block - bypasses Rust memory safety guarantees'),
    (r'\bunsafe\s+fn\s+',
     'unsafe function - verify all safety invariants are documented'),
    (r'unsafe\s+impl\s+',
     'unsafe impl block - verify safety guarantees are met'),
    (r'\btransmute\s*\(',
     'mem::transmute() changes type arbitrarily - verify alignment and size'),
]

# Path Traversal (HIGH)
_PATH_PATTERNS = [
    (r'fs::read_to_string\s*\([^)]*(?:\.[a-z_]+\(\))\s*\+',
     'fs::read_to_string with concat - path traversal risk'),
    (r'File::open\s*\([^)]*(?:\.[a-z_]+\(\))\s*\+',
     'File::open with concat - path traversal risk'),
    (r'\.join\s*\([^)]*(?:\.[a-z_]+\(\))\s*\+',
     '.join() with concat after chain call - path traversal risk'),
    (r'Path::new\s*\([^)]*\)\s*\.\s*join\s*\([^)]*(?:\.[a-z_]+\(\))\s*\+',
     'Path::new().join() with concatenation - path traversal risk'),
]

# Weak Crypto (MEDIUM)
_CRYPTO_PATTERNS = [
    (r'\bmd5::', 'md5 crate usage - MD5 is cryptographically broken'),
    (r'\bsha1::', 'sha1 crate usage - SHA1 is deprecated'),
    (r'rand::random::<(?:u|i|f)\d+>', 'rand::random() is not cryptographically secure - use ThreadRng'),
]

# Information Disclosure via Logging (LOW)
_LOG_PATTERNS = [
    (r'println!\s*\([^)]*(?:password|secret|token|key)',
     'println! contains sensitive keyword - information disclosure'),
    (r'eprintln!\s*\([^)]*(?:password|secret|token|key)',
     'eprintln! contains sensitive keyword - information disclosure'),
    (r'log::(?:info|warn|error|debug)\s*\([^)]*(?:password|secret|token|key)',
     'log macro contains sensitive keyword - information disclosure'),
    (r'dbg!\s*\([^)]*(?:password|secret|token)',
     'dbg! macro with sensitive data - information disclosure in debug output'),
]

# Hardcoded Secrets (HIGH)
_SECRET_PATTERNS = [
    (r'ghp[a-zA-Z0-9]{36}',
     'Hardcoded GitHub token detected'),
    (r'["\047]sk[-_](?:live|test|prod)[-_][a-zA-Z0-9]{20,}["\047]',
     'Hardcoded secret key detected'),
    (r'["\047]AKIA[0-9A-Z]{16}["\047]',
     'Hardcoded AWS access key detected'),
    (r'password\s*[=:]\s*["\047][^"\047]{8,}["\047]',
     'Hardcoded password detected'),
    (r'secret\s*[=:]\s*["\047][a-zA-Z0-9_\-]{8,}["\047]',
     'Hardcoded secret detected'),
]

# Command Injection (CRITICAL)
_CMD_PATTERNS = [
    (r'Command::new\s*\([^)]*(?:\.[a-z_]+\(\))\s*\+',
     'Command::new with concatenation - command injection risk'),
    (r'\.arg\s*\([^)]*(?:\.[a-z_]+\(\))\s*\+',
     'Command argument with concatenation - command injection risk'),
]

# Insecure TLS / HTTP (HIGH)
_TLS_PATTERNS = [
    (r'danger_accept_invalid_certs\s*\(',
     'danger_accept_invalid_certs bypasses TLS verification - MITM risk'),
]


# --------------------------------------------------------------------------
# Rule Class
# --------------------------------------------------------------------------

class RustSecurityRule(Rule):
    """Detects 6 categories of Rust security vulnerabilities.

    Detects:
      - unsafe Code (memory safety bypass) [HIGH]
      - Path Traversal (fs operations with concat) [HIGH]
      - Weak Crypto (md5, sha1, rand::random) [MEDIUM]
      - Information Disclosure (logging sensitive data) [LOW]
      - Hardcoded Secrets (API keys, tokens, passwords) [HIGH]
      - Command Injection (Command::new with concat) [CRITICAL]
      - Insecure TLS (dangerously_set_root_certificates) [HIGH]

    Supports: rust.
    """

    ALLOWED_SEMANTIC_NODES: Set[str] = set()

    def __init__(self, config=None):
        super().__init__(config)
        self._findings: List[SecurityFinding] = []

    @property
    def supported_languages(self) -> List[str]:
        return ["rust"]

    @property
    def description(self) -> str:
        return (
            "Detects Rust security vulnerabilities: unsafe blocks, path traversal, "
            "weak crypto, sensitive data in logs, hardcoded secrets, command injection"
        )

    def apply(self, code_file: CodeFile) -> TransformationResult:
        self._findings = []
        content = code_file.content
        lines = content.split('\n')

        self._scan_unsafe(content, lines)
        self._scan_path(content, lines)
        self._scan_crypto(content, lines)
        self._scan_logs(content, lines)
        self._scan_secrets(content, lines)
        self._scan_cmd(content, lines)
        self._scan_tls(content, lines)

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

    def _scan_unsafe(self, content: str, lines: List[str]) -> None:
        for pat, problem in _UNSAFE_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUST-SEC-001", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-119", "Memory Safety Violation",
                        "A04", "Insecure Design",
                        8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Minimize unsafe code to the smallest possible scope",
                         "Document all safety invariants with comments",
                         "Use the unsafe code guidelines from the Rustonomicon"),
                        ("Do NOT use unsafe for performance without verification",
                         "Do NOT use transmute without validating size/alignment"),
                        ("Run: cargo miri to detect undefined behavior",
                         "Use cargo audit for dependency vulnerabilities",
                         "Review all unsafe blocks with the Rust unsafe guidelines"),
                        ("https://doc.rust-lang.org/nomicon/",
                         "https://cwe.mitre.org/data/definitions/119.html"),
                    ))

    def _scan_path(self, content: str, lines: List[str]) -> None:
        for pat, problem in _PATH_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUST-SEC-002", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-22", "Path Traversal",
                        "A01", "Broken Access Control",
                        8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use Path::canonicalize() to resolve symlinks",
                         "Validate path is within allowed directory",
                         "Use realpath() equivalents to detect traversal"),
                        ("Do NOT concatenate user input directly into file paths",
                         "Do NOT rely on string replacement alone"),
                        ("Test: ../../../etc/passwd with path normalization",
                         "Verify path stays within allowed directory"),
                        ("https://owasp.org/www-community/attacks/Path_Traversal",
                         "https://cwe.mitre.org/data/definitions/22.html"),
                    ))

    def _scan_crypto(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CRYPTO_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUST-SEC-003", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.MEDIUM,
                        "CWE-327", "Use of Weak Cryptographic Algorithm",
                        "A02", "Cryptographic Failures",
                        7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use ring or rustls for TLS/cryptography",
                         "Use sha2 crate with SHA-256+ for hashing",
                         "Use rand::rngs::ThreadRng or rand::os::OsRng for secure randomness"),
                        ("Do NOT use md5 or sha1 for security purposes",
                         "Do NOT use rand::random() for cryptographic randomness"),
                        ("Run: cargo audit for vulnerable crypto dependencies",
                         "Use ring for cryptographic operations"),
                        ("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Cryptography/01-Testing_for_Weak_Cryptography",
                         "https://cwe.mitre.org/data/definitions/327.html"),
                    ))

    def _scan_logs(self, content: str, lines: List[str]) -> None:
        for pat, problem in _LOG_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUST-SEC-004", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.LOW,
                        "CWE-532", "Information Exposure Through Log",
                        "A09", "Security Logging and Monitoring Failures",
                        3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        ("Use structured logging (tracing, log crate)",
                         "Redact sensitive fields before logging",
                         "Use log level filtering from environment"),
                        ("Do NOT log passwords, tokens, or secrets",
                         "Do NOT use dbg!() in production code"),
                        ("Search: grep -r 'println.*password\\|dbg!' src/",
                         "Review all logging statements before deployment"),
                        ("https://cwe.mitre.org/data/definitions/532.html"),
                    ))

    def _scan_secrets(self, content: str, lines: List[str]) -> None:
        for pat, problem in _SECRET_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUST-SEC-005", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-798", "Use of Hard-coded Credentials",
                        "A07", "Identification and Authentication Failures",
                        7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use std::env::var() for secrets from environment",
                         "Use a secrets manager: AWS SM, HashiCorp Vault",
                         "Use dotenvy for local dev, not production secrets"),
                        ("Do NOT hardcode API keys, passwords, or tokens",
                         "Do NOT commit secrets to version control"),
                        ("Run: cargo secret scan or Gitleaks",
                         "Enable .gitignore for .env files",
                         "Use: git log -S 'password=' -- src/ to find leaks"),
                        ("https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                         "https://cwe.mitre.org/data/definitions/798.html"),
                    ))

    def _scan_cmd(self, content: str, lines: List[str]) -> None:
        for pat, problem in _CMD_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUST-SEC-006", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.CRITICAL,
                        "CWE-78", "OS Command Injection",
                        "A03", "Injection",
                        9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ("Pass arguments as separate slices, not concatenated strings",
                         "Validate and sanitize all user input",
                         "Use std::process::Command with explicit args array"),
                        ("Do NOT build command strings from user input",
                         "Do NOT use shell invocation unless absolutely necessary"),
                        ("Test: '; ls', '$(whoami)', '`id`'",
                         "Review all Command::new calls for input validation"),
                        ("https://owasp.org/www-community/attacks/Command_Injection",
                         "https://cwe.mitre.org/data/definitions/78.html"),
                    ))

    def _scan_tls(self, content: str, lines: List[str]) -> None:
        for pat, problem in _TLS_PATTERNS:
            for m in re.finditer(pat, content):
                line_no = _line_no(content, m.start())
                if self._is_real_code(lines, line_no):
                    self._findings.append(_f(
                        "RUST-SEC-007", line_no,
                        _snippet(lines, line_no, m.group()),
                        problem, SecuritySeverity.HIGH,
                        "CWE-295", "Improper Certificate Validation",
                        "A02", "Cryptographic Failures",
                        7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ("Use verified certificate stores, not custom certificates",
                         "Use rustls instead of native-tls for safer defaults",
                         "Never disable TLS verification in production"),
                        ("Do NOT use dangerously_set_root_certificates without careful review",
                         "Do NOT disable certificate verification"),
                        ("Test TLS configuration with testssl.sh or sslyze",
                         "Review all TLS/custom certificate usages"),
                        ("https://cwe.mitre.org/data/definitions/295.html"),
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
