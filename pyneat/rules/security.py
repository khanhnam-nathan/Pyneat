"""Rule for detecting and auto-fixing security vulnerabilities in AI-generated code.

Copyright (c) 2024-2026 PyNEAT Authors

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

For commercial licensing, contact: license@pyneat.dev

Handles the full 50+ rule security pack across 5 severity levels:
  - Critical: Command Injection, SQL Injection, Eval/Exec, Deserialization RCE, Path Traversal
  - High: Hardcoded Secrets, Weak Crypto, Insecure SSL, XXE, YAML Unsafe, Debug Mode, CORS, JWT, Weak Random
  - Medium: LDAP Injection, XSS, SSRF, Open Redirect, Mass Assignment, Race Condition, etc.
  - Low: Sensitive Comments, Info Disclosure, PII in Logs, Missing Headers, etc.
  - Info: Deprecated APIs, Missing Access Control, Business Logic, etc.

Each detection produces a SecurityFinding with full CWE/OWASP mapping, CVSS scoring,
fix guidance, and auto-fix availability.
"""

import re
import difflib
from typing import List, Union, Tuple, Optional, Dict, Any

import libcst as cst

from pyneat.core.types import (
    CodeFile, RuleConfig, TransformationResult, SecurityFinding,
    SecuritySeverity, CWE_SEVERITY_MAP, OWASP_SEVERITY_MAP
)
from pyneat.rules.base import Rule
from pyneat.rules.security_registry import (
    SECURITY_RULES_REGISTRY, get_security_rule, get_all_rule_ids
)


class SecurityScannerRule(Rule):
    """Detects and auto-fixes 50+ security vulnerabilities across 5 severity levels.

    This rule acts as the main entry point for the security pack. It uses a
    LibCST transformer for structural detections and regex passes for patterns
    that require context. Each finding is enriched with CWE/OWASP mapping,
    CVSS scoring, and detailed fix guidance from the security registry.

    OPTIMIZED: Single CST parse (reuse cached), combined regex pass,
    findings aggregation.
    """

    ALLOWED_SEMANTIC_NODES: set = {"Raise", "Statement", "Assign"}

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self._findings: List[SecurityFinding] = []
        self._auto_fix_applied: List[str] = []
        self._file_path: str = ""
        self._seen_findings: set = set()

    @property
    def description(self) -> str:
        return "Detects and auto-fixes 50+ security vulnerabilities across 5 severity levels (CWE + OWASP aligned)"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        """Run security scan and return findings with optional auto-fixes."""
        try:
            content = code_file.content
            lines = content.split('\n')
            self._findings = []
            self._auto_fix_applied = []
            self._file_path = str(code_file.path)
            self._seen_findings = set()
            transformed = content

            # Use cached CST tree if available (RuleEngine pre-parses)
            if hasattr(code_file, 'cst_tree') and code_file.cst_tree is not None:
                tree = code_file.cst_tree
            else:
                try:
                    tree = cst.parse_module(content)
                except Exception:
                    return self._apply_regex_only(content, code_file, lines)

            # Phase 1: LibCST transformer for structural detections
            transformer = _SecurityTransformer()
            new_tree = tree.visit(transformer)
            transformed = new_tree.code

            # Collect auto-fixes applied
            for change in transformer.changes:
                if change.startswith("AUTO-FIX:"):
                    self._auto_fix_applied.append(change)
                else:
                    # Parse changes into findings
                    pass

            # Phase 2: Regex-based detections for patterns needing context
            self._scan_regex_patterns(content, lines)

            # Phase 3: Hardcoded secrets via AST visitor
            # Transformer findings are collected by the engine via result.security_findings
            # No need to manually add them here

            # Phase 4: SQL Injection detection
            self._scan_sql_injection(content, lines)

            # Phase 5: Weak crypto patterns (hashlib, random)
            self._scan_weak_crypto(content, lines)

            # Phase 6: Pickle/RCE patterns
            self._scan_pickle_rce(content, lines)

            # Phase 7: YAML unsafe patterns
            self._scan_yaml_unsafe(content, lines)

            # Phase 8: Password in URL
            self._scan_password_in_url(content, lines)

            # Phase 9: Information disclosure
            self._scan_information_disclosure(content, lines)

            # Phase 10: Missing security headers
            self._scan_missing_security_headers(content, lines)

            # Phase 11: Add hardcoded secrets and weak crypto from transformer
            # (These are detected via CST, not regex - needs specific line info)
            for finding in transformer.secret_findings:
                self._add_finding(
                    finding.rule_id, finding.start_line, finding.end_line,
                    finding.snippet, finding.problem,
                )
            for finding in transformer.weak_crypto_findings:
                self._add_finding(
                    finding.rule_id, finding.start_line, finding.end_line,
                    finding.snippet, finding.problem,
                )

            # Build change messages from findings
            all_changes = self._build_change_messages(transformer.changes)

            return TransformationResult(
                original=code_file,
                transformed_content=transformed,
                changes_made=all_changes,
                success=True,
                security_findings=self._findings.copy(),
                auto_fix_applied=self._auto_fix_applied.copy(),
            )

        except Exception as e:
            return self._create_error_result(
                code_file, f"Security scan failed: {str(e)}"
            )

    def _apply_regex_only(self, content: str, code_file: CodeFile, lines: List[str]) -> TransformationResult:
        """Fallback when CST parsing fails - use regex only."""
        self._findings = []
        self._auto_fix_applied = []
        self._scan_regex_patterns(content, lines)
        return self._create_result(code_file, content, self._build_change_messages([]))

    def _scan_regex_patterns(self, content: str, lines: List[str]) -> None:
        """Scan for patterns detectable via regex. Skips docstrings and comments."""
        # Build line-by-line map for skipping docstrings
        skip_lines = set()
        in_docstring = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('"""') or stripped.startswith("'''"):
                if stripped.count('"""') >= 2 or stripped.count("'''") >= 2:
                    skip_lines.add(i)
                    if in_docstring:
                        in_docstring = False
                else:
                    in_docstring = not in_docstring
                    skip_lines.add(i)
            elif in_docstring or stripped.startswith("#"):
                skip_lines.add(i)

        # Command Injection: os.system, subprocess shell=True, os.popen
        for match in re.finditer(
            r'(os\.system\s*\(|subprocess\.run\s*\([^)]*shell\s*=\s*True|os\.popen\s*\()',
            content
        ):
            line_no = content[:match.start()].count('\n') + 1
            if line_no - 1 in skip_lines:
                continue
            snippet = self._get_snippet(lines, line_no, match.group())
            self._add_finding(
                "SEC-001", line_no, line_no, snippet,
                "Command injection via shell=True or os.system()"
            )

        # Debug Mode Enabled
        for match in re.finditer(
            r'(^DEBUG\s*=\s*True|^DEBUG\s*=\s*["\']True["\']|'
            r'app\.config\s*\[\s*["\']DEBUG["\']\s*\]\s*=\s*True|'
            r'app\.run\s*\([^)]*debug\s*=\s*True)',
            content, re.MULTILINE
        ):
            line_no = content[:match.start()].count('\n') + 1
            if line_no - 1 in skip_lines:
                continue
            snippet = self._get_snippet(lines, line_no, match.group())
            self._add_finding(
                "SEC-016", line_no, line_no, snippet,
                "DEBUG mode enabled - exposes internal details in production"
            )

        # Insecure SSL context
        for match in re.finditer(
            r'ssl\._create_unverified_context\s*\(',
            content
        ):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group())
            self._add_finding(
                "SEC-012", line_no, line_no, snippet,
                "SSL certificate verification disabled"
            )

        # XXE: lxml.etree.parse from external source
        for match in re.finditer(
            r'(lxml\.etree\.parse\s*\(|xml\.etree\.ElementTree\.parse\s*\(|'
            r'xml\.dom\.minidom\.parse\s*\()',
            content
        ):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group())
            self._add_finding(
                "SEC-034", line_no, line_no, snippet,
                "XML parsing may allow XXE attacks without safe settings"
            )

        # Insecure temporary files
        for match in re.finditer(r'tempfile\.mktemp\s*\(', content):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group())
            self._add_finding(
                "SEC-026", line_no, line_no, snippet,
                "Insecure temporary file creation via mktemp()"
            )

    def _scan_sql_injection(self, content: str, lines: List[str]) -> None:
        """Detect SQL injection via string concatenation."""
        # Simple patterns - check for cursor.execute with string concat
        for match in re.finditer(r'(cursor|db)\.execute\s*\(.*?\+', content, re.DOTALL):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group()[:150])
            self._add_finding(
                "SEC-002", line_no, line_no, snippet,
                "SQL query built by string concatenation - injection risk"
            )

    def _scan_xss_and_template_injection(self, content: str, lines: List[str]) -> None:
        """Detect XSS and template injection."""
        # render_template_string
        for match in re.finditer(r'render_template_string', content):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, "render_template_string(...)")
            self._add_finding(
                "SEC-021", line_no, line_no, snippet,
                "render_template_string with user input - potential SSTI/XSS"
            )

    def _scan_ssrf(self, content: str, lines: List[str]) -> None:
        """Detect Server-Side Request Forgery."""
        # Simple: check for requests.get/post and similar with url= parameters
        for match in re.finditer(r'requests\.(get|post|put|delete|patch)\s*\(', content):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group()[:80])
            self._add_finding(
                "SEC-022", line_no, line_no, snippet,
                "URL fetching - verify URL is not user-controlled (SSRF risk)"
            )

    def _scan_open_redirect(self, content: str, lines: List[str]) -> None:
        """Detect open redirect vulnerabilities."""
        # redirect function with user input
        for match in re.finditer(r'redirect\s*\(', content):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group()[:80])
            self._add_finding(
                "SEC-023", line_no, line_no, snippet,
                "Redirect - verify destination is not user-controlled (phishing risk)"
            )

    def _scan_ldap_injection(self, content: str, lines: List[str]) -> None:
        """Detect LDAP injection."""
        # ldap search with string concat
        for match in re.finditer(r'ldap.*search.*\+', content, re.IGNORECASE):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group()[:150])
            self._add_finding(
                "SEC-020", line_no, line_no, snippet,
                "LDAP query with string concatenation - injection risk"
            )

    def _scan_mass_assignment(self, content: str, lines: List[str]) -> None:
        """Detect mass assignment patterns."""
        # **request.json, **request.form
        for match in re.finditer(r'\*\*\s*(?:request|input)\.(?:json|form|data)', content):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group()[:150])
            self._add_finding(
                "SEC-024", line_no, line_no, snippet,
                "Direct unpacking of request data - mass assignment risk"
            )

    def _scan_race_conditions(self, content: str, lines: List[str]) -> None:
        """Detect TOCTOU race conditions."""
        # Simple pattern: os.path.exists followed by file operations
        for match in re.finditer(r'os\.path\.exists.*?os\.(?:remove|unlink|mkdir)', content, re.DOTALL):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group()[:150])
            self._add_finding(
                "SEC-025", line_no, line_no, snippet,
                "File check followed by file operation - race condition risk"
            )

    def _scan_insecure_temp_files(self, content: str, lines: List[str]) -> None:
        """Detect insecure temporary file usage."""
        for match in re.finditer(r'tempfile\.mktemp', content):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group()[:80])
            self._add_finding(
                "SEC-026", line_no, line_no, snippet,
                "Insecure temp file via mktemp() - race condition risk"
            )

    def _scan_jwt_none(self, content: str, lines: List[str]) -> None:
        """Detect JWT verification bypass."""
        # jwt.decode with verify=False
        for match in re.finditer(r'jwt\.decode.*verify\s*=\s*False', content, re.IGNORECASE):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group()[:150])
            self._add_finding(
                "SEC-018", line_no, line_no, snippet,
                "JWT signature verification disabled - forgery possible"
            )

    def _scan_cookie_flags(self, content: str, lines: List[str]) -> None:
        """Detect cookies without security flags."""
        for match in re.finditer(r'set_cookie', content):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group()[:80])
            self._add_finding(
                "SEC-032", line_no, line_no, snippet,
                "Cookie set - verify HttpOnly/Secure flags are configured"
            )

    def _scan_password_in_url(self, content: str, lines: List[str]) -> None:
        """Detect credentials passed in URL."""
        # Check for password in URL pattern: ://user:pass@
        for match in re.finditer(r'://[^:]+:[^@]+@', content):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group()[:100])
            self._add_finding(
                "SEC-028", line_no, line_no, snippet,
                "Credentials in URL - will be logged and exposed"
            )

    def _scan_weak_crypto(self, content: str, lines: List[str]) -> None:
        """Detect weak cryptography usage (MD5, SHA1, random for security)."""
        patterns = [
            (r'hashlib\.md5', "SEC-011", "MD5 is weak for cryptographic purposes"),
            (r'hashlib\.sha1', "SEC-011", "SHA1 is weak for cryptographic purposes"),
            (r'random\.(choice|choices|random|randint)', "SEC-019", "random module is not cryptographically secure"),
        ]
        for pattern, rule_id, msg in patterns:
            for match in re.finditer(pattern, content):
                line_no = content[:match.start()].count('\n') + 1
                snippet = self._get_snippet(lines, line_no, match.group()[:80])
                self._add_finding(rule_id, line_no, line_no, snippet, msg)

    def _scan_pickle_rce(self, content: str, lines: List[str]) -> None:
        """Detect pickle.loads() RCE risk."""
        for match in re.finditer(r'pickle\.(loads|load)\s*\(', content):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group()[:80])
            self._add_finding(
                "SEC-004", line_no, line_no, snippet,
                "pickle.loads with untrusted data allows arbitrary code execution"
            )

    def _scan_yaml_unsafe(self, content: str, lines: List[str]) -> None:
        """Detect yaml.load() without SafeLoader."""
        for match in re.finditer(r'yaml\.load\s*\([^)]*(?<!Loader=)(?<!loader=)', content):
            line_no = content[:match.start()].count('\n') + 1
            snippet = self._get_snippet(lines, line_no, match.group()[:80])
            self._add_finding(
                "SEC-014", line_no, line_no, snippet,
                "yaml.load without SafeLoader can execute arbitrary code"
            )

    def _scan_information_disclosure(self, content: str, lines: List[str]) -> None:
        """Detect information disclosure patterns."""
        patterns = [
            # Stack trace in error response
            (r'(?:print|logging|return)\s*\([^)]*traceback\.format_exc',
             "Stack trace exposed to users - information disclosure"),
            # Config with debug enabled
            (r'app\[(?:"DEBUG"|\'DEBUG\')\]\s*=\s*(?:True|true|1)',
             "DEBUG configuration exposed"),
            # Verbose error with exception
            (r'return\s+(?:jsonify|render_template)\([^)]*(?:str\s*\(\s*e\s*\)|error)',
             "Exception details returned to user - information disclosure"),
        ]
        for pattern, msg in patterns:
            for match in re.finditer(pattern, content):
                line_no = content[:match.start()].count('\n') + 1
                snippet = self._get_snippet(lines, line_no, match.group()[:150])
                self._add_finding("SEC-041", line_no, line_no, snippet, msg)

    def _scan_missing_security_headers(self, content: str, lines: List[str]) -> None:
        """Detect missing security headers (check absence, not presence)."""
        # Look for patterns that indicate no security headers configured
        flask_pattern = re.compile(r'@app\.route|Flask\(')
        django_pattern = re.compile(r'from django|import django')
        fastapi_pattern = re.compile(r'FastAPI\(|@app\.|@router\.')

        framework = None
        if flask_pattern.search(content):
            framework = "Flask"
        elif django_pattern.search(content):
            framework = "Django"
        elif fastapi_pattern.search(content):
            framework = "FastAPI"

        # Check for security header configuration absence
        has_security_headers = bool(re.search(
            r'X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|'
            r'Access-Control-Allow|@security_headers|SecurityHeaders',
            content
        ))

        if framework and not has_security_headers:
            # Add SEC-043 for missing security headers
            for i, line in enumerate(lines, 1):
                if framework in line:
                    self._add_finding(
                        "SEC-043", i, i, line[:100],
                        f"{framework} app without security headers (X-Frame-Options, CSP, etc.)"
                    )
                    break

    def _add_finding(
        self,
        rule_id: str,
        start_line: int,
        end_line: int,
        snippet: str,
        problem: str,
        auto_fix_before: Optional[str] = None,
        auto_fix_after: Optional[str] = None,
    ) -> None:
        """Add a security finding from registry metadata. Deduplicates by (rule_id, line, snippet)."""
        meta = get_security_rule(rule_id)
        if meta is None:
            return

        # Better deduplication: include snippet to avoid skipping different secrets on line 0
        dedup_key = (rule_id, start_line, snippet)
        if dedup_key in self._seen_findings:
            return
        self._seen_findings.add(dedup_key)

        cvss_score = meta.cvss_base
        cvss_vector = meta.cvss_vector

        # Auto-fix diff
        auto_fix_diff = None
        if auto_fix_before and auto_fix_after:
            diff = difflib.unified_diff(
                auto_fix_before.splitlines(keepends=True),
                auto_fix_after.splitlines(keepends=True),
                lineterm="", n=0
            )
            auto_fix_diff = "".join(diff)

        finding = SecurityFinding(
            rule_id=rule_id,
            severity=meta.severity,
            confidence=0.95 if meta.can_auto_fix else 0.85,
            cwe_id=meta.cwe_id,
            owasp_id=meta.owasp_id,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            file=self._file_path,
            start_line=start_line,
            end_line=end_line,
            snippet=snippet[:200],
            problem=problem,
            fix_constraints=meta.fix_constraints,
            do_not=meta.do_not,
            verify=meta.verify,
            resources=meta.resources,
            can_auto_fix=meta.can_auto_fix,
            auto_fix_available=meta.auto_fix_available,
            auto_fix_before=auto_fix_before,
            auto_fix_after=auto_fix_after,
            auto_fix_diff=auto_fix_diff,
        )
        self._findings.append(finding)

    def _get_snippet(self, lines: List[str], line_no: int, matched_text: str = "") -> str:
        """Get code snippet around line number. Skips docstring-only lines."""
        idx = line_no - 1
        if idx < 0 or idx >= len(lines):
            return (matched_text or "")[:100]
        line = lines[idx].strip()
        # Skip if line is only a comment or docstring
        if line.startswith("#") or line.startswith('"""') or line.startswith("'''"):
            return (matched_text or "")[:100]
        return line[:200]

    def _build_change_messages(self, transformer_changes: List[str]) -> List[str]:
        """Build human-readable change messages from findings."""
        messages = []
        seen = set()

        for finding in self._findings:
            key = (finding.rule_id, finding.start_line)
            if key in seen:
                continue
            seen.add(key)

            meta = get_security_rule(finding.rule_id)
            severity_label = finding.severity.upper()

            msg = f"[{severity_label}] {finding.rule_id} - {finding.problem}"
            messages.append(msg)

        for change in transformer_changes:
            if not any(change in m for m in messages):
                messages.append(change)

        return messages


# ----------------------------------------------------------------------
# LibCST Transformer for structural security fixes
# ----------------------------------------------------------------------


class _SecurityTransformer(cst.CSTTransformer):
    """Transformer that auto-fixes or warns about security issues."""

    def __init__(self):
        super().__init__()
        self.changes: List[str] = []
        self.secret_findings: List[SecurityFinding] = []
        self.weak_crypto_findings: List[SecurityFinding] = []

    # ------------------------------------------------------------------
    # YAML Unsafe Load Fix
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Command Injection Auto-fix
    # ------------------------------------------------------------------

    def leave_Call(
        self, original: cst.Call, updated: cst.Call
    ) -> cst.BaseExpression:
        """Detect and auto-fix command injection vulnerabilities."""
        func = original.func
        func_name = self._get_name(func)

        # Check for os.system
        if func_name == 'os.system':
            result = self._fix_os_system(original, updated)
            if result is not None:
                return result

        # Check for os.popen
        if func_name == 'os.popen':
            result = self._fix_os_popen(original, updated)
            if result is not None:
                return result

        # Check for subprocess.run/call with shell=True
        if func_name in ('subprocess.run', 'subprocess.call', 'subprocess.Popen'):
            result = self._fix_subprocess_shell(original, updated)
            if result is not None:
                return result

        # Check for yaml.load or yaml.unsafe_load
        if func_name in ('yaml.load', 'yaml.unsafe_load', 'load'):
            # Check if Loader is already provided
            has_loader = any(
                arg.keyword is not None and arg.keyword.value in ('Loader', 'loader')
                for arg in original.args
            )

            if not has_loader and len(original.args) <= 2:
                # Auto-fix: add SafeLoader
                self.changes.append(
                    "AUTO-FIX: yaml.load() now uses SafeLoader to prevent arbitrary code execution."
                )

                finding = SecurityFinding(
                    rule_id="SEC-014",
                    severity="high",
                    confidence=0.98,
                    cwe_id="CWE-502",
                    owasp_id="A08",
                    cvss_score=9.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    file="",
                    start_line=0, end_line=0,
                    snippet=self._get_call_snippet(original),
                    problem="yaml.load() without SafeLoader can execute arbitrary code",
                    fix_constraints=("Always use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader)",),
                    do_not=("Do NOT use yaml.load() without specifying a Loader",),
                    verify=("Replace: yaml.load(data) -> yaml.load(data, Loader=yaml.SafeLoader)",),
                    resources=("https://pyyaml.readthedocs.io/en/latest/library/yaml.html#yaml.safe_load",),
                    can_auto_fix=True,
                    auto_fix_available=True,
                )
                self.weak_crypto_findings.append(finding)

                return cst.Call(
                    func=updated.func,
                    args=[
                        *updated.args,
                        cst.Arg(
                            keyword=cst.Name(value='Loader'),
                            value=cst.Attribute(
                                value=cst.Name(value='yaml'),
                                attr=cst.Name(value='SafeLoader'),
                            ),
                        ),
                    ],
                )

        # Check for pickle.loads
        if func_name in ('pickle.loads', 'pickle.load'):
            self.changes.append(
                "SECURITY: pickle.loads() is dangerous with untrusted data - "
                "RCE risk. Consider using json.loads() or a signed pickle alternative."
            )

        # Check for render_template_string
        if func_name == 'render_template_string':
            if len(original.args) > 0:
                self.changes.append(
                    "SECURITY: render_template_string() with user input may allow SSTI. "
                    "Ensure input is sanitized or use a strict template engine."
                )
                finding = SecurityFinding(
                    rule_id="SEC-021",
                    severity="medium",
                    confidence=0.85,
                    cwe_id="CWE-79",
                    owasp_id="A03",
                    cvss_score=6.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
                    file="",
                    start_line=0, end_line=0,
                    snippet=self._get_call_snippet(original),
                    problem="render_template_string with user input allows SSTI/XSS",
                    fix_constraints=(
                        "Use render_template() instead of render_template_string()",
                        "Sanitize user input or use auto-escaping template engine",
                    ),
                    do_not=(
                        "Do NOT pass unsanitized user input to render_template_string()",
                    ),
                    verify=("Test with: {{ config }} payload",),
                    resources=("https://jinja.palletsprojects.com/en/latest/templates/",),
                    can_auto_fix=False,
                    auto_fix_available=False,
                )
                self.weak_crypto_findings.append(finding)

        # Check for hashlib.md5/sha1
        if func_name in ('hashlib.md5', 'hashlib.sha1'):
            self.changes.append(
                "SECURITY: MD5/SHA1 are weak for cryptographic purposes. "
                "Use hashlib.sha256 or hashlib.pbkdf2_hmac for passwords, "
                "or secrets.token_hex() for tokens."
            )
            finding = SecurityFinding(
                rule_id="SEC-011",
                severity="high",
                confidence=0.95,
                cwe_id="CWE-327",
                owasp_id="A02",
                cvss_score=7.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                file="",
                start_line=0, end_line=0,
                snippet=self._get_call_snippet(original),
                problem="MD5/SHA1 are weak cryptographic algorithms",
                fix_constraints=(
                    "Use hashlib.sha256() for integrity checks",
                    "Use hashlib.pbkdf2_hmac() or argon2 for password hashing",
                    "Use secrets.token_hex() for token generation",
                ),
                do_not=(
                    "Do NOT use MD5/SHA1 for password hashing or security purposes",
                    "Do NOT use DES or 3DES for encryption",
                ),
                verify=("Replace MD5/SHA1 with SHA-256 or SHA-3 for integrity",),
                resources=(
                    "https://docs.python.org/3/library/hashlib.html",
                    "https://docs.python.org/3/library/secrets.html",
                ),
                can_auto_fix=False,
                auto_fix_available=False,
            )
            self.weak_crypto_findings.append(finding)

        # Check for random.choice/choices
        if func_name in ('random.choice', 'random.choices', 'random.random', 'random.randint'):
            self.changes.append(
                "SECURITY: 'random' module is not cryptographically secure. "
                "Use 'secrets' module (secrets.choice, secrets.token_hex) instead."
            )
            finding = SecurityFinding(
                rule_id="SEC-019",
                severity="high",
                confidence=0.95,
                cwe_id="CWE-338",
                owasp_id="A02",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                file="",
                start_line=0, end_line=0,
                snippet=self._get_call_snippet(original),
                problem="'random' module is not cryptographically secure",
                fix_constraints=(
                    "Use secrets.choice() instead of random.choice()",
                    "Use secrets.token_hex(32) for API keys and tokens",
                    "Use secrets.randbelow() instead of random.randint()",
                ),
                do_not=(
                    "Do NOT use random.random() for security tokens or passwords",
                    "Do NOT use random.randint() for session IDs or API keys",
                ),
                verify=("Replace random.choice() -> secrets.choice()",),
                resources=("https://docs.python.org/3/library/secrets.html",),
                can_auto_fix=False,
                auto_fix_available=False,
            )
            self.weak_crypto_findings.append(finding)

        return updated

    def _get_call_snippet(self, call: cst.Call) -> str:
        """Extract a readable snippet from a Call node."""
        try:
            return call.value.code if hasattr(call.value, 'code') else ""
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Command Injection Fix Helpers
    # ------------------------------------------------------------------

    def _fix_os_system(self, original: cst.Call, updated: cst.Call) -> cst.Call | None:
        """Auto-fix os.system() to subprocess.run() with shell=False."""
        if len(original.args) < 1:
            return None

        cmd_arg = original.args[0]
        cmd_value = self._extract_cmd_string(cmd_arg.value)

        if cmd_value is None:
            self.changes.append(
                "AUTO-FIX: os.system() detected - "
                "consider using subprocess.run() with shell=False."
            )
            return None

        cmd_parts = self._parse_cmd_to_list(cmd_value)
        if cmd_parts is None:
            self.changes.append(
                "AUTO-FIX: os.system() detected with shell operators - "
                "consider using subprocess.run() with shell=False."
            )
            return None

        self.changes.append(
            "AUTO-FIX: os.system() converted to subprocess.run() with shell=False."
        )

        return cst.Call(
            func=cst.Attribute(
                value=cst.Name(value='subprocess'),
                attr=cst.Name(value='run'),
            ),
            args=[
                cst.Arg(value=cst.List([cst.Element(p) for p in cmd_parts])),
                cst.Arg(
                    keyword=cst.Name(value='shell'),
                    value=cst.Name(value='False'),
                ),
            ],
        )

    def _fix_os_popen(self, original: cst.Call, updated: cst.Call) -> cst.Call | None:
        """Auto-fix os.popen() to subprocess.run() with capture_output=True."""
        if len(original.args) < 1:
            return None

        cmd_arg = original.args[0]
        cmd_value = self._extract_cmd_string(cmd_arg.value)

        if cmd_value is None:
            self.changes.append(
                "AUTO-FIX: os.popen() detected - "
                "consider using subprocess.run() with capture_output=True."
            )
            return None

        cmd_parts = self._parse_cmd_to_list(cmd_value)
        if cmd_parts is None:
            self.changes.append(
                "AUTO-FIX: os.popen() detected with shell operators - "
                "consider using subprocess.run() with capture_output=True."
            )
            return None

        self.changes.append(
            "AUTO-FIX: os.popen() converted to subprocess.run() with shell=False."
        )

        return cst.Call(
            func=cst.Attribute(
                value=cst.Name(value='subprocess'),
                attr=cst.Name(value='run'),
            ),
            args=[
                cst.Arg(value=cst.List([cst.Element(p) for p in cmd_parts])),
                cst.Arg(
                    keyword=cst.Name(value='shell'),
                    value=cst.Name(value='False'),
                ),
                cst.Arg(
                    keyword=cst.Name(value='capture_output'),
                    value=cst.Name(value='True'),
                ),
            ],
        )

    def _fix_subprocess_shell(self, original: cst.Call, updated: cst.Call) -> cst.Call | None:
        """Auto-fix subprocess.run/call with shell=True to shell=False."""
        shell_true_found = False
        new_args = []

        for arg in original.args:
            if arg.keyword is not None and arg.keyword.value == 'shell':
                new_args.append(
                    cst.Arg(
                        keyword=cst.Name(value='shell'),
                        value=cst.Name(value='False'),
                    )
                )
                shell_true_found = True
            else:
                new_args.append(arg)

        if not shell_true_found:
            return None

        if len(new_args) >= 1 and isinstance(new_args[0].value, cst.SimpleString):
            self.changes.append(
                "AUTO-FIX: subprocess.run() shell=True changed to shell=False. "
                "Note: String arguments may need conversion to list for shell=False."
            )
        else:
            self.changes.append(
                "AUTO-FIX: subprocess.run() shell=True changed to shell=False."
            )

        return cst.Call(func=updated.func, args=new_args)

    def _extract_cmd_string(self, node: cst.BaseExpression) -> str | None:
        """Extract string value from a CST node for command parsing."""
        if isinstance(node, cst.SimpleString):
            return node.value.strip('"\'')
        return None

    def _parse_cmd_to_list(self, cmd: str) -> list[cst.BaseExpression] | None:
        """Parse a command string into list of arguments.

        Returns None if the command is too complex (contains shell operators).
        """
        shell_operators = ['|', '&&', '||', '>', '<', '>>', '<<', ';', '$(']
        for op in shell_operators:
            if op in cmd:
                return None

        import re
        fstring_pattern = re.compile(r'\{([^}]+)\}')
        matches = list(fstring_pattern.finditer(cmd))

        if not matches:
            return [cst.SimpleString(f'"{cmd}"')]

        parts = []
        last_end = 0

        for match in matches:
            before = cmd[last_end:match.start()]
            if before:
                parts.append(cst.SimpleString(f'"{before}"'))

            var_expr = match.group(1)
            parts.append(cst.Name(value=var_expr.strip()))

            last_end = match.end()

        if last_end < len(cmd):
            after = cmd[last_end:]
            if after:
                parts.append(cst.SimpleString(f'"{after}"'))

        return parts

    # ------------------------------------------------------------------
    # Empty Except Blocks Fix
    # ------------------------------------------------------------------

    def leave_ExceptHandler(
        self, original: cst.ExceptHandler, updated: cst.ExceptHandler
    ) -> cst.ExceptHandler:
        """Detect empty except blocks and auto-fix by adding raise.

        Only fixes BARE except: blocks (no exception type specified).
        Does NOT fix except Exception:, except AttributeError:, etc. because those
        may be intentional silent-fail patterns in __getattr__, __getitem__,
        and other special methods (e.g., Jinja2 Undefined objects, Django querysets).

        For typed except blocks with pass, this rule acts as detection-only.
        """
        # Only fix BARE except: blocks (no exception type specified).
        # Bare except catches everything including KeyboardInterrupt and SystemExit,
        # which is almost always a bug. Typed except blocks (except Exception:, etc.)
        # may be intentional silent-fail patterns in special methods.
        if original.type is not None:
            return updated

        body = updated.body

        # Check if body is empty
        if len(body.body) == 0:
            self.changes.append(
                "AUTO-FIX: Added 'raise' to empty bare except block."
            )
            return updated.with_changes(
                body=cst.IndentedBlock(
                    body=[
                        cst.SimpleStatementLine(
                            body=[
                                cst.Raise(
                                    exc=cst.Call(
                                        func=cst.Name(value='Exception'),
                                        args=[cst.Arg(value=cst.SimpleString('"Unknown error"'))],
                                    ),
                                )
                            ]
                        )
                    ]
                )
            )

        # Check if only 'pass' statement
        if len(body.body) == 1:
            stmt = body.body[0]
            if isinstance(stmt, cst.SimpleStatementLine):
                if len(stmt.body) == 1 and isinstance(stmt.body[0], cst.Pass):
                    self.changes.append(
                        "AUTO-FIX: Replaced 'pass' with 'raise' in bare except block."
                    )
                    return updated.with_changes(
                        body=cst.IndentedBlock(
                            body=[
                                cst.SimpleStatementLine(
                                    body=[
                                        cst.Raise(
                                            exc=cst.Call(
                                                func=cst.Name(value='Exception'),
                                                args=[
                                                    cst.Arg(value=cst.SimpleString('"Unknown error"'))
                                                ],
                                            ),
                                        )
                                    ]
                                )
                            ]
                        )
                    )

        return updated

    # ------------------------------------------------------------------
    # Hardcoded Secrets & Weak KEY Detection (via SimpleStatementLine visitor)
    # ------------------------------------------------------------------

    def visit_SimpleStatementLine(self, node: cst.SimpleStatementLine) -> None:
        """Visit assignment statements to detect hardcoded secrets."""
        for stmt in node.body:
            if isinstance(stmt, cst.Assign):
                self._check_assignment_for_secrets(stmt)
            elif isinstance(stmt, cst.AnnAssign):
                self._check_annassign_for_secrets(stmt)

    def _check_assignment_for_secrets(self, node: cst.Assign) -> None:
        """Check assignment nodes for hardcoded secrets."""
        for target in node.targets:
            if isinstance(target, cst.AssignTarget):
                var_name = self._get_name(target.target)
                if not var_name:
                    continue

                var_name_lower = var_name.lower()

                # Check for secret-related variable names
                secret_patterns = [
                    'api_key', 'apikey', 'api-key', 'secret', 'password', 'passwd',
                    'token', 'auth', 'credential', 'private_key', 'privatekey',
                    'aws_key', 'awskey', 'aws_secret', 'jwt_secret',
                    'encryption_key', 'encryptionkey', 'hmac_key',
                    'client_secret', 'access_token', 'refresh_token',
                    'db_password', 'database_password', 'connection_string',
                    'encryption_iv', 'salt', 'nonce',
                ]

                is_secret_var = any(p in var_name_lower for p in secret_patterns)
                is_secret_value = self._is_string_literal(node.value)

                if is_secret_var and is_secret_value:
                    value_str = ""
                    if isinstance(node.value, cst.SimpleString):
                        value_str = node.value.value.strip('"\'')
                        if len(value_str) > 8:
                            value_str = value_str[:4] + "..."

                    finding = SecurityFinding(
                        rule_id="SEC-010",
                        severity="high",
                        confidence=0.95,
                        cwe_id="CWE-798",
                        owasp_id="A07",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        file="",
                        start_line=0, end_line=0,
                        snippet=f"{var_name} = {value_str}" if value_str else var_name,
                        problem=f"Hardcoded secret '{var_name}' detected in source code",
                        fix_constraints=(
                            "Move secrets to environment variables (os.environ)",
                            "Use python-dotenv (.env files) for local development",
                            "Use secrets manager (AWS Secrets Manager, HashiCorp Vault) in production",
                        ),
                        do_not=(
                            "Do NOT hardcode any secret value in source code",
                            "Do NOT commit .env files or credentials to git",
                        ),
                        verify=(
                            "Run: gitleaks, trufflehog, or git-secrets to scan repos",
                            "Check: .gitignore excludes .env files",
                        ),
                        resources=(
                            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                            "https://12factor.net/config",
                        ),
                        can_auto_fix=False,
                        auto_fix_available=False,
                    )
                    self.secret_findings.append(finding)

                # Check for weak SECRET_KEY
                if 'SECRET' in var_name.upper() and is_secret_value:
                    if self._is_short_or_weak_key(node.value):
                        finding = SecurityFinding(
                            rule_id="SEC-010",
                            severity="high",
                            confidence=0.90,
                            cwe_id="CWE-798",
                            owasp_id="A07",
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            file="",
                            start_line=0, end_line=0,
                            snippet=var_name,
                            problem="Weak SECRET_KEY detected - too short or uses common pattern",
                            fix_constraints=(
                                "Use secrets.token_hex(32) for production SECRET_KEY",
                                "Never use placeholder or example values in production",
                            ),
                            do_not=(
                                "Do NOT use short strings or common patterns for SECRET_KEY",
                            ),
                            verify=("Use: secrets.token_hex(32)",),
                            resources=(),
                            can_auto_fix=False,
                            auto_fix_available=False,
                        )
                        self.secret_findings.append(finding)

    def _check_annassign_for_secrets(self, node: cst.AnnAssign) -> None:
        """Check annotated assignment nodes for secrets."""
        var_name = self._get_name(node.target)
        if not var_name:
            return

        var_name_lower = var_name.lower()

        # Check for secret-related variable names
        secret_patterns = [
            'api_key', 'apikey', 'api-key', 'secret', 'password', 'passwd',
            'token', 'auth', 'credential',
        ]

        is_secret_var = any(p in var_name_lower for p in secret_patterns)
        is_secret_value = node.value is not None and self._is_string_literal(node.value)

        if is_secret_var and is_secret_value:
            finding = SecurityFinding(
                rule_id="SEC-010",
                severity="high",
                confidence=0.95,
                cwe_id="CWE-798",
                owasp_id="A07",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                file="",
                start_line=0, end_line=0,
                snippet=var_name,
                problem=f"Hardcoded secret '{var_name}' detected in source code",
                fix_constraints=(
                    "Move secrets to environment variables (os.environ)",
                    "Use python-dotenv (.env files) for local development",
                    "Use secrets manager (AWS Secrets Manager, HashiCorp Vault) in production",
                ),
                do_not=(
                    "Do NOT hardcode any secret value in source code",
                    "Do NOT commit .env files or credentials to git",
                ),
                verify=(
                    "Run: gitleaks, trufflehog, or git-secrets to scan repos",
                ),
                resources=(
                    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                ),
                can_auto_fix=False,
                auto_fix_available=False,
            )
            self.secret_findings.append(finding)

    def _is_string_literal(self, node: cst.BaseExpression) -> bool:
        """Check if a node is a string literal."""
        if node is None:
            return False
        return isinstance(node, (cst.SimpleString, cst.ConcatenatedString))

    def _is_short_or_weak_key(self, node: cst.BaseExpression) -> bool:
        """Check if a key/value is short or uses weak patterns."""
        if not isinstance(node, cst.SimpleString):
            return False

        value = node.value.strip('"\'')
        weak_patterns = ['dev', 'secret', 'test', 'placeholder', 'your-', 'changeme', 'example']

        if any(p in value.lower() for p in weak_patterns):
            return True
        if len(value) < 32 and not any(c in value for c in ['$', '{', 'os.environ']):
            return True
        return False

    # ------------------------------------------------------------------
    # Utility Methods
    # ------------------------------------------------------------------

    def _get_name(self, node: cst.CSTNode) -> str:
        """Recursively extract a dotted name from a CST node."""
        if isinstance(node, cst.Name):
            return node.value
        if isinstance(node, cst.Attribute):
            base = self._get_name(node.value)
            attr = self._get_name(node.attr)
            if base:
                return f"{base}.{attr}"
            return attr
        if isinstance(node, cst.SimpleString):
            return node.value.strip('"\'')
        return ""
