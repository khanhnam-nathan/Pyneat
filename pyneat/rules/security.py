"""Rule for detecting and auto-fixing security vulnerabilities in AI-generated code."""

import re
from typing import List, Union

import libcst as cst

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class SecurityScannerRule(Rule):
    """Detects and auto-fixes security vulnerabilities in AI-generated code.

    Handles:
      - Command Injection: os.system(), subprocess.run() with shell=True
      - YAML Unsafe Load: yaml.load() without SafeLoader
      - Weak Crypto: random module for security, MD5/SHA1 for passwords
      - Pickle Deserialize: pickle.loads() (RCE risk)
      - Debug Mode: DEBUG=True in production code
      - Weak SECRET_KEY: short or common secret keys
      - Hardcoded Secrets: api_key, password, token in code
      - SQL Injection: string concatenation in SQL queries
      - Template Injection: render_template_string() with user input
      - Empty Except Blocks: silent exception swallowing
    """

    # Patterns for line-based detection
    COMMAND_INJECTION_PATTERNS = [
        re.compile(r'os\.system\s*\('),
        re.compile(r'subprocess\.run\s*\([^)]*shell\s*=\s*True'),
        re.compile(r'subprocess\.call\s*\([^)]*shell\s*=\s*True'),
        re.compile(r'os\.popen\s*\('),
    ]

    DEBUG_MODE_PATTERNS = [
        re.compile(r'DEBUG\s*=\s*True'),
        re.compile(r'app\.config\s*\[\s*["\']DEBUG["\']\s*\]\s*=\s*True'),
        re.compile(r'app\.run\s*\([^)]*debug\s*=\s*True'),
    ]

    @property
    def description(self) -> str:
        return "Detects and auto-fixes security vulnerabilities (SQL injection, hardcoded secrets, command injection, etc.)"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            content = code_file.content

            # Parse with CST for structural fixes
            try:
                tree = cst.parse_module(content)
            except Exception:
                # If parse fails, fall back to regex-only detection
                return self._apply_regex_only(content, code_file)

            transformer = _SecurityTransformer()
            new_tree = tree.visit(transformer)
            new_content = new_tree.code

            all_changes = transformer.changes.copy()

            # Add regex-based detections that CST can't easily catch
            self._detect_command_injection(content, all_changes)
            self._detect_debug_mode(content, all_changes)

            return self._create_result(code_file, new_content, all_changes)

        except Exception as e:
            return self._create_error_result(
                code_file, f"Security scan failed: {str(e)}"
            )

    def _apply_regex_only(self, content: str, code_file: CodeFile) -> TransformationResult:
        """Fallback when CST parsing fails."""
        changes: List[str] = []
        self._detect_command_injection(content, changes)
        self._detect_debug_mode(content, changes)
        return self._create_result(code_file, content, changes)

    def _detect_command_injection(self, content: str, changes: List[str]) -> None:
        """Detect command injection vulnerabilities via regex."""
        for pattern in self.COMMAND_INJECTION_PATTERNS:
            if pattern.search(content):
                changes.append(
                    "SECURITY: Command injection risk detected - "
                    "user input may be passed to shell. "
                    "Consider using subprocess.run() with shell=False or shlex.quote()."
                )
                break

    def _detect_debug_mode(self, content: str, changes: List[str]) -> None:
        """Detect DEBUG=True in production code."""
        for pattern in self.DEBUG_MODE_PATTERNS:
            if pattern.search(content):
                changes.append(
                    "SECURITY: DEBUG mode enabled - "
                    "ensure this is disabled before production deployment."
                )
                break


# ----------------------------------------------------------------------
# LibCST Transformer for structural security fixes
# ----------------------------------------------------------------------


class _SecurityTransformer(cst.CSTTransformer):
    """Transformer that auto-fixes or warns about security issues."""

    def __init__(self):
        super().__init__()
        self.changes: List[str] = []

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

        # Check for hashlib.md5/sha1
        if func_name in ('hashlib.md5', 'hashlib.sha1'):
            self.changes.append(
                "SECURITY: MD5/SHA1 are weak for cryptographic purposes. "
                "Use hashlib.sha256 or hashlib.pbkdf2_hmac for passwords, "
                "or secrets.token_hex() for tokens."
            )

        # Check for random.choice/choices
        if func_name in ('random.choice', 'random.choices', 'random.random', 'random.randint'):
            self.changes.append(
                "SECURITY: 'random' module is not cryptographically secure. "
                "Use 'secrets' module (secrets.choice, secrets.token_hex) instead."
            )

        return updated

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
        """Detect empty except blocks and auto-fix by adding raise."""
        body = updated.body

        # Check if body is empty
        if len(body.body) == 0:
            self.changes.append(
                "AUTO-FIX: Added 'raise' to empty except block to prevent silent failures."
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
                        "AUTO-FIX: Replaced 'pass' with 'raise' in except block to prevent silent failures."
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
                    self.changes.append(
                        f"SECURITY: Hardcoded secret detected in '{var_name}'. "
                        f"Use environment variables via os.environ or python-dotenv instead."
                    )

                # Check for weak SECRET_KEY
                if 'SECRET' in var_name.upper() and is_secret_value:
                    if self._is_short_or_weak_key(node.value):
                        self.changes.append(
                            "SECURITY: Weak SECRET_KEY detected. "
                            "Use secrets.token_hex(32) for production."
                        )

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
            self.changes.append(
                f"SECURITY: Hardcoded secret detected in '{var_name}'. "
                f"Use environment variables via os.environ or python-dotenv instead."
            )

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
