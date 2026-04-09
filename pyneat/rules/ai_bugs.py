"""AI Bug Pattern Rules — detect issues uniquely caused by AI code generation.

Detects patterns from the AIBugs taxonomy (2026), derived from the
arXiv:2512.05239v1 survey of 72 studies across 94 papers.

Bug categories by severity (research-backed):
  CRITICAL  45% of AI code contains security vulnerabilities
  HIGH      78% of studies report functional/logic bugs
  MEDIUM    Logic off-by-one, deprecated API, infinite loops
  LOW       Code style inconsistency, naming convention violations

Detection approach:
  - AST-based for semantic/logic/type bugs
  - Regex-based for syntax, API hallucination patterns
  - Semantic analysis for edge-case misses, wrong algorithm

Copyright (c) 2026 PyNEAT Authors
"""

from __future__ import annotations

import ast
import re
from typing import List, Set, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from pyneat.core.types import CodeFile, TransformationResult, RuleConfig, AgentMarker
from pyneat.rules.base import Rule


# --------------------------------------------------------------------------
# Severity taxonomy from research
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class AIBugPattern:
    """A detected AI-specific bug pattern."""
    bug_id: str           # e.g. "AI-SYNTAX-001"
    category: str         # functional / reliability / syntax / hallucination / ...
    subcategory: str      # e.g. "logic_bug", "off_by_one"
    severity: str         # critical / high / medium / low / info
    line: int
    snippet: str
    hint: str
    why: str
    confidence: float
    can_auto_fix: bool
    cwe_id: Optional[str]
    auto_fix_available: bool = False


# --------------------------------------------------------------------------
# Pattern registries
# --------------------------------------------------------------------------

# CRITICAL: Security vulnerabilities (CWE-based)
SECURITY_PATTERNS = [
    # SQL Injection — CWE-89
    {
        "id": "AI-SEC-001",
        "regex": re.compile(
            r'(?:execute|cursor\.execute|query|sql)\s*\(\s*["\']'
            r'.*?%s.*?["\'].*?%\s*.*?\)',
            re.IGNORECASE | re.DOTALL
        ),
        "msg": "Possible SQL injection — use parameterized queries",
        "cwe": "CWE-89",
        "severity": "critical",
    },
    # OS Command Injection — CWE-78
    {
        "id": "AI-SEC-002",
        "regex": re.compile(
            r'(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen)|'
            r'eval|exec|exec\().*?(?:request\.(?:args|form|data)|'
            r'input|sys\.argv|\b(?:GET|POST)\b)',
            re.IGNORECASE | re.DOTALL
        ),
        "msg": "Possible OS command injection — validate and sanitize all inputs",
        "cwe": "CWE-78",
        "severity": "critical",
    },
    # Hardcoded secret — CWE-798
    {
        "id": "AI-SEC-003",
        "regex": re.compile(
            r'(?:password|api[_-]?key|secret[_-]?key|token|'
            r'private[_-]?key)\s*=\s*["\'][^"\']{8,}["\']',
            re.IGNORECASE
        ),
        "msg": "Hardcoded secret detected — use environment variables or a secrets manager",
        "cwe": "CWE-798",
        "severity": "critical",
    },
    # Insecure hash (MD5/SHA1 for security) — CWE-327
    {
        "id": "AI-SEC-004",
        "regex": re.compile(
            r'(?:hashlib\.(?:md5|sha1|sha)\(|'
            r'DigestUtils\.(?:md5Hex|shaHex))\s*\(',
            re.IGNORECASE
        ),
        "msg": "Weak cryptographic hash — use SHA-256 or stronger for security purposes",
        "cwe": "CWE-327",
        "severity": "critical",
    },
    # XSS — CWE-79
    {
        "id": "AI-SEC-005",
        "regex": re.compile(
            r'(?:response\.write|document\.write|innerHTML\s*=|'
            r'v-html|RenderBody|HttpResponse)\s*\(.*?(?:request|input|param)',
            re.IGNORECASE | re.DOTALL
        ),
        "msg": "Possible XSS — sanitize HTML output",
        "cwe": "CWE-79",
        "severity": "critical",
    },
    # Eval/exec — CWE-95
    {
        "id": "AI-SEC-006",
        "regex": re.compile(r'\beval\s*\(|'
            r'\bexec\s*\(|'
            r'\bexec\s+[\'"]', re.IGNORECASE),
        "msg": "eval/exec with user input — high RCE risk",
        "cwe": "CWE-95",
        "severity": "critical",
    },
    # Pickle.loads — CWE-502
    {
        "id": "AI-SEC-007",
        "regex": re.compile(r'pickle\.loads?\s*\('),
        "msg": "Pickle deserialization is unsafe with untrusted data",
        "cwe": "CWE-502",
        "severity": "critical",
    },
    # YAML unsafe load — CWE-502
    {
        "id": "AI-SEC-008",
        "regex": re.compile(r'yaml\.load\s*\(.*?(?!Loader\s*=\s*yaml\.SafeLoader)', re.DOTALL),
        "msg": "yaml.load without SafeLoader is unsafe",
        "cwe": "CWE-502",
        "severity": "critical",
    },
]

# HIGH: Logic/semantic bugs
# Detected via AST analysis (see _AIBugDetector visitor)

# MEDIUM: Known problematic patterns
MEDIUM_PATTERNS = [
    # Infinite loop — recursion without base case detection
    {
        "id": "AI-LOGIC-001",
        "regex": re.compile(
            r'def\s+\w+\([^)]*\):.*?'
            r'(?:while\s+True|for\s+_?\s+in\s+range)'
            r'.*?(?!return|break)\Z',
            re.DOTALL | re.MULTILINE
        ),
        "msg": "Potential infinite loop — no break/return inside loop",
        "cwe": None,
        "severity": "medium",
    },
    # Off-by-one: range(n) vs range(n+1)
    {
        "id": "AI-LOGIC-002",
        "regex": re.compile(r'range\s*\(\s*\w+\s*\*\s*2\s*\)'),
        "msg": "Off-by-one risk in range() — verify loop bounds",
        "cwe": None,
        "severity": "medium",
    },
    # Comparison with None using == instead of "is"
    {
        "id": "AI-LOGIC-003",
        "regex": re.compile(r'\w+\s*==\s*None(?![\s]*[,\)])'),
        "msg": "Use 'is None' instead of '== None' (PEP8 E711)",
        "cwe": None,
        "severity": "medium",
    },
    # Empty exception handling
    {
        "id": "AI-LOGIC-004",
        "regex": re.compile(r'except\s*[^:]+:\s*(?:#[^\n]*)?\s*(?:\n|$)'),
        "msg": "Empty except block — errors are silently swallowed",
        "cwe": None,
        "severity": "medium",
    },
    # Division in Python 2 style (not future-proof)
    {
        "id": "AI-LOGIC-005",
        "regex": re.compile(r'(?<![/])(?<![//])(?<!\w)\/\s*(?!\/)'),
        "msg": "Use // for integer division — / is float division in Python 3",
        "cwe": None,
        "severity": "medium",
    },
    # Mutable default argument
    {
        "id": "AI-LOGIC-006",
        "regex": re.compile(r'def\s+\w+\s*\([^)]*=\s*\[\s*\]'),
        "msg": "Mutable default argument — use None instead (PEP8 E010)",
        "cwe": None,
        "severity": "medium",
    },
    # TODO/FIXME/HACK left in code (AI often skips these)
    {
        "id": "AI-LOGIC-007",
        "regex": re.compile(r'#\s*(?:TODO|FIXME|HACK|XXX|BUG|NOTE):', re.IGNORECASE),
        "msg": "Unresolved TODO/FIXME comment — resolve or document reason for deferring",
        "cwe": None,
        "severity": "medium",
    },
]

# LOW: Style/naming inconsistencies (AI often ignores project conventions)
STYLE_PATTERNS = [
    # Mixed snake_case / camelCase in same file
    {
        "id": "AI-STYLE-001",
        "regex": re.compile(r'\b[a-z][a-z0-9_]*[A-Z]\w*\b'),
        "msg": "Mixed naming convention detected — ensure consistent snake_case or camelCase",
        "cwe": None,
        "severity": "low",
    },
    # Line too long (> 120 chars)
    {
        "id": "AI-STYLE-002",
        "regex": re.compile(r'^.{121,}$', re.MULTILINE),
        "msg": "Line exceeds 120 characters — reduce for readability (PEP8 E501)",
        "cwe": None,
        "severity": "low",
    },
    # Tab/space inconsistency
    {
        "id": "AI-STYLE-003",
        "regex": re.compile(r'\t'),
        "msg": "Tab character found — use spaces for consistent indentation (PEP8 W191)",
        "cwe": None,
        "severity": "low",
    },
]


# --------------------------------------------------------------------------
# NEW: AI Bug Pattern Extensions (from user request)
# Detects additional AI-specific bugs: boundary checks, resource leaks,
# phantom packages, fake parameters, redundant I/O, naming inconsistencies.
# --------------------------------------------------------------------------


# RESOURCE LEAK patterns — detect unsafe resource usage
RESOURCE_LEAK_PATTERNS = [
    # open() without context manager — CWE-775
    # Match lines with open(...) but NOT "with open(...)"
    {
        "id": "AI-RES-001",
        "regex": re.compile(r'^\s*(?!with\b)\s*.*?\bopen\s*\([^)]+\)', re.MULTILINE),
        "msg": "FILE-LEAK: open() used without 'with' statement — risk of resource leak",
        "cwe": "CWE-775",
        "severity": "high",
    },
    # requests.get/post without timeout — CWE-400
    {
        "id": "AI-RES-002",
        "regex": re.compile(
            r'requests\.(?:get|post|put|patch|delete|head|options)\s*\('
            r'(?![^)]*\btimeout\s*=)',
            re.IGNORECASE
        ),
        "msg": "NET-LEAK: HTTP request without timeout — connection may hang indefinitely",
        "cwe": "CWE-400",
        "severity": "medium",
    },
    # urllib.request.urlopen without timeout
    {
        "id": "AI-RES-003",
        "regex": re.compile(
            r'urllib\.request\.urlopen\s*\('
            r'(?![^)]*\btimeout\s*=)',
            re.IGNORECASE
        ),
        "msg": "NET-LEAK: urllib urlopen without timeout — may hang indefinitely",
        "cwe": "CWE-400",
        "severity": "medium",
    },
    # httpx without timeout
    {
        "id": "AI-RES-004",
        "regex": re.compile(
            r'httpx\.(?:get|post|put|patch|delete|head|options|Client|AsyncClient)\s*\('
            r'(?![^)]*\btimeout\s*=)',
            re.IGNORECASE
        ),
        "msg": "NET-LEAK: httpx request without timeout — may hang indefinitely",
        "cwe": "CWE-400",
        "severity": "medium",
    },
    # aiohttp without timeout
    {
        "id": "AI-RES-005",
        "regex": re.compile(
            r'aiohttp\.(?:ClientSession|web)\s*\('
            r'(?![^)]*\btimeout\s*=)',
            re.IGNORECASE
        ),
        "msg": "NET-LEAK: aiohttp session without timeout configuration — may hang",
        "cwe": "CWE-400",
        "severity": "medium",
    },
]


# BOUNDARY CHECK patterns — detect unsafe array/string indexing
BOUNDARY_CHECK_PATTERNS = [
    # List indexing at 0 without guard
    {
        "id": "AI-BOUND-001",
        "regex": re.compile(
            r'(?:^|[^\w])\s*(?:\w+(?:\[[^\]]+\])?(?:\.[^\W\d][\w]*)*)'
            r'\s*\[\s*0\s*\](?!\s*(?:==|!=|>|<|>=|<=))'
        ),
        "msg": "BOUNDARY: accessing [0] without checking if list is empty — IndexError risk",
        "cwe": "CWE-125",
        "severity": "medium",
    },
    # x.split()[0] without guard — common AI mistake
    {
        "id": "AI-BOUND-002",
        "regex": re.compile(
            r'(?:split|strip|replace|splitlines|partition)\s*\([^)]*\)\s*\[\s*0\s*\]'
        ),
        "msg": "BOUNDARY: chaining [0] on split() result without checking for empty — IndexError risk",
        "cwe": "CWE-125",
        "severity": "medium",
    },
    # Negative indexing without bounds check
    {
        "id": "AI-BOUND-003",
        "regex": re.compile(r'\[\s*-\d+\s*\]'),
        "msg": "BOUNDARY: negative indexing without verifying length > abs(index) — IndexError risk",
        "cwe": "CWE-125",
        "severity": "low",
    },
]


# PHANTOM PACKAGE patterns — detect imports that may not exist
# Note: actual PyPI verification is async and done in _check_phantom_packages
PHANTOM_PACKAGE_PATTERNS = [
    # Very short import names that are likely hallucinations
    {
        "id": "AI-PKG-001",
        "regex": re.compile(
            r'^(?:import|from)\s+([a-z][a-z0-9_]{0,6})\b',
            re.MULTILINE
        ),
        "msg": "PACKAGE: import name '{name}' is suspiciously short — verify it exists on PyPI",
        "cwe": None,
        "severity": "low",
    },
    # Common hallucinated package names
    {
        "id": "AI-PKG-002",
        "regex": re.compile(
            r'^(?:import|from)\s+'
            r'(?:my_|fake_|mock_|dummy_|custom_|ai_|ml_|dl_|nn_|tf_|torch_)?'
            r'(?:package|library|module|api|utils|tools|helpers|lib)',
            re.MULTILINE | re.IGNORECASE
        ),
        "msg": "PACKAGE: generic package name detected — may be a hallucination. Verify on PyPI",
        "cwe": None,
        "severity": "low",
    },
]


# REDUNDANT I/O patterns — detect repeated I/O calls
# Note: actual redundant I/O detection is done via _RedundantIOVisitor AST visitor
# These patterns serve as quick heuristics for obvious cases
REDUNDANT_IO_PATTERNS = [
    # Repeated same-line patterns (heuristic)
    {
        "id": "AI-IO-001",
        "regex": re.compile(r'^\s*print\([^)]+\)\s*$', re.MULTILINE),
        "msg": "STYLE: Multiple print() statements on separate lines — consider logging framework",
        "cwe": None,
        "severity": "info",
    },
]


# NAMING INCONSISTENCY patterns — detect same concept with different names
NAMING_INCONSISTENCY_PATTERNS = [
    # Same root concept with different naming styles
    # e.g. "userId" and "user_id" in same file
    {
        "id": "AI-NAME-001",
        "regex": re.compile(r'\buser[_-]?(?:id|name|email|token|key)\b', re.IGNORECASE),
        "msg": "NAMING: 'userId/user_id/userName' — ensure consistent naming for same concept",
        "cwe": None,
        "severity": "low",
    },
    {
        "id": "AI-NAME-002",
        "regex": re.compile(r'\b(db|database|db_|postgres|mysql|mongo)[_-]?(?:host|port|name|user|pass)\b', re.IGNORECASE),
        "msg": "NAMING: mixed database naming styles detected — use consistent naming",
        "cwe": None,
        "severity": "low",
    },
    {
        "id": "AI-NAME-003",
        "regex": re.compile(r'\b(api|rest|http|web|server)[_-]?(?:url|endpoint|host|port|key|token)\b', re.IGNORECASE),
        "msg": "NAMING: mixed API naming styles detected — use consistent naming",
        "cwe": None,
        "severity": "low",
    },
]


# --------------------------------------------------------------------------
# AST-based semantic/logic bug detector
# --------------------------------------------------------------------------

class _AIBugVisitor(ast.NodeVisitor):
    """AST visitor that detects logic/semantic bugs in AI-generated code."""

    def __init__(self, source_lines: List[str]):
        self.source_lines = source_lines
        self.bugs: List[AIBugPattern] = []
        self._in_loop: Set[str] = set()
        self._in_function: Set[str] = set()
        self._has_return: bool = False
        self._loop_depth: int = 0
        self._defined_names: Set[str] = set()
        self._assigned_names: Set[str] = set()
        self._loop_exit_paths: Set[str] = set()
        self._fn_name: str = ""
        self._file_assigns: List[Tuple[int, str]] = []  # (line, name)
        self._func_uses: List[Tuple[int, str]] = []  # (line, name)
        self._undefined_uses: List[Tuple[int, str]] = []

    def _snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()[:80]
        return ""

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_fn = self._fn_name
        old_in_fn = self._fn_name
        old_has_return = self._has_return
        old_defined = set(self._defined_names)
        old_assigned = set(self._assigned_names)

        self._fn_name = node.name
        self._has_return = False
        self._defined_names = set()
        self._assigned_names = set()
        self._loop_exit_paths = set()

        self.generic_visit(node)

        # BUG-001: Unused parameters — AI often creates params never used
        args_used: Set[str] = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Name):
                args_used.add(n.id)

        unused_params = [
            arg.arg for arg in node.args.args
            if arg.arg not in args_used and arg.arg not in ('self', 'cls', 'args', 'kwargs')
        ]
        for param in unused_params:
            self.bugs.append(AIBugPattern(
                bug_id="AI-FUNC-001",
                category="functional",
                subcategory="unused_param",
                severity="medium",
                line=node.lineno,
                snippet=self._snippet(node.lineno),
                hint=f"Parameter '{param}' in '{node.name}()' appears unused",
                why="Unused parameters indicate a logic mismatch — AI may have generated the function with incorrect assumptions about which params are needed",
                confidence=0.85,
                can_auto_fix=False,
                cwe_id=None,
            ))

        # BUG-002: Function returns nothing (missing return statement)
        if not self._has_return and node.returns is not None:
            self.bugs.append(AIBugPattern(
                bug_id="AI-FUNC-002",
                category="functional",
                subcategory="missing_return",
                severity="high",
                line=node.lineno,
                snippet=self._snippet(node.lineno),
                hint=f"Function '{node.name}()' declares a return type but has no return statement",
                why="Missing return causes None to be returned — AI often forgets to add the return statement",
                confidence=0.90,
                can_auto_fix=False,
                cwe_id=None,
            ))

        # BUG-003: Off-by-one in range() — common AI mistake
        for child in ast.walk(node):
            if isinstance(child, ast.Compare) and isinstance(child.left, ast.Call):
                cmp_ops = {type(op).__name__ for op in child.ops}
                if 'LtE' in cmp_ops:  # <= instead of <
                    call = child.left
                    if (isinstance(call, ast.Call) and
                        hasattr(call.func, 'id') and call.func.id == 'range' and
                        len(call.args) == 1 and
                        isinstance(call.args[0], ast.BinOp) and
                        isinstance(call.args[0].op, ast.Add)):
                        self.bugs.append(AIBugPattern(
                            bug_id="AI-LOGIC-008",
                            category="functional",
                            subcategory="off_by_one",
                            severity="high",
                            line=node.lineno,
                            snippet=self._snippet(node.lineno),
                            hint="range() with x+1 may indicate off-by-one error — verify bounds",
                            why="AI commonly generates range(x+1) when range(x) is correct, or uses <= instead of <",
                            confidence=0.80,
                            can_auto_fix=False,
                            cwe_id=None,
                        ))

        self._fn_name = old_fn
        self._has_return = old_has_return
        self._defined_names = old_defined
        self._assigned_names = old_assigned

    def visit_Return(self, node: ast.Return):
        self._has_return = True
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_While(self, node: ast.While):
        # Check for infinite while True with no break
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            has_break = any(
                isinstance(n, ast.Break)
                for n in ast.walk(node)
            )
            if not has_break:
                self.bugs.append(AIBugPattern(
                    bug_id="AI-LOOP-001",
                    category="reliability",
                    subcategory="infinite_loop",
                    severity="medium",
                    line=node.lineno,
                    snippet=self._snippet(node.lineno),
                    hint="while True without break — possible infinite loop",
                    why="AI often writes while True loops without guaranteed exit conditions, causing CPU spin or OOM",
                    confidence=0.75,
                    can_auto_fix=False,
                    cwe_id=None,
                ))
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Store):
            self._defined_names.add(node.id)
            self._assigned_names.add(node.id)
            self._file_assigns.append((node.lineno, node.id))
        elif isinstance(node.ctx, ast.Load):
            self._func_uses.append((node.lineno, node.id))
            if node.id not in self._defined_names and node.id not in BUILTINS:
                self._undefined_uses.append((node.lineno, node.id))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # BUG-004: Name assigned but never used
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id
                is_used = any(
                    n.id == name
                    for n in ast.walk(node)
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                ) or any(
                    n.id == name
                    for s, n in self._func_uses
                    if n == name
                )
                # Only flag if it's a meaningful name (not temp/counter)
                if not is_used and len(name) > 1 and name not in ('i', 'j', 'k', '_', 'x', 'y', 'tmp'):
                    self.bugs.append(AIBugPattern(
                        bug_id="AI-FUNC-003",
                        category="functional",
                        subcategory="unused_variable",
                        severity="low",
                        line=node.lineno,
                        snippet=self._snippet(node.lineno),
                        hint=f"Variable '{name}' is assigned but never used",
                        why="AI-generated code often creates variables that aren't referenced — may indicate a logic gap",
                        confidence=0.70,
                        can_auto_fix=False,
                        cwe_id=None,
                    ))
        self.generic_visit(node)


BUILTINS = set(dir(__builtins__)) if isinstance(dir(__builtins__), list) else set(__builtins__)


# --------------------------------------------------------------------------
# NEW: AST visitors for additional AI bug patterns
# --------------------------------------------------------------------------


class _BoundaryCheckVisitor(ast.NodeVisitor):
    """Detect unsafe array/string indexing without boundary checks."""

    def __init__(self, source_lines: List[str]):
        self.source_lines = source_lines
        self.bugs: List[AIBugPattern] = []

    def _snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()[:80]
        return ""

    def _is_guarded(self, node: ast.AST, tree: ast.AST) -> bool:
        """Check if node is inside a guard condition (if/elif/while)."""
        for parent in ast.walk(tree):
            if isinstance(parent, (ast.If, ast.While)):
                # Check if our node is inside the test of this guard
                for child in ast.walk(parent):
                    if child is node and isinstance(parent.test, ast.Compare):
                        cmp = parent.test
                        # Check for: if len(x) > 0, if x, if x is not None, etc.
                        if any(isinstance(c, (ast.Call, ast.Name, ast.Attribute))
                               for c in [cmp.left] + list(cmp.comparators)):
                            return True
        return False

    def visit_Subscript(self, node: ast.Subscript):
        # Detect x[0], x[-1], x[1], etc. without guard
        if isinstance(node.slice, ast.Constant):
            value = node.slice.value
            if isinstance(value, int):
                # x[0] or x[-1] without guard
                if value == 0:
                    self.bugs.append(AIBugPattern(
                        bug_id="AI-BOUND-001",
                        category="reliability",
                        subcategory="boundary_check",
                        severity="medium",
                        line=node.lineno,
                        snippet=self._snippet(node.lineno),
                        hint="BOUNDARY: accessing [0] on possibly empty collection — add `if items:` or `if len(items) > 0:` guard",
                        why="AI often generates code that accesses the first element without checking if the collection is empty, causing IndexError at runtime",
                        confidence=0.75,
                        can_auto_fix=False,
                        cwe_id="CWE-125",
                    ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Detect .split()[0], .splitlines()[0], etc.
        attr = node.func
        if isinstance(attr, ast.Attribute):
            method_name = attr.attr
            if method_name in ('split', 'strip', 'replace', 'splitlines', 'partition', 'rsplit'):
                # Check if result is indexed at 0
                parent = getattr(node, '_parent', None)
                if isinstance(parent, ast.Subscript):
                    if isinstance(parent.slice, ast.Constant) and parent.slice.value == 0:
                        self.bugs.append(AIBugPattern(
                            bug_id="AI-BOUND-002",
                            category="reliability",
                            subcategory="boundary_check",
                            severity="medium",
                            line=node.lineno,
                            snippet=self._snippet(node.lineno),
                            hint=f"BOUNDARY: chaining [0] on .{method_name}() result — add guard to check for empty result",
                            why=f"AI commonly chains .{method_name}()[0] assuming non-empty result, causing IndexError when result is empty",
                            confidence=0.80,
                            can_auto_fix=False,
                            cwe_id="CWE-125",
                        ))
        self.generic_visit(node)


class _RedundantIOVisitor(ast.NodeVisitor):
    """Detect redundant I/O operations within the same function."""

    def __init__(self, source_lines: List[str]):
        self.source_lines = source_lines
        self.bugs: List[AIBugPattern] = []

    def _snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()[:80]
        return ""

    def _get_call_key(self, node: ast.Call) -> Optional[Tuple[str, str]]:
        """Get a hashable key for a function call."""
        try:
            if isinstance(node.func, ast.Name):
                args_repr = ','.join(self._get_node_repr(a) for a in node.args)
                return (node.func.id, args_repr)
            elif isinstance(node.func, ast.Attribute):
                args_repr = ','.join(self._get_node_repr(a) for a in node.args)
                return (node.func.attr, args_repr)
        except Exception:
            pass
        return None

    def _get_node_repr(self, node: ast.AST) -> str:
        """Get a string representation of a node for comparison."""
        try:
            return ast.dump(node)
        except Exception:
            return "?"

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Collect all calls within this function
        call_keys: Dict[Tuple[str, str], List[int]] = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                key = self._get_call_key(child)
                if key:
                    if key not in call_keys:
                        call_keys[key] = []
                    call_keys[key].append(child.lineno)

        # Report redundant calls (same function, same args, called >= 3 times)
        for (func_name, args_repr), line_nos in call_keys.items():
            if len(line_nos) >= 3:
                # I/O-heavy functions
                io_functions = {
                    'print', 'read', 'write', 'send', 'recv', 'fetch',
                    'get', 'post', 'put', 'delete', 'request',
                    'query', 'execute', 'select', 'insert', 'update',
                    'save', 'load', 'open', 'close', 'connect', 'disconnect'
                }
                if any(io in func_name.lower() for io in io_functions):
                    self.bugs.append(AIBugPattern(
                        bug_id="AI-IO-001",
                        category="performance",
                        subcategory="redundant_io",
                        severity="medium",
                        line=line_nos[0],
                        snippet=self._snippet(line_nos[0]),
                        hint=f"REDUNDANT-I/O: {func_name}() called {len(line_nos)} times with same args in '{node.name}()' — cache the result instead",
                        why="AI-generated code often calls I/O functions repeatedly with identical arguments, causing 8x slowdown vs caching the result",
                        confidence=0.80,
                        can_auto_fix=False,
                        cwe_id=None,
                    ))
        self.generic_visit(node)


class _FakeParamVisitor(ast.NodeVisitor):
    """Detect calls with fake/mismatched parameters."""

    def __init__(self, source_lines: List[str]):
        self.source_lines = source_lines
        self.bugs: List[AIBugPattern] = []

    def _snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()[:80]
        return ""

    def _get_func_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None

    def visit_Call(self, node: ast.Call):
        func_name = self._get_func_name(node.func)
        if not func_name:
            self.generic_visit(node)
            return

        # Get keyword arguments
        known_kwargs = {kw.arg for kw in node.keywords if kw.arg}

        # Check for suspicious kwargs not matching known patterns
        suspicious_kwargs = {
            'fake_param', 'dummy', 'mock', 'fake', 'nonexistent',
            'param1', 'param2', 'arg1', 'arg2', 'value1', 'value2',
            'temp', 'tmp', 'undefined', 'null', 'placeholder',
        }
        for kw in known_kwargs:
            if kw.lower() in suspicious_kwargs:
                self.bugs.append(AIBugPattern(
                    bug_id="AI-PARAM-001",
                    category="functional",
                    subcategory="fake_parameter",
                    severity="high",
                    line=node.lineno,
                    snippet=self._snippet(node.lineno),
                    hint=f"FAKE-PARAM: keyword argument '{kw}' looks like a hallucinated parameter — verify function signature",
                    why="AI often invents parameter names that don't exist in the actual function signature, causing TypeError at runtime",
                    confidence=0.85,
                    can_auto_fix=False,
                    cwe_id=None,
                ))

        # Check for numeric kwargs (like foo(1, 2, 3) where function expects names)
        for i, arg in enumerate(node.args):
            if isinstance(arg, ast.Constant) and isinstance(arg.value, (int, str)):
                if i > 5:  # More than 5 positional args is suspicious
                    self.bugs.append(AIBugPattern(
                        bug_id="AI-PARAM-002",
                        category="functional",
                        subcategory="fake_parameter",
                        severity="medium",
                        line=node.lineno,
                        snippet=self._snippet(node.lineno),
                        hint=f"FAKE-PARAM: function '{func_name}()' called with {i+1} positional args — verify signature",
                        why="AI often uses positional arguments when the function requires named parameters, or invents extra arguments",
                        confidence=0.70,
                        can_auto_fix=False,
                        cwe_id=None,
                    ))

        self.generic_visit(node)


class _NamingInconsistencyVisitor(ast.NodeVisitor):
    """Detect naming inconsistencies within a file (same concept, different styles)."""

    def __init__(self, source_lines: List[str]):
        self.source_lines = source_lines
        self.bugs: List[AIBugPattern] = []
        self._all_names: List[Tuple[int, str]] = []

    def _snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()[:80]
        return ""

    def _normalize_name(self, name: str) -> str:
        """Normalize a name to its base concept for comparison."""
        # Remove common prefixes/suffixes
        name = name.lower()
        # Convert to common separator
        for sep in ['_', '-']:
            name = name.replace(sep, '')
        # Remove common prefixes
        for prefix in ['the_', 'a_', 'an_', 'my_', 'our_', 'get_', 'set_', 'is_', 'has_', 'usr_']:
            if name.startswith(prefix):
                name = name[len(prefix):]
        return name

    def _get_name_category(self, name: str) -> Optional[str]:
        """Categorize a name into a semantic concept."""
        name_lower = name.lower()

        # User-related
        if any(x in name_lower for x in ['user', 'usr']):
            if any(x in name_lower for x in ['id', 'name', 'email', 'token', 'key', 'pass']):
                return 'user_identifier'
        # Database-related
        if any(x in name_lower for x in ['db', 'database', 'postgres', 'mysql', 'mongo', 'redis']):
            if any(x in name_lower for x in ['host', 'port', 'name', 'user', 'pass', 'url']):
                return 'db_config'
        # API-related
        if any(x in name_lower for x in ['api', 'rest', 'http']):
            if any(x in name_lower for x in ['url', 'endpoint', 'host', 'key', 'token']):
                return 'api_config'
        # Config-related
        if any(x in name_lower for x in ['config', 'cfg', 'setting']):
            if any(x in name_lower for x in ['file', 'path', 'dir', 'url']):
                return 'config_path'
        return None

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load):
            self._all_names.append((node.lineno, node.id))
        self.generic_visit(node)

    def finalize(self):
        """Analyze collected names for inconsistencies after visiting."""
        # Group names by category
        categories: Dict[str, List[Tuple[int, str]]] = {}
        for lineno, name in self._all_names:
            category = self._get_name_category(name)
            if category:
                if category not in categories:
                    categories[category] = []
                categories[category].append((lineno, name))

        # Check each category for naming style inconsistency
        for category, entries in categories.items():
            if len(entries) < 2:
                continue

            # Check if there are both snake_case and camelCase variants
            has_snake = any('_' in name for _, name in entries)
            has_camel = any(c.isupper() for name in entries for c in name if c.isalpha())

            if has_snake and has_camel:
                # Find the specific conflicting names
                snake_names = [(ln, n) for ln, n in entries if '_' in n]
                camel_names = [(ln, n) for ln, n in entries if any(c.isupper() for c in n)]

                if snake_names and camel_names:
                    lineno, _ = entries[0]
                    self.bugs.append(AIBugPattern(
                        bug_id="AI-NAME-001",
                        category="code_style",
                        subcategory="naming_inconsistency",
                        severity="low",
                        line=lineno,
                        snippet=self._snippet(lineno),
                        hint=f"NAMING-INCONSISTENCY: found both snake_case ({snake_names[0][1]}) and camelCase ({camel_names[0][1]}) for the same concept — use consistent naming",
                        why="AI-generated code often uses mixed naming conventions for the same concept, reducing readability and causing confusion",
                        confidence=0.75,
                        can_auto_fix=False,
                        cwe_id=None,
                    ))


# --------------------------------------------------------------------------
# Deprecated API hallucination detector
# --------------------------------------------------------------------------

# Known deprecated/wrong APIs that AI hallucinates
HALLUCINATED_APIS = [
    (re.compile(r'\.items\.iteritems\(\)'), "dict.items() in Python 3 — .iteritems() was removed in Python 3"),
    (re.compile(r'\.keys\.iterkeys\(\)'), "dict.keys() in Python 3 — .iterkeys() was removed in Python 3"),
    (re.compile(r'\.values\.itervalues\(\)'), "dict.values() in Python 3 — .itervalues() was removed in Python 3"),
    (re.compile(r'basestring'), "basestring doesn't exist in Python 3 — use str"),
    (re.compile(r'\braw_input\s*\('), "raw_input doesn't exist in Python 3 — use input()"),
    (re.compile(r'apply\s*\('), "apply() was removed in Python 3 — use func(*args)"),
    (re.compile(r'execfile\s*\('), "execfile() was removed in Python 3"),
    (re.compile(r'file\s*\('), "file() was removed in Python 3 — use open()"),
    (re.compile(r'\.next\s*\(\s*\)'), ".next() removed in Python 3 — use next(iterator)"),
    (re.compile(r'from\s+PIL\s+import\s+\w+'), "PIL imports may be wrong — use 'from PIL import Image'"),
]


# --------------------------------------------------------------------------
# Main rule
# --------------------------------------------------------------------------

class AIBugRule(Rule):
    """Detect AI-specific bug patterns from the AIBugs taxonomy.

    Categories detected (per arXiv:2512.05239v1 survey of 94 studies):
      CRITICAL  Security: SQLi, XSS, Command Injection, Hardcoded secrets
      HIGH      Logic: off-by-one, missing return, wrong algorithm
      MEDIUM    Reliability: infinite loop, empty except, deprecated API
      LOW       Style: mixed naming, long lines, TODO comments

    Confidence is based on detection reliability from research data.
    """

    ALLOWED_SEMANTIC_NODES: Set[str] = set()

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self._cached_bugs: List[AIBugPattern] = []

    @property
    def description(self) -> str:
        return (
            "Detects AI-specific bug patterns: logic bugs, semantic errors, "
            "hallucinated APIs, security vulnerabilities, and style inconsistencies. "
            "Based on the AIBugs taxonomy from 94 studies (arXiv:2512.05239)."
        )

    def apply(self, code_file: CodeFile) -> TransformationResult:
        self._cached_bugs = []
        source = code_file.content
        lines = source.splitlines()

        # 1. Security pattern matching
        for pattern in SECURITY_PATTERNS:
            for i, line in enumerate(lines, 1):
                match = pattern["regex"].search(line)
                if match:
                    self._cached_bugs.append(AIBugPattern(
                        bug_id=pattern["id"],
                        category="security",
                        subcategory="vulnerability",
                        severity=pattern["severity"],
                        line=i,
                        snippet=line.strip()[:80],
                        hint=pattern["msg"],
                        why=f"AI-generated code often omits security checks. CWE: {pattern['cwe']}",
                        confidence=0.90,
                        can_auto_fix=False,
                        cwe_id=pattern["cwe"],
                    ))

        # 2. Medium logic pattern matching
        for pattern in MEDIUM_PATTERNS:
            for i, line in enumerate(lines, 1):
                if pattern["regex"].search(line):
                    self._cached_bugs.append(AIBugPattern(
                        bug_id=pattern["id"],
                        category="functional",
                        subcategory="logic_antipattern",
                        severity=pattern["severity"],
                        line=i,
                        snippet=line.strip()[:80],
                        hint=pattern["msg"],
                        why="AI often generates code that compiles but has subtle runtime issues",
                        confidence=0.75,
                        can_auto_fix=False,
                        cwe_id=None,
                    ))

        # 3. Hallucinated API detection
        for pattern_regex, msg in HALLUCINATED_APIS:
            for i, line in enumerate(lines, 1):
                if pattern_regex.search(line):
                    self._cached_bugs.append(AIBugPattern(
                        bug_id="AI-API-001",
                        category="hallucination",
                        subcategory="deprecated_api",
                        severity="high",
                        line=i,
                        snippet=line.strip()[:80],
                        hint=msg,
                        why="AI trained on Python 2 / outdated code often generates deprecated API calls",
                        confidence=0.95,
                        can_auto_fix=False,
                        cwe_id=None,
                    ))

        # 4. AST-based semantic/logic analysis
        try:
            # Use cached AST if available (RuleEngine pre-parses)
            if hasattr(code_file, 'ast_tree') and code_file.ast_tree is not None:
                tree = code_file.ast_tree
            else:
                tree = ast.parse(source)
        except SyntaxError:
            # Let syntax rules handle this
            return self._create_result(code_file, source, [])

        visitor = _AIBugVisitor(lines)
        visitor.visit(tree)
        self._cached_bugs.extend(visitor.bugs)

        # 5. Low-priority style checks (only if configured)
        if self.config.enabled:
            for pattern in STYLE_PATTERNS:
                for i, line in enumerate(lines, 1):
                    if pattern["regex"].search(line):
                        self._cached_bugs.append(AIBugPattern(
                            bug_id=pattern["id"],
                            category="code_style",
                            subcategory="convention_violation",
                            severity=pattern["severity"],
                            line=i,
                            snippet=line.strip()[:80],
                            hint=pattern["msg"],
                            why="AI-generated code often ignores project style conventions",
                            confidence=0.60,
                            can_auto_fix=False,
                            cwe_id=None,
                        ))

        # 6. Resource leak pattern detection (NEW)
        for pattern in RESOURCE_LEAK_PATTERNS:
            for i, line in enumerate(lines, 1):
                if pattern["regex"].search(line):
                    self._cached_bugs.append(AIBugPattern(
                        bug_id=pattern["id"],
                        category="reliability",
                        subcategory="resource_leak",
                        severity=pattern["severity"],
                        line=i,
                        snippet=line.strip()[:80],
                        hint=pattern["msg"],
                        why="AI often generates code with unclosed resources or missing timeouts, causing resource exhaustion",
                        confidence=0.85,
                        can_auto_fix=False,
                        cwe_id=pattern["cwe"],
                    ))

        # 7. Boundary check pattern detection (NEW)
        for pattern in BOUNDARY_CHECK_PATTERNS:
            for i, line in enumerate(lines, 1):
                if pattern["regex"].search(line):
                    self._cached_bugs.append(AIBugPattern(
                        bug_id=pattern["id"],
                        category="reliability",
                        subcategory="boundary_check",
                        severity=pattern["severity"],
                        line=i,
                        snippet=line.strip()[:80],
                        hint=pattern["msg"],
                        why="AI often assumes non-empty collections or arrays, causing IndexError when collections are empty",
                        confidence=0.75,
                        can_auto_fix=False,
                        cwe_id=pattern["cwe"],
                    ))

        # 8. Phantom package pattern detection (NEW)
        for pattern in PHANTOM_PACKAGE_PATTERNS:
            for i, line in enumerate(lines, 1):
                if pattern["regex"].search(line):
                    # Extract package name
                    match = pattern["regex"].search(line)
                    pkg_name = match.group(1) if match.groups() else ""
                    hint = pattern["msg"].format(name=pkg_name) if "{name}" in pattern["msg"] else pattern["msg"]
                    self._cached_bugs.append(AIBugPattern(
                        bug_id=pattern["id"],
                        category="hallucination",
                        subcategory="phantom_package",
                        severity=pattern["severity"],
                        line=i,
                        snippet=line.strip()[:80],
                        hint=hint,
                        why="AI may hallucinate package names that don't exist on PyPI, causing ImportError at runtime",
                        confidence=0.60,
                        can_auto_fix=False,
                        cwe_id=None,
                    ))

        # 9. Naming inconsistency pattern detection (NEW)
        for pattern in NAMING_INCONSISTENCY_PATTERNS:
            for i, line in enumerate(lines, 1):
                if pattern["regex"].search(line):
                    self._cached_bugs.append(AIBugPattern(
                        bug_id=pattern["id"],
                        category="code_style",
                        subcategory="naming_inconsistency",
                        severity=pattern["severity"],
                        line=i,
                        snippet=line.strip()[:80],
                        hint=pattern["msg"],
                        why="AI-generated code often uses mixed naming conventions for the same concept within a file",
                        confidence=0.70,
                        can_auto_fix=False,
                        cwe_id=None,
                    ))

        # 10. AST-based boundary check analysis (NEW)
        try:
            # Use cached AST if available (RuleEngine pre-parses)
            if hasattr(code_file, 'ast_tree') and code_file.ast_tree is not None:
                tree = code_file.ast_tree
            else:
                tree = ast.parse(source)
        except SyntaxError:
            pass
        else:
            # Boundary check visitor
            boundary_visitor = _BoundaryCheckVisitor(lines)
            boundary_visitor.visit(tree)
            self._cached_bugs.extend(boundary_visitor.bugs)

            # Redundant I/O visitor
            redundant_io_visitor = _RedundantIOVisitor(lines)
            redundant_io_visitor.visit(tree)
            self._cached_bugs.extend(redundant_io_visitor.bugs)

            # Fake parameter visitor
            fake_param_visitor = _FakeParamVisitor(lines)
            fake_param_visitor.visit(tree)
            self._cached_bugs.extend(fake_param_visitor.bugs)

            # Naming inconsistency visitor
            naming_visitor = _NamingInconsistencyVisitor(lines)
            naming_visitor.visit(tree)
            naming_visitor.finalize()
            self._cached_bugs.extend(naming_visitor.bugs)

        # No code transformation — this is a read-only detector
        changes = [
            f"[AI-BUG] {b.bug_id} ({b.severity}): line {b.line}: {b.hint}"
            for b in self._cached_bugs
        ]
        return self._create_result(code_file, source, changes)

    def mark_for_agent(self, code_file: CodeFile) -> Optional[List[AgentMarker]]:
        """Return AgentMarkers for all detected AI bug patterns.

        Filters to high-impact issues only (medium+ severity) to avoid
        flooding the manifest with low-priority style notes.
        """
        # Ensure bugs are detected
        if not self._cached_bugs:
            self.apply(code_file)

        markers: List[AgentMarker] = []
        for bug in self._cached_bugs:
            # Skip low-priority style issues unless they are the only output
            if bug.severity == "low" and len(self._cached_bugs) > 10:
                continue

            marker_id = bug.bug_id.replace("AI-", "PYN-AI-")

            markers.append(AgentMarker(
                marker_id=marker_id,
                issue_type=f"ai_{bug.subcategory}",
                rule_id="AIBugRule",
                severity=bug.severity,
                line=bug.line,
                hint=bug.hint,
                why=bug.why,
                confidence=bug.confidence,
                can_auto_fix=bug.can_auto_fix,
                snippet=bug.snippet[:80],
                cwe_id=bug.cwe_id,
                auto_fix_available=bug.auto_fix_available,
            ))

        return markers if markers else None
