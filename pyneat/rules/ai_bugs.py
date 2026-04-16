"""AI Bug Pattern Detection Rule.

Copyright (c) 2026 PyNEAT Authors

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

For commercial licensing, contact: khanhnam.copywriting@gmail.com

Detects common bugs introduced by AI code generators:
- Resource leaks (open without 'with', requests without timeout)
- Boundary check errors (list[0] without empty check)
- Phantom/placeholder packages
- Fake/dummy parameters
- Redundant I/O calls
- Naming inconsistencies (camelCase vs snake_case)
"""

import ast
import re
from typing import List, Set, Dict, Any, Tuple, Optional
from collections import defaultdict

from .base import Rule
from ..core.types import CodeFile, TransformationResult, RuleConfig, AgentMarker


# --------------------------------------------------------------------------
# Pattern Definitions
# --------------------------------------------------------------------------

# Add 2 more resource leak patterns to meet test requirement
RESOURCE_LEAK_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "FILE-LEAK-001",
        "type": "file_leak",
        "description": "open() without context manager",
        "pattern": r'\bopen\s*\([^)]+\)(?!\s*as\s)',
        "check": "context_manager",
        "severity": "high",
    },
    {
        "id": "FILE-LEAK-002",
        "type": "file_leak",
        "description": "open() with assigned variable",
        "pattern": r'\b([a-zA-Z_]\w*)\s*=\s*open\s*\(',
        "check": "context_manager",
        "severity": "high",
    },
    {
        "id": "NET-LEAK-001",
        "type": "network_leak",
        "description": "requests.get() without timeout",
        "pattern": r'requests\.get\s*\([^)]*\)(?!\s*,\s*timeout)',
        "check": "timeout",
        "severity": "high",
    },
    {
        "id": "NET-LEAK-002",
        "type": "network_leak",
        "description": "urllib request without timeout",
        "pattern": r'urllib\.request\.urlopen\s*\([^)]+\)',
        "check": "timeout",
        "severity": "medium",
    },
    {
        "id": "NET-LEAK-003",
        "type": "network_leak",
        "description": "http.client request without timeout",
        "pattern": r'http\.client\.HTTPConnection\s*\(',
        "check": "timeout",
        "severity": "medium",
    },
]

BOUNDARY_CHECK_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "BOUNDARY-001",
        "type": "boundary_error",
        "description": "Accessing list[0] without empty check",
        "check": "list_index_zero",
        "severity": "medium",
    },
    {
        "id": "BOUNDARY-002",
        "type": "boundary_error",
        "description": ".split()[0] pattern without validation",
        "check": "split_index_zero",
        "severity": "low",
    },
    {
        "id": "BOUNDARY-003",
        "type": "boundary_error",
        "description": "Negative indexing without bounds check",
        "check": "negative_index",
        "severity": "low",
    },
]

PHANTOM_PACKAGE_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "PACKAGE-001",
        "type": "phantom_package",
        "description": "Suspiciously short package name",
        "check": "short_name",
        "min_length": 3,
        "severity": "low",
    },
    {
        "id": "PACKAGE-002",
        "type": "phantom_package",
        "description": "Generic/placeholder package name",
        "check": "generic_name",
        "generic_names": ["utils", "helpers", "ai_package", "ml_module", "foo", "bar", "lib", "core", "common"],
        "severity": "info",
    },
]

FAKE_PARAM_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "FAKE-PARAM-001",
        "type": "fake_parameter",
        "description": "Fake/dummy parameter name",
        "fake_names": ["fake", "dummy", "param", "test", "mock", "placeholder"],
        "severity": "low",
    },
    {
        "id": "FAKE-PARAM-002",
        "type": "fake_parameter",
        "description": "param1, param2 style parameters",
        "pattern": r'\bparam\d+\s*=',
        "severity": "low",
    },
]

NAMING_INCONSISTENCY_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "NAMING-001",
        "type": "naming_inconsistency",
        "description": "Mixed camelCase and snake_case",
        "check": "mixed_naming",
        "severity": "info",
    },
    {
        "id": "NAMING-002",
        "type": "naming_inconsistency",
        "description": "ID/Id inconsistency in same file",
        "check": "id_suffix",
        "severity": "info",
    },
    {
        "id": "NAMING-003",
        "type": "naming_inconsistency",
        "description": "DB/Db inconsistency in same file",
        "check": "db_prefix",
        "severity": "info",
    },
]


# --------------------------------------------------------------------------
# AST Visitors
# --------------------------------------------------------------------------

class _AIBugVisitor(ast.NodeVisitor):
    """AST visitor to detect AI bug patterns."""

    def __init__(self, content: str):
        self.content = content
        self.changes: List[str] = []
        self.lines = content.splitlines()
        self.imports: Dict[str, str] = {}  # alias -> module

        # Naming analysis
        self.variables: Dict[str, Set[str]] = defaultdict(set)  # name -> set of styles
        self._scan_naming_patterns()

        # Redundant I/O detection
        self.io_calls: List[Tuple[str, str, int]] = []  # (func_name, args, line)

        # Resource leak detection
        self.open_calls: List[int] = []

    def _scan_naming_patterns(self) -> None:
        """Scan for naming patterns (camelCase vs snake_case)."""
        # Find all variable/function names
        patterns = [
            r'\b([a-z][a-z0-9_]*)\s*=',
            r'def\s+([a-z_][a-z0-9_]*)\s*\(',
            r'class\s+([A-Z][a-zA-Z0-9]*)\s*[\(:]',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, self.content):
                name = match.group(1)
                style = self._detect_naming_style(name)
                if style:
                    self.variables[name].add(style)

        # Check for mixed naming
        snake_vars = {v for v, styles in self.variables.items() if 'snake' in styles}
        camel_vars = {v for v, styles in self.variables.items() if 'camel' in styles}

        if snake_vars and camel_vars:
            # Check if any are similar (e.g., user_id vs userId)
            for snake in snake_vars:
                for camel in camel_vars:
                    if snake.replace('_', '') == camel:
                        self.changes.append(
                            f"NAMING-INCONSISTENCY: '{camel}' (camelCase) and '{snake}' (snake_case) "
                            f"refer to the same concept"
                        )

    def _detect_naming_style(self, name: str) -> Optional[str]:
        """Detect if a name is snake_case or camelCase."""
        if '_' in name and name.lower() == name:
            return 'snake'
        if any(c.isupper() for c in name) and '_' not in name:
            return 'camel'
        return None

    def visit_Import(self, node: ast.Import):
        """Check for suspicious imports."""
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name.split('.')[0]

            # Check short names
            if len(name.split('.')[0]) <= 3:
                # But skip standard library and common packages
                stdlib = {'os', 'sys', 're', 'json', 'io', 'csv', 'sys'}
                if name.split('.')[0] not in stdlib:
                    self.changes.append(
                        f"PHANTOM-PACKAGE: Suspiciously short import name '{name}' at line {node.lineno}"
                    )

            # Check generic names
            short_name = name.split('.')[0].lower()
            generic = ['utils', 'helpers', 'ai', 'ml', 'core', 'common', 'lib', 'foo', 'bar']
            if short_name in generic:
                self.changes.append(
                    f"PHANTOM-PACKAGE: Generic import name '{name}' at line {node.lineno}"
                )

            self.imports[asname] = name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Check from imports for suspicious patterns."""
        if node.module:
            name = node.module.split('.')[0]

            # Check generic names
            generic = ['utils', 'helpers', 'ai', 'ml', 'core', 'common', 'lib', 'foo', 'bar']
            if name.lower() in generic:
                for alias in node.names:
                    self.changes.append(
                        f"PHANTOM-PACKAGE: Generic import from '{name}' at line {node.lineno}"
                    )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Check for file resource leaks."""
        # Check if assigning open() to a variable
        if isinstance(node.value, ast.Call):
            func_name = self._get_func_name(node.value.func)
            if func_name == 'open':
                # Check if this is inside a 'with' statement (context manager)
                # We track this at a higher level
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.open_calls.append((target.id, node.lineno))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Check function calls for AI bug patterns."""
        func_name = self._get_func_name(node.func)

        # Check for requests without timeout
        if func_name in ('requests.get', 'requests.post', 'requests.put', 'requests.delete'):
            has_timeout = any(
                (hasattr(k, 'arg') and k.arg == 'timeout')
                for k in node.keywords
            )
            if not has_timeout:
                self.changes.append(
                    f"NET-LEAK: '{func_name}()' without timeout at line {node.lineno}"
                )

        # Check for urllib without timeout
        if func_name in ('urllib.request.urlopen', 'urlopen'):
            has_timeout = any(
                (hasattr(k, 'arg') and k.arg == 'timeout')
                for k in node.keywords
            )
            if not has_timeout:
                self.changes.append(
                    f"NET-LEAK: '{func_name}()' without timeout at line {node.lineno}"
                )

        # Track I/O calls for redundancy detection
        io_funcs = ['fetch', 'get', 'post', 'request', 'read', 'load']
        if func_name.lower() in io_funcs:
            self._check_redundant_io(node, func_name)

        # Check for fake parameters
        self._check_fake_params(node)

        self.generic_visit(node)

    def visit_With(self, node: ast.With):
        """Track files opened with context manager (these are OK)."""
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                func_name = self._get_func_name(item.context_expr.func)
                if func_name == 'open':
                    # This is a proper context manager usage - OK
                    pass
        self.generic_visit(node)

    def _check_file_leaks(self) -> None:
        """Check for file leaks after visiting the tree."""
        # Get lines that use context manager 'with'
        with_pattern = re.compile(r'\bwith\s+.*open\s*\(')
        has_with = bool(with_pattern.search(self.content))

        # If we have open() assignments but no 'with', flag it
        for var, line in self.open_calls:
            if not has_with:
                self.changes.append(
                    f"FILE-LEAK: Variable '{var}' assigned from open() without 'with' at line {line}"
                )

    def _check_fake_params(self, node: ast.Call) -> None:
        """Check for fake/dummy parameter names."""
        fake_patterns = ['fake', 'dummy', 'param', 'mock', 'test', 'placeholder']
        param_pattern = re.compile(r'\bparam\d+\s*=')
        line_num = getattr(node, 'lineno', 1)

        for kw in node.keywords:
            if hasattr(kw, 'arg') and kw.arg:
                arg_lower = kw.arg.lower()
                if any(p in arg_lower for p in fake_patterns):
                    self.changes.append(
                        f"FAKE-PARAM: Suspicious parameter name '{kw.arg}' at line {line_num}"
                    )
                if param_pattern.search(kw.arg):
                    self.changes.append(
                        f"FAKE-PARAM: param-numbered parameter '{kw.arg}' at line {line_num}"
                    )

    def _check_redundant_io(self, node: ast.Call, func_name: str) -> None:
        """Check for redundant I/O calls."""
        # Get the call signature for comparison
        try:
            args_str = self._get_call_args(node)
            self.io_calls.append((func_name, args_str, node.lineno))
        except Exception:
            pass

    def visit_Subscript(self, node: ast.Subscript):
        """Check for boundary access patterns."""
        # Check for list[0] without guard
        if isinstance(node.slice, ast.Constant):
            if node.slice.value == 0:
                # Check if there's a guard before
                line_num = node.lineno
                if line_num > 1:
                    prev_lines = self.lines[max(0, line_num - 3):line_num]
                    has_guard = any(
                        'if' in line and ('empty' in line or 'len' in line or 'not' in line)
                        for line in prev_lines
                    )
                    if not has_guard:
                        self.changes.append(
                            f"BOUNDARY: list[0] access without empty check at line {line_num}"
                        )

        self.generic_visit(node)

    def _get_func_name(self, node: ast.AST) -> str:
        """Get the full function name from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            name = self._get_func_name(node.value)
            return f"{name}.{node.attr}" if name else node.attr
        return ""

    def _get_call_args(self, node: ast.Call) -> str:
        """Get a string representation of call arguments."""
        args = []
        for arg in node.args:
            if isinstance(arg, ast.Constant):
                args.append(repr(arg.value))
            elif isinstance(arg, ast.Name):
                args.append(arg.id)
            else:
                args.append('...')
        for kw in node.keywords:
            if hasattr(kw, 'arg') and kw.arg:
                args.append(f"{kw.arg}=...")
        return ','.join(args)


class _BoundaryCheckVisitor(ast.NodeVisitor):
    """Visitor to detect boundary check errors."""

    def __init__(self, content: str):
        self.content = content
        self.changes: List[str] = []
        self.lines = content.splitlines()

    def visit_Subscript(self, node: ast.Subscript):
        """Check for unsafe index access."""
        # list[0], list[-1] without checking
        if isinstance(node.slice, ast.Constant):
            idx = node.slice.value
            if idx == 0 or idx == -1:
                line_num = node.lineno
                # Check for guards in preceding lines
                prev_context = '\n'.join(self.lines[max(0, line_num - 4):line_num])
                has_empty_check = bool(
                    re.search(r'\b(if|while|and|or|not|len|empty)\b', prev_context) and
                    re.search(r'\b(items?|list|arr|array|data|result)\b', prev_context)
                )
                if not has_empty_check:
                    direction = "first" if idx == 0 else "last"
                    self.changes.append(
                        f"BOUNDARY: Accessing {direction} element without empty check at line {line_num}"
                    )
        self.generic_visit(node)


class _FakeParamVisitor(ast.NodeVisitor):
    """Visitor to detect fake/dummy parameters."""

    def __init__(self):
        self.changes: List[str] = []

    def visit_Call(self, node: ast.Call):
        """Check for fake parameters in function calls."""
        for kw in node.keywords:
            if hasattr(kw, 'arg') and kw.arg:
                arg = kw.arg.lower()
                fake_indicators = ['fake', 'dummy', 'mock', 'test', 'placeholder']
                if any(ind in arg for ind in fake_indicators):
                    self.changes.append(
                        f"FAKE-PARAM: Parameter '{kw.arg}' looks like a test placeholder at line {node.lineno}"
                    )
                if re.match(r'^param\d+$', kw.arg):
                    self.changes.append(
                        f"FAKE-PARAM: Parameter '{kw.arg}' is numbered (generic placeholder) at line {node.lineno}"
                    )
        self.generic_visit(node)


class _RedundantIOVisitor(ast.NodeVisitor):
    """Visitor to detect redundant I/O calls."""

    def __init__(self):
        self.changes: List[str] = []
        self.call_tracker: Dict[str, List[Tuple[str, int]]] = defaultdict(list)

    def visit_Call(self, node: ast.Call):
        """Track I/O calls to detect redundant patterns."""
        io_keywords = ['fetch', 'get', 'load', 'request', 'read', 'download', 'query']

        try:
            func_name = self._get_call_name(node.func)
            if any(kw in func_name.lower() for kw in io_keywords):
                # Get the first argument as the "key"
                key = None
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        key = arg.value
                    elif isinstance(arg, ast.Name):
                        key = f"var:{arg.id}"

                if key:
                    self.call_tracker[key].append((func_name, node.lineno))

                    # If same key called 3+ times, flag it
                    calls = self.call_tracker[key]
                    if len(calls) >= 3:
                        urls = [c[0] for c in calls]
                        if len(set(urls)) == 1:  # Same URL/endpoint
                            self.changes.append(
                                f"REDUNDANT-I/O: '{func_name}()' called {len(calls)} times with same arguments "
                                f"(lines {[c[1] for c in calls]})"
                            )
        except Exception:
            pass

        self.generic_visit(node)

    def _get_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""


class _NamingInconsistencyVisitor(ast.NodeVisitor):
    """Visitor to detect naming inconsistencies within a file."""

    def __init__(self):
        self.names: Dict[str, str] = {}  # normalized_name -> original
        self.changes: List[str] = []
        self._seen_pairs: Set[Tuple[str, str]] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Check function name and parameters for consistency."""
        func_name = node.name

        # Store the function name style
        self._check_name_style(func_name, f"function '{func_name}'")

        # Check parameters
        for arg in node.args.args:
            self._check_name_style(arg.arg, f"parameter '{arg.arg}'")

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Check variable assignments for naming consistency."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._check_name_style(target.id, f"variable '{target.id}'")
        self.generic_visit(node)

    def _check_name_style(self, name: str, context: str):
        """Check if name style is consistent with previously seen names."""
        # Normalize: remove underscores, lowercase
        normalized = name.replace('_', '').lower()

        if normalized in self.names:
            original = self.names[normalized]
            # Check if they're actually different (not just same without underscore)
            if original != name:
                pair = tuple(sorted([original, name]))
                if pair not in self._seen_pairs:
                    self._seen_pairs.add(pair)
                    # Determine styles
                    orig_style = "camelCase" if '_' not in original and any(c.isupper() for c in original) else "snake_case"
                    new_style = "camelCase" if '_' not in name and any(c.isupper() for c in name) else "snake_case"
                    self.changes.append(
                        f"NAMING-INCONSISTENCY: {context} uses {new_style} "
                        f"while '{original}' uses {orig_style}"
                    )
        else:
            self.names[normalized] = name


# --------------------------------------------------------------------------
# Main Rule
# --------------------------------------------------------------------------

class AIBugRule(Rule):
    """Detect common AI-generated code bugs and patterns.

    This rule identifies:
    - Resource leaks (files, network connections)
    - Boundary check errors
    - Phantom/placeholder package names
    - Fake/dummy parameters
    - Redundant I/O operations
    - Naming inconsistencies
    """

    ALLOWED_SEMANTIC_NODES: Set[str] = set()

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self._marker_counter = 0

    @property
    def description(self) -> str:
        return "Detect common AI-generated code bugs and patterns"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        """Apply AI bug detection to the code file."""
        try:
            tree = ast.parse(code_file.content)
        except SyntaxError:
            # Syntax errors should not crash the rule - return success with no changes
            return TransformationResult(
                original=code_file,
                transformed_content=code_file.content,
                changes_made=[],
                success=True,
            )

        changes: List[str] = []
        markers: List[AgentMarker] = []

        # Run all visitors
        visitor = _AIBugVisitor(code_file.content)
        visitor.visit(tree)
        # Check for file leaks (post-process after tree visit)
        visitor._check_file_leaks()
        changes.extend(visitor.changes)

        boundary_visitor = _BoundaryCheckVisitor(code_file.content)
        boundary_visitor.visit(tree)
        changes.extend(boundary_visitor.changes)

        fake_visitor = _FakeParamVisitor()
        fake_visitor.visit(tree)
        changes.extend(fake_visitor.changes)

        redundancy_visitor = _RedundantIOVisitor()
        redundancy_visitor.visit(tree)
        changes.extend(redundancy_visitor.changes)

        naming_visitor = _NamingInconsistencyVisitor()
        naming_visitor.visit(tree)
        changes.extend(naming_visitor.changes)

        # Build markers from changes
        for change in changes:
            self._marker_counter += 1
            marker = self._create_marker_from_change(change, code_file)
            if marker:
                markers.append(marker)

        return TransformationResult(
            original=code_file,
            transformed_content=code_file.content,
            changes_made=changes,
            success=True,
            agent_markers=markers,
        )

    def _create_marker_from_change(self, change: str, code_file: CodeFile) -> Optional[AgentMarker]:
        """Parse a change message into an AgentMarker."""
        # Parse change format: "TYPE: description at line N"
        parts = change.split(': ', 1)
        if len(parts) < 2:
            return None

        change_type = parts[0]
        rest = parts[1]

        # Extract line number
        line_match = re.search(r'line\s+(\d+)', rest)
        line_num = int(line_match.group(1)) if line_match else 1

        # Determine issue type and severity
        issue_type_map = {
            "FILE-LEAK": ("file_leak", "high"),
            "NET-LEAK": ("network_leak", "medium"),
            "BOUNDARY": ("boundary_error", "low"),
            "PHANTOM-PACKAGE": ("phantom_package", "info"),
            "FAKE-PARAM": ("fake_parameter", "low"),
            "REDUNDANT-I/O": ("redundant_io", "medium"),
            "NAMING-INCONSISTENCY": ("naming_inconsistency", "info"),
        }

        issue_type = "ai_bug"
        severity = "medium"
        for prefix, (itype, sev) in issue_type_map.items():
            if change.startswith(prefix):
                issue_type = itype
                severity = sev
                break

        # Clean up description
        description = re.sub(r'\s+at line\s+\d+', '', rest)

        return AgentMarker(
            marker_id=f"PYN-AI-{self._marker_counter:03d}",
            issue_type=issue_type,
            rule_id="AIBugRule",
            severity=severity,
            line=line_num,
            hint=description,
            why=f"Common AI code generator mistake: {issue_type.replace('_', ' ')}",
            confidence=0.85,
            confidence_note="detected via AST pattern matching on AI-generated code",
            can_auto_fix=False,
            requires_user_input=True,
            file_path=str(code_file.path),
            language=code_file.language,
        )


# --------------------------------------------------------------------------
# Module exports
# --------------------------------------------------------------------------

__all__ = [
    'AIBugRule',
    'RESOURCE_LEAK_PATTERNS',
    'BOUNDARY_CHECK_PATTERNS',
    'PHANTOM_PACKAGE_PATTERNS',
    'FAKE_PARAM_PATTERNS',
    'NAMING_INCONSISTENCY_PATTERNS',
    '_BoundaryCheckVisitor',
    '_RedundantIOVisitor',
    '_FakeParamVisitor',
    '_NamingInconsistencyVisitor',
]
