"""Rule for removing debug artifacts left by AI code generators.

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

For commercial licensing, contact: license@pyneat.dev
"""

import re
from typing import List, Literal
import libcst as cst

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class DebugCleaner(Rule):
    """Removes debug artifacts: print() calls, console.log, pdb/ipdb breakpoints, and debug comments.
    
    Supports 3 modes:
    - 'safe': (default) Only removes prints that are clearly debug artifacts
    - 'aggressive': Removes ALL print/console.log calls
    - 'off': Keeps all print calls (no removal)

    OPTIMIZED: Single CST parse for all transformations.
    """

    DEBUG_COMMENT_RE = re.compile(
        r'^\s*#.*\b(debug|breakpoint|log\s*:|print\s*:|dbg|dbug)\b.*$',
        re.IGNORECASE | re.MULTILINE,
    )
    # Pre-compiled regex for fast PDB line detection
    PDB_LINE_RE = re.compile(
        r'\bpdb\.set_trace\(\)'
        r'|\bipdb\.set_trace\(\)'
        r'|\bpudb\.set_trace\(\)'
        r'|\bset_trace\(\)',
    )
    DEBUG_KEYWORDS = frozenset({
        'debug', 'test', 'temp', 'here', 'check', 'foo', 'bar',
        'tmp', 'dump', 'snapshot', 'debugging',
        'result', 'output', 'value', 'xwyn', 'x1', 'x2',
        'val', 'res', 'out', 'buf', 'log', 'dat',
        'helper', 'util', 'misc', 'zzz', 'aaa', 'abc',
        'temp1', 'temp2', 'test1', 'result1',
    })
    LOG_LEVEL_RE = re.compile(r'["\']?\s*\[(INFO|WARN|ERROR|DEBUG|TRACE|FATAL)\]', re.IGNORECASE)

    def __init__(self, mode: Literal['safe', 'aggressive', 'off'] = 'safe'):
        self.mode = mode
        self._name = "DebugCleaner"
        self.config = RuleConfig(enabled=True)

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return f"Removes debug artifacts (mode={self.mode})"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            if self.mode == 'off':
                return self._create_result(code_file, content, changes)

            # Single CST parse for all transformations
            try:
                module = cst.parse_module(content)
            except Exception:
                return self._create_result(code_file, content, changes)

            # Pre-scan for comment/pdb counts (fast text operations)
            comment_count = len(self.DEBUG_COMMENT_RE.findall(content))
            pdb_count = len(self.PDB_LINE_RE.findall(content))

            # Apply unified transformer ONCE
            transformer = _UnifiedDebugTransformer(
                mode=self.mode,
                remove_comments=comment_count > 0,
                remove_pdb=pdb_count > 0,
            )
            new_module = module.visit(transformer)
            changes.extend(transformer.changes_made)
            content = new_module.code

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"DebugCleaner failed: {str(e)}")


class _UnifiedDebugTransformer(cst.CSTTransformer):
    """Single CST transformer that removes comments, pdb imports, and prints.

    OPTIMIZED: Handles both safe and aggressive modes in one pass.
    """

    DEBUG_KEYWORDS = frozenset({
        'debug', 'test', 'temp', 'here', 'check', 'foo', 'bar',
        'tmp', 'dump', 'snapshot', 'debugging',
        'result', 'output', 'value', 'xwyn', 'x1', 'x2',
        'val', 'res', 'out', 'buf', 'log', 'dat',
        'helper', 'util', 'misc', 'zzz', 'aaa', 'abc',
        'temp1', 'temp2', 'test1', 'result1',
    })
    LOG_LEVEL_RE = re.compile(r'["\']?\s*\[(INFO|WARN|ERROR|DEBUG|TRACE|FATAL)\]', re.IGNORECASE)

    def __init__(self, mode: str, remove_comments: bool = True, remove_pdb: bool = True):
        super().__init__()
        self.mode = mode
        self.remove_comments = remove_comments
        self.remove_pdb = remove_pdb
        self.removed_comments = 0
        self.removed_pdb = 0
        self.removed_prints = 0
        self.changes_made: List[str] = []
        self._pending_pdb_import = False

    def _is_debug_print(self, call_node: cst.Call) -> bool:
        """Check if print call is a debug artifact."""
        args = list(call_node.args)
        if len(args) == 0:
            return True
        if not args:
            return False

        first_arg = args[0].value

        # 1. Check for log level pattern
        if isinstance(first_arg, cst.SimpleString):
            if self.LOG_LEVEL_RE.match(first_arg.value):
                return True

        # 2. Check for keyword-based debug detection
        if isinstance(first_arg, (cst.SimpleString, cst.ConcatenatedString)):
            text = self._extract_string_text(first_arg).lower()
            text_clean = re.sub(r'["\'\[\]:]', '', text)
            words = text_clean.split()
            for word in words:
                if word in self.DEBUG_KEYWORDS:
                    return True

        # 3. Variable dump: single variable without description
        if len(args) == 1 and isinstance(first_arg, (cst.Name, cst.Attribute, cst.BinaryOperation, cst.UnaryOperation)):
            return True

        # 4. Check f-string with only expressions, no literal text
        if isinstance(first_arg, cst.FormattedString):
            try:
                has_text = any(isinstance(e, cst.FormattedStringText) and e.value.strip()
                              for e in first_arg.expressions)
                if not has_text:
                    return True
            except AttributeError:
                pass

        return False

    def _extract_string_text(self, node: cst.SimpleString | cst.ConcatenatedString) -> str:
        """Extract text content from a string node."""
        if isinstance(node, cst.SimpleString):
            return node.value[1:-1]
        elif isinstance(node, cst.ConcatenatedString):
            parts = []
            for part in node.left.parts if hasattr(node, 'left') else []:
                if isinstance(part, cst.SimpleString):
                    parts.append(part.value[1:-1])
            for part in node.right.parts if hasattr(node, 'right') else []:
                if isinstance(part, cst.SimpleString):
                    parts.append(part.value[1:-1])
            return ''.join(parts)
        return ""

    def _is_print_call(self, node: cst.CSTNode) -> bool:
        """Check if node is a print/console call."""
        if not isinstance(node, cst.Call):
            return False
        func = node.func
        if isinstance(func, cst.Name):
            return func.value in ('print', 'console')
        if isinstance(func, cst.Attribute):
            name = self._get_call_name(func)
            return name in ('console.log',)
        return False

    def _get_call_name(self, node: cst.CSTNode) -> str:
        if isinstance(node, cst.Name):
            return node.value
        if isinstance(node, cst.Attribute):
            base = self._get_call_name(node.value)
            attr = self._get_call_name(node.attr)
            return f"{base}.{attr}" if base else attr
        return ""

    def leave_Comment(self, original: cst.Comment, updated: cst.Comment) -> cst.CSTNode | cst.RemovalSentinel:
        if not self.remove_comments:
            return updated
        text = original.value.lower()
        debug_keywords = {'debug', 'breakpoint', 'log', 'dbg', 'dbug'}
        if any(kw in text for kw in debug_keywords):
            self.removed_comments += 1
            return cst.RemovalSentinel.REMOVE
        return updated

    def leave_SimpleStatementLine(
        self, original: cst.SimpleStatementLine, updated: cst.SimpleStatementLine
    ) -> cst.BaseStatement:
        """Remove entire lines containing pdb imports or set_trace calls.

        Handles both standalone lines and semicolon-separated patterns like:
        - 'import pdb; pdb.set_trace()'
        - 'pdb.set_trace()'
        """
        if not self.remove_pdb:
            return updated

        body = original.body
        if not body:
            return updated

        # Check for pdb patterns in the entire line
        has_pdb_import = False
        has_set_trace = False

        for stmt in body:
            # Check for import pdb / import ipdb / import pudb
            if isinstance(stmt, cst.Import):
                for alias in stmt.names:
                    name = self._get_import_name(alias.name)
                    if name in ('pdb', 'ipdb', 'pudb'):
                        has_pdb_import = True
            # Check for pdb.set_trace() call
            elif isinstance(stmt, cst.Expr) and isinstance(stmt.value, cst.Call):
                func = stmt.value.func
                name = self._get_call_name(func)
                if name in ('pdb.set_trace', 'ipdb.set_trace', 'pudb.set_trace'):
                    has_set_trace = True

        # Remove line if it has pdb import AND set_trace call
        if has_pdb_import and has_set_trace:
            self.removed_pdb += 1
            return cst.RemovalSentinel.REMOVE

        # Remove standalone pdb.set_trace() lines
        if len(body) == 1:
            stmt = body[0]
            if isinstance(stmt, cst.Expr):
                if isinstance(stmt.value, cst.Call):
                    func = stmt.value.func
                    name = self._get_call_name(func)
                    if name in ('pdb.set_trace', 'ipdb.set_trace', 'pudb.set_trace', 'set_trace'):
                        self.removed_pdb += 1
                        return cst.RemovalSentinel.REMOVE

        return updated

    def leave_Expr(self, original: cst.Expr, updated: cst.Expr) -> cst.Expr | cst.RemovalSentinel:
        if not isinstance(original.value, cst.Call):
            return updated

        func = original.value.func
        name = self._get_call_name(func)
        is_console_log = name == 'console.log'
        is_print = isinstance(func, cst.Name) and func.value == 'print'

        if is_console_log:
            self.removed_prints += 1
            return cst.RemovalSentinel.REMOVE

        if is_print:
            if self.mode == 'aggressive':
                self.removed_prints += 1
                return cst.RemovalSentinel.REMOVE
            if self._is_debug_print(original.value):
                self.removed_prints += 1
                return cst.RemovalSentinel.REMOVE

        return updated

    def leave_Module(self, original: cst.Module, updated: cst.Module) -> cst.Module:
        if self.removed_comments > 0:
            self.changes_made.append(f"Removed {self.removed_comments} debug comment(s)")
        if self.removed_pdb > 0:
            self.changes_made.append(f"Removed {self.removed_pdb} debugger import/call(s)")
        if self.removed_prints > 0:
            self.changes_made.append(f"Removed {self.removed_prints} print/console.log call(s)")
        return updated

    def leave_Import(self, original: cst.Import, updated: cst.Import) -> cst.Import:
        """Track pdb imports for later removal in leave_SimpleStatementLine."""
        if not self.remove_pdb:
            return updated
        for alias in original.names:
            name = self._get_import_name(alias.name)
            if name in ('pdb', 'ipdb', 'pudb'):
                # Mark that this import should trigger line removal
                self._pending_pdb_import = True
                return updated
        return updated

    def leave_ImportFrom(self, original: cst.ImportFrom, updated: cst.ImportFrom) -> cst.ImportFrom:
        """Track pdb imports for later removal."""
        if not self.remove_pdb:
            return updated
        module_name = ""
        if original.module:
            if isinstance(original.module, cst.Name):
                module_name = original.module.value
        if module_name in ('pdb', 'ipdb', 'pudb'):
            self._pending_pdb_import = True
        return updated

    def leave_SimpleStatementLine(
        self, original: cst.SimpleStatementLine, updated: cst.SimpleStatementLine
    ) -> cst.BaseStatement:
        """Remove entire lines containing pdb imports or set_trace calls.

        Handles patterns like:
        - 'import pdb; pdb.set_trace()'
        - 'pdb.set_trace()'
        """
        if not self.remove_pdb:
            return updated

        body = original.body
        if not body:
            return updated

        # Check for 'import pdb; pdb.set_trace()' pattern
        # This is a single SimpleStatementLine with 2 statements
        if len(body) == 2:
            stmt0 = body[0]
            stmt1 = body[1]
            has_pdb_import = False
            has_set_trace = False

            if isinstance(stmt0, cst.Import):
                for alias in stmt0.names:
                    name = self._get_import_name(alias.name)
                    if name in ('pdb', 'ipdb', 'pudb'):
                        has_pdb_import = True

            if isinstance(stmt1, cst.Expr) and isinstance(stmt1.value, cst.Call):
                func = stmt1.value.func
                name = self._get_call_name(func)
                if name in ('pdb.set_trace', 'ipdb.set_trace', 'pudb.set_trace'):
                    has_set_trace = True

            if has_pdb_import and has_set_trace:
                self.removed_pdb += 1
                # Clear the pending flag
                self._pending_pdb_import = False
                return cst.RemovalSentinel.REMOVE

        # Check standalone 'pdb.set_trace()' lines
        if len(body) == 1:
            stmt = body[0]
            if isinstance(stmt, cst.Expr):
                if isinstance(stmt.value, cst.Call):
                    func = stmt.value.func
                    name = self._get_call_name(func)
                    if name in ('pdb.set_trace', 'ipdb.set_trace', 'pudb.set_trace', 'set_trace'):
                        self.removed_pdb += 1
                        return cst.RemovalSentinel.REMOVE

        return updated

    def _get_import_name(self, name_node: cst.CSTNode) -> str:
        """Extract import name from Name or Attribute node."""
        if isinstance(name_node, cst.Name):
            return name_node.value
        if isinstance(name_node, cst.Attribute):
            base = self._get_import_name(name_node.value)
            attr = self._get_import_name(name_node.attr)
            return f"{base}.{attr}" if base else attr
        return ""
