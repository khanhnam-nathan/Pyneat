"""Rule for removing debug artifacts left by AI code generators."""

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
    """

    DEBUG_COMMENT_RE = re.compile(
        r'^\s*#.*\b(debug|breakpoint|log\s*:|print\s*:|dbg|dbug)\b.*$',
        re.IGNORECASE | re.MULTILINE,
    )
    PDB_TRACE_RE = re.compile(
        r'import\s+pdb\s*;?\s*pdb\.set_trace\(\)'
        r'|import\s+ipdb\s*;?\s*ipdb\.set_trace\(\)'
        r'|import\s+ pudb\s*;?\s*pudb\.set_trace\(\)'
        r'|from\s+pdb\s+import\s+set_trace\s*;?\s*set_trace\(\)',
        re.IGNORECASE,
    )
    DEBUG_KEYWORDS = {'debug', 'test', 'temp', 'here', 'check', 'foo', 'bar'}
    LOG_LEVEL_RE = re.compile(r'^\s*\[(INFO|WARN|ERROR|DEBUG|TRACE|FATAL)\]', re.IGNORECASE)

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

            if self.mode != 'off':
                new_content, comment_count = self._remove_debug_comments(content)
                if comment_count:
                    changes.append(f"Removed {comment_count} debug comment(s)")
                content = new_content

                new_content, pdb_count = self._remove_debugger_imports(content)
                if pdb_count:
                    changes.append(f"Removed {pdb_count} debugger import/call(s)")
                content = new_content

            if self.mode == 'aggressive':
                new_content, print_count = self._remove_all_prints(content)
                if print_count:
                    changes.append(f"Removed {print_count} print/console.log call(s)")
                content = new_content
            elif self.mode == 'safe':
                new_content, print_count = self._remove_debug_prints(content)
                if print_count:
                    changes.append(f"Removed {print_count} debug print(s)")
                content = new_content

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"DebugCleaner failed: {str(e)}")

    def _remove_debug_comments(self, content: str) -> tuple[str, int]:
        lines = content.split('\n')
        new_lines = []
        removed = 0
        for line in lines:
            if self.DEBUG_COMMENT_RE.match(line):
                removed += 1
            else:
                new_lines.append(line)
        return '\n'.join(new_lines), removed

    def _remove_debugger_imports(self, content: str) -> tuple[str, int]:
        lines = content.split('\n')
        new_lines = []
        removed = 0
        for line in lines:
            if self.PDB_TRACE_RE.search(line):
                removed += 1
            else:
                new_lines.append(line)
        return '\n'.join(new_lines), removed

    def _remove_all_prints(self, content: str) -> tuple[str, int]:
        """Remove ALL print/console.log calls (aggressive mode)."""
        try:
            module = cst.parse_module(content)
        except Exception:
            return content, 0
        transformer = _AggressivePrintRemover()
        new_module = module.visit(transformer)
        return new_module.code, transformer.removed_count

    def _remove_debug_prints(self, content: str) -> tuple[str, int]:
        """Remove only debug-like print calls (safe mode)."""
        try:
            module = cst.parse_module(content)
        except Exception:
            return content, 0
        transformer = _SafePrintRemover()
        new_module = module.visit(transformer)
        return new_module.code, transformer.removed_count


class _AggressivePrintRemover(cst.CSTTransformer):
    """Removes ALL print/console.log calls."""

    def __init__(self):
        super().__init__()
        self.removed_count = 0

    def _is_print_call(self, node: cst.CSTNode) -> bool:
        if not isinstance(node, cst.Call):
            return False
        func = node.func
        if isinstance(func, cst.Name):
            return func.value in ('print', 'console')
        if isinstance(func, cst.Attribute):
            name = self._get_name(func)
            return name in ('console.log',)
        return False

    def leave_Expr(self, original: cst.Expr, updated: cst.Expr) -> cst.Expr | cst.RemovalSentinel:
        if self._is_print_call(original.value):
            self.removed_count += 1
            return cst.RemovalSentinel.REMOVE
        return updated

    def _get_name(self, node: cst.CSTNode) -> str:
        if isinstance(node, cst.Name):
            return node.value
        if isinstance(node, cst.Attribute):
            base = self._get_name(node.value)
            attr = self._get_name(node.attr)
            return f"{base}.{attr}"
        return ""


class _SafePrintRemover(cst.CSTTransformer):
    """Smart removal: only removes debug-like prints."""

    DEBUG_KEYWORDS = {'debug', 'test', 'temp', 'here', 'check', 'foo', 'bar'}
    LOG_LEVEL_RE = re.compile(r'^\s*\[(INFO|WARN|ERROR|DEBUG|TRACE|FATAL)\]', re.IGNORECASE)

    def __init__(self):
        super().__init__()
        self.removed_count = 0

    def _is_print_call(self, node: cst.CSTNode) -> bool:
        if not isinstance(node, cst.Call):
            return False
        func = node.func
        if isinstance(func, cst.Name):
            return func.value in ('print', 'console')
        if isinstance(func, cst.Attribute):
            name = self._get_name(func)
            return name in ('console.log',)
        return False

    def _get_name(self, node: cst.CSTNode) -> str:
        if isinstance(node, cst.Name):
            return node.value
        if isinstance(node, cst.Attribute):
            base = self._get_name(node.value)
            attr = self._get_name(node.attr)
            return f"{base}.{attr}"
        return ""

    def _is_debug_print(self, call_node: cst.Call) -> bool:
        """Check if print call is a debug artifact (should be removed)."""
        args = list(call_node.args)

        # Empty print() → remove
        if len(args) == 0:
            return True

        first_arg = args[0].value

        # 1. Check for log level pattern: [INFO], [WARN], etc.
        if isinstance(first_arg, cst.SimpleString):
            if self.LOG_LEVEL_RE.match(first_arg.value):
                return True

        # 2. Check for keyword-based debug detection
        if isinstance(first_arg, (cst.SimpleString, cst.ConcatenatedString)):
            text = self._extract_string_text(first_arg).lower()
            text_clean = re.sub(r'["\'\[\]]', '', text)
            words = set(text_clean.split())
            if words & self.DEBUG_KEYWORDS:
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

    def leave_Expr(self, original: cst.Expr, updated: cst.Expr) -> cst.Expr | cst.RemovalSentinel:
        if not isinstance(original.value, cst.Call):
            return updated

        func = original.value.func
        is_console_log = False
        if isinstance(func, cst.Attribute):
            name = self._get_name(func)
            is_console_log = name == 'console.log'

        # Always remove console.log (always debug artifact in Python)
        if is_console_log:
            self.removed_count += 1
            return cst.RemovalSentinel.REMOVE

        # For print calls, apply debug detection
        if self._is_print_call(original.value) and self._is_debug_print(original.value):
            self.removed_count += 1
            return cst.RemovalSentinel.REMOVE
        return updated
