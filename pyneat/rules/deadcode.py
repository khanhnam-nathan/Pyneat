"""Rule for detecting and removing dead/unused code (functions, classes, methods).

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

import ast
import re
from typing import List, Set, Tuple, Optional

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule
from pyneat.core.scope_guard import ScopeGuard


class DeadCodeRule(Rule):
    """Detects and removes dead/unused code using AST analysis.

    Identifies:
      - Unused functions (defined but never called)
      - Unused classes (defined but never instantiated)
      - Unused methods (defined but never called from within the class)
      - Unused private functions (optional, configurable)

    Preserves:
      - Functions in `if __name__ == "__main__"` blocks
      - Functions with `@export`, `@public`, `@register` decorators
      - Entry points: main, cli, run, app, serve
      - Functions with side effects (yield, raise, I/O)
      - Built-in magic methods: __init__, __str__, __repr__, etc.
    """

    ALLOWED_SEMANTIC_NODES: Set[str] = {
        "FunctionDef", "AsyncFunctionDef", "ClassDef",
        "Assign", "AnnAssign",  # Removing functions/classes also removes their local variables
        "Try",  # Try blocks can be removed when the containing function is removed
    }

    PRESERVE_DECORATORS: frozenset = frozenset({
        'export', 'public', 'register', 'app.route', 'route',
        'app.command', 'command', 'cli.command', 'click.command',
        'property', 'cached_property', 'lru_cache', 'staticmethod',
        'classmethod',
    })

    ENTRY_POINT_NAMES: frozenset = frozenset({
        'main', 'cli', 'run', 'app', 'serve', 'start', 'execute',
        'init', 'initialize', 'setup', 'configure',
    })

    MAGIC_METHODS: frozenset = frozenset({
        '__init__', '__new__', '__del__', '__repr__', '__str__',
        '__bytes__', '__hash__', '__bool__', '__format__', '__lt__',
        '__le__', '__eq__', '__ne__', '__gt__', '__ge__', '__compare__',
        '__abs__', '__add__', '__sub__', '__mul__', '__matmul__',
        '__truediv__', '__floordiv__', '__mod__', '__divmod__',
        '__pow__', '__and__', '__or__', '__xor__', '__lshift__',
        '__rshift__', '__radd__', '__rmul__', '__rsub__', '__rtruediv__',
        '__rfloordiv__', '__rmod__', '__rdivmod__', '__rpow__',
        '__rand__', '__ror__', '__rxor__', '__rlshift__', '__rrshift__',
        '__iadd__', '__isub__', '__imul__', '__imatmul__', '__itruediv__',
        '__ifloordiv__', '__imod__', '__ipow__', '__iand__', '__ior__',
        '__ixor__', '__ilshift__', '__irshift__', '__neg__', '__pos__',
        '__invert__', '__call__', '__contains__', '__iter__', '__reversed__',
        '__next__', '__getitem__', '__setitem__', '__delitem__',
        '__getslice__', '__setslice__', '__delslice__', '__len__',
        '__length_hint__', '__missing__', '__enter__', '__exit__',
        '__getattribute__', '__getattr__', '__setattr__', '__delattr__',
        '__dir__', '__get__', '__set__', '__delete__', '__set_name__',
        '__slots__', '__class__', '__bases__', '__mro__', '__subclasses__',
    })

    @property
    def description(self) -> str:
        return "Removes dead/unused code (functions, classes, methods) using AST analysis"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes)

            # Use cached AST if available (RuleEngine pre-parses)
            ast_tree = None
            if hasattr(code_file, 'ast_tree') and code_file.ast_tree is not None:
                ast_tree = code_file.ast_tree

            new_content, removed_items = self._remove_dead_code(content, ast_tree)
            for item in removed_items:
                changes.append(f"Removed dead code: {item}")

            return self._create_result(code_file, new_content, changes)

        except SyntaxError:
            return self._create_result(code_file, code_file.content, [])

        except Exception as e:
            return self._create_error_result(
                code_file, f"DeadCodeRule failed: {str(e)}"
            )

    def _remove_dead_code(self, content: str, ast_tree=None) -> Tuple[str, List[str]]:
        """Return (new_content, list_of_removed_items)."""
        try:
            tree = ast.parse(content) if ast_tree is None else ast_tree
        except SyntaxError:
            return content, []

        # Collect all defined and referenced names
        defined_funcs, defined_classes = self._collect_definitions(tree)
        all_references = self._collect_references(tree)
        referenced_names = self._collect_name_references(tree)

        # Combine all references
        all_references.update(referenced_names)

        # Determine dead code
        dead_funcs, dead_classes = self._find_dead_code(
            tree, defined_funcs, defined_classes,
            all_references, content
        )

        # Find dead branches (constant-condition branches) — report as suggestions
        dead_branch_items = self._find_dead_branches(tree, content)

        # Layer 4: ScopeGuard — filter out items still referenced downstream
        scope_guard = ScopeGuard()
        all_dead = dead_funcs + dead_classes
        safe_dead, scope_warnings = scope_guard.check_dead_code_safe(content, all_dead)

        # Split back into funcs and classes
        dead_funcs = [d for d in safe_dead if "func" in d.get("type", "func")]
        dead_classes = [d for d in safe_dead if "class" in d.get("type", "class")]

        if not dead_funcs and not dead_classes and not dead_branch_items:
            return content, []

        # Remove dead code from content
        lines = content.split('\n')
        removed_items: List[str] = []

        for func_info in dead_funcs:
            func_name = func_info['name']
            start, end = func_info['start'], func_info['end']
            self._remove_lines(lines, start, end)
            removed_items.append(f"unused function: {func_name}()")

        for class_info in dead_classes:
            class_name = class_info['name']
            start, end = class_info['start'], class_info['end']
            self._remove_lines(lines, start, end)
            removed_items.append(f"unused class: {class_name}")

        # Mark dead branches as suggestions (don't auto-remove — too risky)
        for branch in dead_branch_items:
            removed_items.append(f"Dead branch detected: {branch}")

        # Log scope warnings as informational changes
        for warning in scope_warnings:
            removed_items.append(f"SCOPE GUARD: {warning}")

        # Clean up blank lines
        new_content = self._cleanup_blank_lines('\n'.join(lines))

        return new_content, removed_items

    def _collect_definitions(self, tree: ast.AST) -> Tuple[Set[str], Set[str]]:
        """Collect top-level function and class names (not methods)."""
        funcs: Set[str] = set()
        classes: Set[str] = set()

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not self._is_method(node, tree):
                    funcs.add(node.name)
            elif isinstance(node, ast.ClassDef):
                classes.add(node.name)

        return funcs, classes

    def _is_method(self, node: ast.FunctionDef | ast.AsyncFunctionDef, tree: ast.AST) -> bool:
        """Check if a FunctionDef is a method inside a ClassDef.

        ast.walk() descends INTO a node's children, so it can't be used to find
        parents. We check if the function is a direct child of tree.body instead.
        If it is, it's top-level. Otherwise it's inside a class (method).
        """
        return node not in tree.body

    def _collect_references(self, tree: ast.AST) -> Set[str]:
        """Collect all function/class names that are called or instantiated."""
        references: Set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    references.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        references.add(node.func.value.id)

        return references

    def _collect_name_references(self, tree: ast.AST) -> Set[str]:
        """Collect all name references (for attribute access patterns)."""
        references: Set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                references.add(node.id)
            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name):
                    references.add(node.value.id)

        return references

    def _find_dead_code(
        self,
        tree: ast.AST,
        defined_funcs: Set[str],
        defined_classes: Set[str],
        all_references: Set[str],
        content: str
    ) -> Tuple[List[dict], List[dict]]:
        """Find dead functions and classes."""
        dead_funcs: List[dict] = []
        dead_classes: List[dict] = []

        # Find dead functions
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                func_info = self._check_dead_function(
                    node, defined_funcs, all_references, content
                )
                if func_info:
                    dead_funcs.append(func_info)

        # Find dead classes
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                class_info = self._check_dead_class(
                    node, defined_classes, all_references, content
                )
                if class_info:
                    dead_classes.append(class_info)

        return dead_funcs, dead_classes

    def _check_dead_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        all_funcs: Set[str],
        all_references: Set[str],
        content: str
    ) -> Optional[dict]:
        """Check if a function is dead code."""
        name = node.name

        # Never remove entry point names
        if name in self.ENTRY_POINT_NAMES:
            return None

        # Never remove main block
        if self._is_in_main_block(node, content):
            return None

        # Check decorators - ANY decorator suggests the function/class is meant to be used
        if node.decorator_list:
            return None

        # Check for side effects (yield, raise, I/O)
        if self._has_side_effects(node):
            return None

        # Never remove magic methods (even if unreferenced)
        if name in self.MAGIC_METHODS:
            return None

        # Check if it's referenced as an attribute
        if name in all_funcs and self._is_used_as_attribute(name, node, all_references):
            return None

        return {
            'name': name,
            'start': node.lineno,
            'end': node.end_lineno or node.lineno,
            'type': 'function',
        }

    def _check_dead_class(
        self,
        node: ast.ClassDef,
        all_classes: Set[str],
        all_references: Set[str],
        content: str
    ) -> Optional[dict]:
        """Check if a class is dead code."""
        name = node.name

        # Check decorators - ANY decorator suggests the class is meant to be used
        if node.decorator_list:
            return None

        # Check if it's referenced anywhere (instantiated or as base class)
        if name in all_references:
            return None

        # Check if it's used as a base class
        for other in ast.walk(node):
            if isinstance(other, ast.ClassDef):
                for base in other.bases:
                    if isinstance(base, ast.Name) and base.id == name:
                        return None
                    elif isinstance(base, ast.Attribute):
                        base_name = self._get_name_from_node(base)
                        if base_name == name:
                            return None

        return {
            'name': name,
            'start': node.lineno,
            'end': node.end_lineno or node.lineno,
            'type': 'class',
        }

    def _is_in_main_block(self, node: ast.FunctionDef | ast.AsyncFunctionDef, content: str) -> bool:
        """Check if function is inside `if __name__ == "__main__":` block."""
        for parent in ast.walk(node):
            if isinstance(parent, ast.If):
                test = parent.test
                if isinstance(test, ast.Compare):
                    if isinstance(test.left, ast.Name) and test.left.id == '__name__':
                        for comp in test.comparators:
                            if isinstance(comp, ast.Constant):
                                if comp.value == '__main__':
                                    return True
        return False

    def _has_preserved_decorator(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> bool:
        """Check if node has a decorator that should prevent removal."""
        for decorator in node.decorator_list:
            name = self._get_decorator_name(decorator)
            if name:
                # Check for exact matches
                if name in self.PRESERVE_DECORATORS:
                    return True
                # Check for partial matches
                for preserve in self.PRESERVE_DECORATORS:
                    if preserve in name:
                        return True
        return False

    def _get_decorator_name(self, node: ast.AST) -> Optional[str]:
        """Extract decorator name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        elif isinstance(node, ast.Call):
            return self._get_decorator_name(node.func)
        return None

    def _has_side_effects(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if function has side effects (yield, raise, I/O).

        Only checks actual Call nodes — references to I/O names without calls
        (e.g. assigning the function to a variable) do not trigger side effects.
        """
        for child in ast.walk(node):
            if isinstance(child, (ast.Yield, ast.YieldFrom)):
                return True
            if isinstance(child, ast.Raise):
                return True
            if isinstance(child, ast.Call):
                func_name = self._get_call_name(child)
                if func_name:
                    io_funcs = {
                        'print', 'write', 'read', 'open', 'send', 'recv',
                        'sendto', 'recvfrom', 'sendfile',
                        'execute', 'fetch', 'query',
                        'insert', 'update', 'delete', 'commit', 'rollback',
                        'save', 'flush', 'log',
                        'append_file', 'write_text', 'read_text',
                    }
                    if func_name.lower() in io_funcs:
                        return True
        return False

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Get the name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return node.func.value.id
            return node.func.attr
        return None

    def _is_used_as_attribute(
        self,
        name: str,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        all_references: Set[str]
    ) -> bool:
        """Check if function name is used as an attribute somewhere."""
        for ref in all_references:
            if name in str(ref):
                return True
        return False

    def _get_name_from_node(self, node: ast.AST) -> Optional[str]:
        """Extract name from various AST nodes."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return node.attr
            return f"{self._get_name_from_node(node.value)}.{node.attr}"
        elif isinstance(node, ast.Constant):
            return str(node.value)
        return None

    def _remove_lines(self, lines: List[str], start: int, end: int) -> None:
        """Remove lines from the lines list (1-indexed)."""
        start_idx = max(0, start - 1)
        end_idx = min(len(lines), end)

        # Clear the lines (keep structure)
        for i in range(start_idx, end_idx):
            lines[i] = ''

    def _cleanup_blank_lines(self, content: str) -> str:
        """Remove consecutive blank lines."""
        lines = content.split('\n')
        result_lines = [line for line in lines if line != '']

        cleaned = []
        prev_blank = False
        for line in result_lines:
            is_blank = (line.strip() == '')
            if is_blank and prev_blank:
                continue
            cleaned.append(line)
            prev_blank = is_blank

        return '\n'.join(cleaned).strip('\n') + '\n'

    def _find_dead_branches(self, tree: ast.AST, content: str) -> List[str]:
        """Find dead branches from if/while/for with constant conditions.

        Detects (but does not auto-remove) patterns like:
        - if False: / while False: — entire block is dead
        - if True: ... else: ... — else branch is dead

        Auto-removal is disabled by default to avoid breaking code that relies
        on these patterns for scaffolding/placeholders.
        """
        removed: List[str] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.If, ast.While, ast.For)):
                continue

            if isinstance(node, ast.If):
                test = node.test
                if self._is_always_falsy(test):
                    reason = self._get_dead_branch_reason(node, content)
                    removed.append(reason)
            elif isinstance(node, (ast.While, ast.For)):
                if isinstance(node, ast.While):
                    test = node.test
                    if self._is_always_falsy(test):
                        reason = self._get_dead_branch_reason(node, content)
                        removed.append(reason)

        return removed

    def _get_dead_branch_reason(self, node: ast.AST, content: str) -> str:
        """Get a human-readable reason for a dead branch."""
        if isinstance(node, ast.While):
            return f"while True: loop with no break (dead)"
        return f"if False: — unreachable block"

    def _is_always_falsy(self, node: ast.AST) -> bool:
        """Check if a test is always falsy."""
        if isinstance(node, ast.Constant) and node.value in (False, 0, None, '', [], {}):
            return True
        return False

    def _is_always_truthy(self, node: ast.AST) -> bool:
        """Check if a test is always truthy."""
        if isinstance(node, ast.Constant) and node.value not in (False, 0, None, '', [], {}):
            return True
        return False
