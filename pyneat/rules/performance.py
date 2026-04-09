"""Rule for detecting performance issues using AST analysis.

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
"""

import ast
from typing import List
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class PerformanceRule(Rule):
    """Detects performance anti-patterns using AST analysis.

    Detects:
    - List concatenation in loops -> use list comprehension
    - Nested loops iterating over the same collection
    - Repeated computation of expensive expressions in loops
    - while True without break
    """

    KNOWN_SAFE_METHODS: frozenset = frozenset({
        # Collection mutating methods
        'append', 'extend', 'add', 'update', 'pop', 'popitem',
        'clear', 'remove', 'discard', 'insert', 'reverse', 'sort',
        # Dict/view methods
        'get', 'setdefault', 'copy', 'keys', 'values', 'items',
        # String methods
        'lower', 'upper', 'strip', 'lstrip', 'rstrip', 'split',
        'rsplit', 'splitlines', 'join', 'replace', 'find', 'rfind',
        'startswith', 'endswith', 'encode', 'decode', 'format',
        'zfill', 'center', 'ljust', 'rjust', 'capitalize', 'swapcase',
        'title', 'casefold', 'expandtabs', 'partition', 'rpartition',
        # File/IO methods
        'read', 'readline', 'readlines', 'write', 'flush', 'seek',
        'tell', 'truncate', 'fileno', 'isatty',
        # Collection methods
        'copy', 'deepcopy', 'count', 'index', 'append', 'extend',
        'difference', 'intersection', 'union', 'issubset', 'issuperset',
        'symmetric_difference',
        # Safe type conversion
        'str', 'int', 'float', 'bool', 'list', 'dict', 'set', 'tuple',
        'bytes', 'ascii', 'repr', 'hash', 'abs', 'round', 'min', 'max',
        'sum', 'all', 'any', 'sorted', 'reversed', 'enumerate', 'filter', 'map',
        # Other safe
        'isalpha', 'isdigit', 'isalnum', 'isspace', 'isupper', 'islower',
        'lstrip', 'rstrip', 'encode', 'decode',
    })

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)

    @property
    def description(self) -> str:
        return "Detects performance issues and inefficient code"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes)

            try:
                # Use cached AST if available (RuleEngine pre-parses)
                if hasattr(code_file, 'ast_tree') and code_file.ast_tree is not None:
                    tree = code_file.ast_tree
                else:
                    tree = ast.parse(content)
            except SyntaxError:
                return self._create_result(code_file, content, changes)

            if self._has_list_concat_in_loop(tree):
                changes.append("INEFFICIENT LOOP: Use list comprehension or extend()")

            nested = self._find_nested_same_iterable(tree)
            for item in nested:
                changes.append(f"INEFFICIENT: Nested loops over same iterable in {item}")

            if self._has_while_true_without_break(tree):
                changes.append("POTENTIAL INFINITE LOOP: Missing break condition")

            repeated = self._find_repeated_method_calls(tree)
            for item in repeated:
                changes.append(
                    f"PERFORMANCE: Repeated {item}() call in loop — call once and reuse"
                )

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"Performance check failed: {str(e)}")

    def _has_list_concat_in_loop(self, tree: ast.AST) -> bool:
        """Detect patterns like `mylist = mylist + [x]` or `mylist += [x]` inside loops."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                for child in ast.walk(node):
                    if isinstance(child, ast.AugAssign):
                        if isinstance(child.op, ast.Add):
                            return True
                    if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Add):
                        if isinstance(child.left, ast.Name):
                            return True
        return False

    def _find_nested_same_iterable(self, tree: ast.AST) -> List[str]:
        """Find nested for loops that iterate over the same collection."""
        results: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.AsyncFor)):
                self._check_nested_same(node, results)
        return results

    def _check_nested_same(self, outer_node: ast.For, results: List[str], depth: int = 0) -> None:
        """Recursively check for nested loops over the same iterable."""
        outer_source = self._get_iter_source(outer_node.iter)
        if outer_source is None:
            return

        for child in ast.walk(outer_node):
            if child is outer_node:
                continue
            if isinstance(child, (ast.For, ast.AsyncFor)):
                inner_source = self._get_iter_source(child.iter)
                if inner_source == outer_source and isinstance(inner_source, ast.Name):
                    results.append(f"{inner_source.id}")

    def _get_iter_source(self, node: ast.AST) -> ast.AST | None:
        """Get the source of a for loop iterator."""
        if isinstance(node, ast.Name):
            return node
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ('range', 'enumerate', 'zip'):
                return node
        return None

    def _has_while_true_without_break(self, tree: ast.AST) -> bool:
        """Check for `while True:` or `while 1:` without any break statement."""
        for node in ast.walk(tree):
            if isinstance(node, ast.While):
                test = node.test
                is_forever = (
                    isinstance(test, ast.Constant) and test.value in (True, 1)
                )
                if is_forever:
                    has_break = any(
                        isinstance(n, ast.Break)
                        for n in ast.walk(node)
                    )
                    if not has_break:
                        return True
        return False

    def _find_repeated_method_calls(self, tree: ast.AST) -> List[str]:
        """Find methods called repeatedly inside loops that are NOT in safe list."""
        results: List[str] = []
        seen_in_loop: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                loop_methods: set[str] = set()
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                        name = child.func.attr
                        if name not in self.KNOWN_SAFE_METHODS:
                            loop_methods.add(name)

                if len(loop_methods) > 0:
                    for name in loop_methods:
                        if name not in seen_in_loop:
                            seen_in_loop.add(name)

        if len(seen_in_loop) <= 5:
            results.extend(sorted(seen_in_loop))
        return results