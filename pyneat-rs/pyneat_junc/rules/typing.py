"""Rule for suggesting type annotations and cleaning type-related issues.

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
"""

import ast
import libcst as cst
from typing import List, Set, Optional
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult, AgentMarker
from pyneat.rules.base import Rule


class TypingRule(Rule):
    """Suggests type annotations and cleans type-related issues.

    Detects and (where safe) auto-fixes:
    - Functions without type hints
    - Missing return type annotations
    - Untyped class methods
    - Complex type annotations that could be simplified

    Auto-fix strategy: Only adds `-> None` return types where analysis
    confirms the function doesn't return a meaningful value. More complex
    type inference is left as a suggestion (detection only).
    """

    BUILTIN_TYPES = {
        'int', 'float', 'str', 'bool', 'list', 'dict', 'set', 'tuple',
        'None', 'type', 'object', 'bytes', 'bytearray', 'range',
        'frozenset', 'complex', 'memoryview',
    }

    COMMON_TYPES = {
        'Optional', 'List', 'Dict', 'Set', 'Tuple', 'Any',
        'Union', 'Callable', 'Type', 'Iterable', 'Generator',
        'Sequence', 'Mapping', 'AnyStr', 'Literal',
    }

    @property
    def description(self) -> str:
        return "Suggests type annotations and cleans type-related issues"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            markers: List = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes, markers)

            has_cached_ast = hasattr(code_file, 'ast_tree') and code_file.ast_tree is not None
            has_cached_cst = hasattr(code_file, 'cst_tree') and code_file.cst_tree is not None

            try:
                tree = ast.parse(content) if not has_cached_ast else code_file.ast_tree
            except SyntaxError:
                return self._create_result(code_file, content, changes, markers)

            untyped_functions = self._find_untyped_functions(tree)
            for func_name, line_no in untyped_functions:
                change = f"Missing type hints: {func_name}() at line {line_no}"
                changes.append(change)
                markers.append(self.build_agent_marker(
                    change=change, code_file=code_file,
                    issue_type="missing-type-hints",
                    severity="low",
                    hint=f"Add type annotations to {func_name}() parameters and return type",
                    why="Missing type hints reduce code clarity and prevent static type checkers from catching bugs",
                    confidence=0.85, category="typing",
                ))

            missing_return = self._find_missing_return_types(tree)
            for func_name, line_no in missing_return:
                change = f"Missing return type: {func_name}() at line {line_no}"
                changes.append(change)
                markers.append(self.build_agent_marker(
                    change=change, code_file=code_file,
                    issue_type="missing-return-type",
                    severity="low",
                    hint=f"Add -> <ReturnType> annotation to {func_name}()",
                    why="Missing return type annotation makes it unclear what the function returns",
                    confidence=0.85, category="typing",
                ))

            type_ignore_count = self._count_type_ignores(content)
            if type_ignore_count > 5:
                change = f"Found {type_ignore_count} # type: ignore comments — consider fixing types properly"
                changes.append(change)
                markers.append(self.build_agent_marker(
                    change=change, code_file=code_file,
                    issue_type="excessive-type-ignores",
                    severity="info",
                    hint="Address the underlying type errors instead of suppressing them with # type: ignore",
                    why=f"Found {type_ignore_count} # type: ignore comments — this suggests type issues are being suppressed rather than fixed",
                    confidence=0.9, category="typing",
                ))

            fixable_functions = self._find_fixable_functions(tree)

            if fixable_functions:
                try:
                    cst_tree = code_file.cst_tree if has_cached_cst else None
                    new_content = self._add_return_type_annotations(content, fixable_functions, cst_tree)
                    if new_content != content:
                        changes.append(f"Added -> None return type to {len(fixable_functions)} function(s)")
                        content = new_content
                except Exception:
                    pass

            return self._create_result(code_file, content, changes, markers)

        except Exception as e:
            return self._create_error_result(code_file, f"TypingRule failed: {str(e)}")

    def _find_untyped_functions(self, tree: ast.AST) -> List[tuple]:
        """Find top-level functions without type hints."""
        untyped = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Only check module-level functions
                if not any(isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                          for parent in ast.walk(tree) if parent is not node):
                    if self._is_untyped_function(node):
                        untyped.append((node.name, node.lineno))

        return untyped

    def _is_untyped_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if a function is missing type hints."""
        # Check if it has any annotations
        has_args = any(arg.annotation is not None for arg in node.args.args)
        has_return = node.returns is not None

        # It's untyped if it has no argument annotations AND no return annotation
        # But only suggest for non-trivial functions (have parameters)
        if not has_args and not has_return and len(node.args.args) > 0:
            return True

        # Check for partial typing (some args but not all)
        if has_args and not has_return:
            return True

        return False

    def _find_missing_return_types(self, tree: ast.AST) -> List[tuple]:
        """Find functions with no return type but likely should have one."""
        missing = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Skip private functions and methods
                if node.name.startswith('_') and node.name != '__init__':
                    continue

                # Skip if already has return type
                if node.returns is not None:
                    continue

                # Check if function body has return statements (nontrivial)
                has_return = self._function_has_returns(node)
                if has_return:
                    missing.append((node.name, node.lineno))

        return missing

    def _function_has_returns(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if function has return statements."""
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value is not None:
                return True
        return False

    def _count_type_ignores(self, content: str) -> int:
        """Count # type: ignore comments."""
        count = 0
        for line in content.split('\n'):
            if '# type: ignore' in line:
                count += 1
        return count

    def _find_fixable_functions(self, tree: ast.AST) -> List[tuple]:
        """Find functions that can be safely auto-fixed with -> None.

        Returns list of (name, has_explicit_return) tuples.
        Functions with explicit non-None returns are NOT fixable.
        """
        fixable = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Skip if already has return annotation
                if node.returns is not None:
                    continue

                # Check if function has any non-None return values
                has_non_none_return = False
                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and child.value is not None:
                        if not self._is_none_literal(child.value):
                            has_non_none_return = True
                            break

                # Only auto-fix if no non-None returns found
                if not has_non_none_return:
                    fixable.append((node.name, node.lineno, node.col_offset))

        return fixable

    def _is_none_literal(self, node: ast.AST) -> bool:
        """Check if an AST node is a None literal."""
        if isinstance(node, ast.Constant) and node.value is None:
            return True
        return False

    def _add_return_type_annotations(self, content: str, fixable: List[tuple], cst_tree=None) -> str:
        """Add -> None to functions that can be safely annotated."""
        try:
            module = cst.parse_module(content) if cst_tree is None else cst_tree
        except Exception:
            return content

        transformer = _ReturnTypeAdder(fixable)
        new_module = module.visit(transformer)

        if transformer.added_count > 0:
            return new_module.code
        return content


class _ReturnTypeAdder(cst.CSTTransformer):
    """Adds -> None return type to functions that have no non-None return values."""

    def __init__(self, fixable: List[tuple]):
        super().__init__()
        self.fixable = fixable
        self.added_count = 0

    def leave_FunctionDef(
        self, original: cst.FunctionDef, updated: cst.FunctionDef
    ) -> cst.FunctionDef:
        # Check if this function is in our fixable list
        lineno = original.definition.location.line if original.definition.location else None

        is_fixable = any(
            name == original.name.value
            for name, line, _ in self.fixable
        )

        if is_fixable and updated.returns is None:
            new_returns = cst.Annotation(annotation=cst.Name(value='None'))
            updated = updated.with_changes(returns=new_returns)
            self.added_count += 1

        return updated

    def leave_AsyncFunctionDef(
        self, original: cst.FunctionDef, updated: cst.FunctionDef
    ) -> cst.FunctionDef:
        is_fixable = any(
            name == original.name.value
            for name, line, _ in self.fixable
        )

        if is_fixable and updated.returns is None:
            new_returns = cst.Annotation(annotation=cst.Name(value='None'))
            updated = updated.with_changes(returns=new_returns)
            self.added_count += 1

        return updated


class TypeAnnotationAdder:
    """DEPRECATED: Type annotation logic moved to TypingRule._add_return_type_annotations.

    Kept for backward compatibility with external code that imports this class.
    """

    def __init__(self):
        self.changes: List[str] = []

    def add_return_type(self, func_node: ast.FunctionDef, return_type: str) -> str:
        """Add return type annotation to a function."""
        self.changes.append(f"Added return type: {return_type}")
        return ""

    def add_arg_types(self, func_node: ast.FunctionDef, arg_types: dict) -> str:
        """Add type annotations to function arguments."""
        self.changes.append(f"Added types: {arg_types}")
        return ""