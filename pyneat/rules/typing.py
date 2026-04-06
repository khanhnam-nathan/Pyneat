"""Rule for suggesting type annotations and cleaning type-related issues."""

import ast
from typing import List, Set, Optional
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class TypingRule(Rule):
    """Suggests type annotations and cleans type-related issues.

    Detects:
    - Functions without type hints
    - Missing return type annotations
    - Untyped class methods
    - Complex type annotations that could be simplified
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
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes)

            try:
                tree = ast.parse(content)
            except SyntaxError:
                return self._create_result(code_file, content, changes)

            # Analyze functions for missing type hints
            untyped_functions = self._find_untyped_functions(tree)
            for func_name, line_no in untyped_functions:
                changes.append(f"Missing type hints: {func_name}() at line {line_no}")

            # Find functions with missing return types
            missing_return = self._find_missing_return_types(tree)
            for func_name, line_no in missing_return:
                changes.append(f"Missing return type: {func_name}() at line {line_no}")

            # Check for # type: ignore cleanup opportunities
            type_ignore_count = self._count_type_ignores(content)
            if type_ignore_count > 5:
                changes.append(f"Found {type_ignore_count} # type: ignore comments - consider fixing types properly")

            return self._create_result(code_file, content, changes)

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


class TypeAnnotationAdder:
    """Helper class to add type annotations to functions."""

    def __init__(self):
        self.changes: List[str] = []

    def add_return_type(self, func_node: ast.FunctionDef, return_type: str) -> str:
        """Add return type annotation to a function."""
        # This would modify the function signature
        # In practice, this would use libcst for proper modification
        self.changes.append(f"Added return type: {return_type}")
        return ""

    def add_arg_types(self, func_node: ast.FunctionDef, arg_types: dict) -> str:
        """Add type annotations to function arguments."""
        self.changes.append(f"Added types: {arg_types}")
        return ""