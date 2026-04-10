"""Code duplication detection rule.

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

Detects identical or near-identical code blocks (functions, methods)
within the same file, which is a common AI code generator mistake.
"""

import ast
import hashlib
from typing import Dict, List, Tuple, Set

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


# --------------------------------------------------------------------------
# Duplication Detection
# --------------------------------------------------------------------------

class _DuplicateCodeVisitor(ast.NodeVisitor):
    """AST visitor to detect duplicate code blocks."""

    def __init__(self):
        self.changes: List[str] = []
        self.code_hashes: Dict[str, List[Tuple[str, int]]] = {}  # hash -> [(name, lineno)]
        self._function_bodies: List[Tuple[str, int, int, str]] = []  # (name, start, end, body)

    def visit_FunctionDef(self, node):
        self._analyze_function(node.name, node.lineno, node.end_lineno or node.lineno, node.body)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self._analyze_function(node.name, node.lineno, node.end_lineno or node.lineno, node.body)
        self.generic_visit(node)

    def _analyze_function(self, name: str, start: int, end: int, body: ast.AST) -> None:
        """Extract and hash function body to detect duplicates."""
        try:
            # Get the function body statements
            if isinstance(body, ast.FunctionDef) or isinstance(body, ast.AsyncFunctionDef):
                stmts = body.body
            elif isinstance(body, list):
                stmts = body
            else:
                stmts = [body]

            # Create a canonical string representation of the body
            parts = []
            for stmt in stmts:
                parts.append(ast.dump(stmt))
            body_str = ','.join(parts)

            # Normalize: remove whitespace
            import re
            normalized = re.sub(r'\s+', '', body_str)
            # Remove string literals
            normalized = re.sub(r"'[^']*'", "''", normalized)
            normalized = re.sub(r'"[^"]*"', '""', normalized)

            if len(normalized) < 50:  # Skip trivial functions
                return

            # Create a hash of the normalized body
            func_hash = hashlib.md5(normalized.encode()).hexdigest()[:12]

            if func_hash in self.code_hashes:
                self.code_hashes[func_hash].append((name, start))
                original = self.code_hashes[func_hash][0]
                self.changes.append(
                    f"DUPLICATION: Function '{name}' (line {start}) is identical to "
                    f"'{original[0]}' (line {original[1]})"
                )
            else:
                self.code_hashes[func_hash] = [(name, start)]
        except Exception:
            pass


# --------------------------------------------------------------------------
# Main Rule
# --------------------------------------------------------------------------

class CodeDuplicationRule(Rule):
    """Detect duplicate code blocks within the same file.

    Identifies identical or near-identical functions/methods that could
    be refactored into shared utilities. This is a common AI code
    generator mistake where the same logic is repeated.
    """

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)

    @property
    def description(self) -> str:
        return "Detect duplicate code blocks within a file"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        """Apply duplication detection."""
        try:
            tree = ast.parse(code_file.content)
        except SyntaxError:
            return self._create_error_result(code_file, f"Syntax error: {code_file.path}")

        visitor = _DuplicateCodeVisitor()
        visitor.visit(tree)

        return self._create_result(code_file, code_file.content, visitor.changes)


# --------------------------------------------------------------------------
# Module exports
# --------------------------------------------------------------------------

__all__ = ['CodeDuplicationRule']
