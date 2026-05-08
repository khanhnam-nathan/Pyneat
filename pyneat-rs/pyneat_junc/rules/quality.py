"""Rule for improving code quality using AST analysis.

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
import re
from typing import List, Set
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult, AgentMarker
from pyneat.rules.base import Rule


class CodeQualityRule(Rule):
    """Improves code quality by detecting anti-patterns using AST analysis.

    Detects:
    - Magic numbers (multi-digit integers ≥ 100)
    - Empty except blocks
    - Potentially unused imports (heuristic: import name not seen elsewhere)
    """

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)

    @property
    def description(self) -> str:
        return "Detects and suggests fixes for code quality issues"

    DEFAULT_SEVERITY = "medium"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            markers: List[AgentMarker] = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes, markers)

            try:
                # Use cached AST if available (RuleEngine pre-parses)
                if hasattr(code_file, 'ast_tree') and code_file.ast_tree is not None:
                    tree = code_file.ast_tree
                else:
                    tree = ast.parse(content)
            except SyntaxError:
                return self._create_result(code_file, content, changes, markers)

            # Detect magic numbers
            magic_numbers = self._find_magic_numbers(tree, content)
            if magic_numbers:
                suspicious = [n for n in magic_numbers if len(n) >= 3 and not n.startswith('0')]
                if suspicious:
                    for num in suspicious:
                        change = f"Magic number {num} detected"
                        changes.append(change)
                        markers.append(self.build_agent_marker(
                            change=change,
                            code_file=code_file,
                            issue_type="magic-number",
                            severity="low",
                            hint=f"Replace magic number {num} with a named constant",
                            why=f"Magic number {num} makes code harder to understand and maintain",
                            confidence=0.9,
                            category="quality",
                        ))

            # Detect empty except blocks
            empty_excepts = self._find_empty_except_blocks(tree)
            if empty_excepts:
                changes.append("EMPTY EXCEPT BLOCKS: Add proper error handling")
                for line in empty_excepts:
                    change = f"Empty except block at line {line}"
                    markers.append(self.build_agent_marker(
                        change=change,
                        code_file=code_file,
                        issue_type="empty-except",
                        severity="medium",
                        hint="Add specific exception handling or re-raise",
                        why="Empty except blocks silently swallow errors, making debugging difficult",
                        confidence=0.95,
                        category="quality",
                    ))

            # Detect potentially unused imports (heuristic)
            unused = self._find_unused_imports_heuristic(tree)
            for imp in unused:
                change = f"Potentially unused import: {imp}"
                changes.append(change)
                markers.append(self.build_agent_marker(
                    change=change,
                    code_file=code_file,
                    issue_type="unused-import",
                    severity="low",
                    hint=f"Remove unused import '{imp}' or verify it is called dynamically",
                    why=f"Import '{imp}' appears to be unused, adding to cognitive load",
                    confidence=0.7,
                    confidence_note="heuristic — may not detect dynamic usage",
                    category="import",
                ))

            return self._create_result(code_file, content, changes, markers)

        except Exception as e:
            return self._create_error_result(code_file, f"Quality check failed: {str(e)}")

    def _find_magic_numbers(self, tree: ast.AST, content: str) -> Set[str]:
        """Find multi-digit numbers that are likely magic constants."""
        magic: Set[str] = set()
        # Only find numeric constants that are integers ≥ 100
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, int):
                if node.value >= 100:
                    magic.add(str(node.value))
        return magic

    def _find_empty_except_blocks(self, tree: ast.AST) -> List[int]:
        """Find except blocks that only contain pass."""
        empty: List[int] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                    empty.append(node.lineno)
        return empty

    def _find_unused_imports_heuristic(self, tree: ast.AST) -> List[str]:
        """Find import names that may not be used (basic heuristic)."""
        imported: Set[str] = set()
        referenced: Set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    imported.add(alias.asname or alias.name)
            elif isinstance(node, ast.Name):
                referenced.add(node.id)
            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name):
                    referenced.add(node.value.id)
            elif isinstance(node, ast.arg):
                referenced.add(node.arg)

        unused = []
        for name in imported:
            if name not in referenced and not name.startswith('_'):
                unused.append(name)

        return unused
