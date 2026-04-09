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

For commercial licensing, contact: n.khanhnam@gmail.com
"""

import ast
import re
from typing import List, Set, Optional
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult, AgentMarker
from pyneat.rules.base import Rule


class CodeQualityRule(Rule):
    """Improves code quality by detecting anti-patterns using AST analysis.

    Detects:
    - Magic numbers (multi-digit integers â‰¥ 100)
    - Empty except blocks
    - Potentially unused imports (heuristic: import name not seen elsewhere)
    """

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)

    @property
    def description(self) -> str:
        return "Detects and suggests fixes for code quality issues"

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

            # Detect magic numbers
            magic_numbers = self._find_magic_numbers(tree, content)
            if magic_numbers:
                suspicious = [n for n in magic_numbers if len(n) >= 3 and not n.startswith('0')]
                if suspicious:
                    changes.append(f"MAGIC NUMBERS DETECTED: {suspicious}")

            # Detect empty except blocks
            empty_excepts = self._find_empty_except_blocks(tree)
            if empty_excepts:
                changes.append("EMPTY EXCEPT BLOCKS: Add proper error handling")

            # Detect potentially unused imports (heuristic)
            unused = self._find_unused_imports_heuristic(tree)
            for imp in unused:
                changes.append(f"POTENTIALLY UNUSED IMPORT: {imp}")

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"Quality check failed: {str(e)}")

    def _find_magic_numbers(self, tree: ast.AST, content: str) -> Set[str]:
        """Find multi-digit numbers that are likely magic constants."""
        magic: Set[str] = set()
        # Only find numeric constants that are integers â‰¥ 100
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

    def mark_for_agent(self, code_file: CodeFile) -> Optional[List[AgentMarker]]:
        """Return AgentMarkers for code quality issues."""
        from typing import Optional

        markers: List[AgentMarker] = []

        try:
            tree = getattr(code_file, 'ast_tree', None) or ast.parse(code_file.content)
        except SyntaxError:
            return None

        lines = code_file.content.splitlines()

        magic_numbers = self._find_magic_numbers(tree, code_file.content)
        for num in magic_numbers:
            for i, line in enumerate(lines):
                if num in line:
                    markers.append(AgentMarker(
                        marker_id=f"PYN-Q{len(markers) + 1:03d}",
                        issue_type="magic_number",
                        rule_id="CodeQualityRule",
                        severity="info",
                        line=i + 1,
                        param=num,
                        hint=f"Magic number {num} — extract to a named constant",
                        why="Magic numbers reduce code readability and maintainability",
                        confidence=0.8,
                        can_auto_fix=False,
                        snippet=line.strip()[:80],
                    ))
                    break

        empty_excepts = self._find_empty_except_blocks(tree)
        for line_no in empty_excepts:
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            markers.append(AgentMarker(
                marker_id=f"PYN-Q{len(markers) + 1:03d}",
                issue_type="empty_except",
                rule_id="CodeQualityRule",
                severity="medium",
                line=line_no,
                hint="Empty except block — add error handling or logging",
                why="Empty except blocks silently swallow errors and make debugging harder",
                confidence=0.95,
                can_auto_fix=False,
                snippet=snippet[:80],
            ))

        return markers if markers else None
