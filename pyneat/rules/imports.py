"""Rule for cleaning and standardizing imports using LibCST.

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

import libcst as cst
from typing import List, Tuple, Union
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class ImportCollectorTransformer(cst.CSTTransformer):
    """
    LibCST transformer that collects all import statements,
    removes duplicates and original positions, and repositions
    them below the module docstring.
    """

    def __init__(self):
        super().__init__()
        self._imports: List[Tuple[cst.Import, cst.ImportFrom]] = []
        self._seen_imports: set[str] = set()

    def _normalize_import(self, node: Union[cst.Import, cst.ImportFrom]) -> str:
        """Return a normalized string key for duplicate detection."""
        if isinstance(node, cst.Import):
            parts = []
            for alias in node.names:
                name = self._get_import_name(alias.name)
                asname = alias.asname.name.value if alias.asname else ''
                parts.append((name, asname))
            return 'import ' + ','.join(f'{n} as {a}' if a else n for n, a in parts)
        else:  # ImportFrom
            module = ''
            if node.module:
                if isinstance(node.module, cst.Name):
                    module = node.module.value
                elif isinstance(node.module, cst.Attribute):
                    module = self._get_import_name(node.module)
            parts = []
            # Handle ImportStar (e.g., "from pygame import *")
            if isinstance(node.names, cst.ImportStar):
                parts.append(('*', ''))
            else:
                for alias in node.names:
                    name = self._get_import_name(alias.name)
                    asname = alias.asname.name.value if alias.asname else ''
                    parts.append((name, asname))
            relative_dots = ''.join('.' for _ in node.relative)
            return f'from {relative_dots}{module} import {",".join(f"{n} as {a}" if a else n for n, a in parts)}'

    def _get_import_name(self, name_node: Union[cst.Name, cst.Attribute]) -> str:
        """Extract dotted import name from a Name or Attribute node."""
        if isinstance(name_node, cst.Name):
            return name_node.value
        elif isinstance(name_node, cst.Attribute):
            base = self._get_import_name(name_node.value)
            attr = self._get_import_name(name_node.attr)
            return f'{base}.{attr}'
        return ''

    def visit_Import(self, node: cst.Import) -> None:
        return None  # don't recurse into children

    def visit_ImportFrom(self, node: cst.ImportFrom) -> None:
        return None  # don't recurse into children

    def leave_Import(
        self, original_node: cst.Import, updated_node: cst.Import
    ) -> Union[cst.Import, cst.RemovalSentinel]:
        key = self._normalize_import(updated_node)
        if key not in self._seen_imports:
            self._seen_imports.add(key)
            self._imports.append(updated_node)
        return cst.RemoveFromParent()  # remove from tree

    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> Union[cst.ImportFrom, cst.RemovalSentinel]:
        key = self._normalize_import(updated_node)
        if key not in self._seen_imports:
            self._seen_imports.add(key)
            self._imports.append(updated_node)
        return cst.RemoveFromParent()  # remove from tree

    def leave_Module(
        self, original_node: cst.Module, updated_node: cst.Module
    ) -> cst.Module:
        body = list(updated_node.body)

        # Track which body indices contained imports in the ORIGINAL tree
        # (so we know which blank lines are "import-adjacent" and worth keeping)
        import_indices: set[int] = set()
        for i, stmt in enumerate(original_node.body):
            if isinstance(stmt, (cst.Import, cst.ImportFrom)):
                import_indices.add(i)

        # Keep blank lines (EmptyLine) that are adjacent to an import in the original
        blank_indices_to_keep: set[int] = set()
        for i, stmt in enumerate(body):
            if isinstance(stmt, cst.EmptyLine):
                if i - 1 in import_indices or i + 1 in import_indices:
                    blank_indices_to_keep.add(i)

        # Remove only standalone blank lines (not adjacent to any import)
        clean_body: List[cst.BaseStatement] = []
        for i, stmt in enumerate(body):
            if isinstance(stmt, cst.EmptyLine) and i not in blank_indices_to_keep:
                continue
            clean_body.append(stmt)

        # Determine insertion index: if body[0] is a docstring, insert at body[1]
        insert_at = 0
        if clean_body and self._is_docstring(clean_body[0]):
            insert_at = 1

        # Convert collected import nodes to SimpleStatementLine wrappers
        import_statements: List[cst.BaseStatement] = [
            cst.SimpleStatementLine(body=[imp]) for imp in self._imports
        ]

        # Insert imports at the determined position
        for i, stmt in enumerate(import_statements):
            clean_body.insert(insert_at + i, stmt)

        return updated_node.with_changes(body=clean_body)

    def _is_docstring(self, stmt: cst.BaseStatement) -> bool:
        """Check if a module body statement is a module-level docstring."""
        if not isinstance(stmt, cst.SimpleStatementLine):
            return False
        if len(stmt.body) != 1:
            return False
        expr = stmt.body[0]
        if not isinstance(expr, cst.Expr):
            return False
        value = expr.value
        return isinstance(value, cst.SimpleString)


class ImportCleaningRule(Rule):
    """Cleans and standardizes Python imports using LibCST."""

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)

    @property
    def description(self) -> str:
        return "Standardizes import statements and removes duplicates (LibCST)"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            # Use cached CST tree if available (RuleEngine pre-parses)
            if hasattr(code_file, 'cst_tree') and code_file.cst_tree is not None:
                source_tree = code_file.cst_tree
            else:
                source_tree = cst.parse_module(code_file.content)

            transformer = ImportCollectorTransformer()
            modified_tree = source_tree.visit(transformer)

            changes: List[str] = []
            changes.append(f"Collected {len(transformer._imports)} import statement(s)")

            new_content = modified_tree.code
            return self._create_result(code_file, new_content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"Import cleaning failed: {str(e)}")
