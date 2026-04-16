"""Rule for cleaning code blocks in isolation using LibCST.

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
from typing import List
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule
from pyneat.rules.imports import ImportCleaningRule


class IsolatedBlockCleaner(Rule):
    """Cleans code blocks (If, Try, For, FunctionDef, ClassDef) in isolation.

    Extracts each block body, applies import cleaning + unused import removal
    to it, and reconstructs the block. This helps clean imports even within
    function bodies, class methods, and other blocks.
    """

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self.import_cleaner = ImportCleaningRule(config)

    @property
    def description(self) -> str:
        return "Cleans code blocks (If, Try, For, FunctionDef, ClassDef) in isolation"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []

            # Use cached CST tree if available (RuleEngine pre-parses)
            if hasattr(code_file, 'cst_tree') and code_file.cst_tree is not None:
                module = code_file.cst_tree
            else:
                module = cst.parse_module(code_file.content)

            transformer = _IsolatedBlockTransformer(self.import_cleaner, changes)
            transformed_module = module.visit(transformer)
            transformed_content = transformed_module.code

            return self._create_result(code_file, transformed_content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"Isolated block cleaning failed: {str(e)}")


class _IsolatedBlockTransformer(cst.CSTTransformer):
    """LibCST transformer for processing isolated code blocks."""

    IGNORE_TAGS = ("# pyneat: ignore", "# pyneat: off")

    def __init__(self, import_cleaner: ImportCleaningRule, changes: List[str]):
        super().__init__()
        self.import_cleaner = import_cleaner
        self.changes = changes

    def _check_ignore(self, node: cst.CSTNode) -> bool:
        """Return True if the node has a leading comment tagged with ignore."""
        if not hasattr(node, "leading_lines"):
            return False
        for line in node.leading_lines:
            if line.comment and any(tag in line.comment.value for tag in self.IGNORE_TAGS):
                return True
        return False

    def leave_Try(self, original_node: cst.Try, updated_node: cst.Try) -> cst.Try:
        """Clean Try blocks in isolation."""
        return self._clean_isolated_block(original_node, updated_node, "Try")

    def leave_If(self, original_node: cst.If, updated_node: cst.If) -> cst.If:
        """Clean If blocks in isolation."""
        return self._clean_isolated_block(original_node, updated_node, "If")

    def leave_For(self, original_node: cst.For, updated_node: cst.For) -> cst.For:
        """Clean For blocks in isolation."""
        return self._clean_isolated_block(original_node, updated_node, "For")

    def leave_ClassDef(self, original_node: cst.ClassDef, updated_node: cst.ClassDef) -> cst.ClassDef:
        """Clean ClassDef blocks in isolation (skip if decorated)."""
        if original_node.decorators:
            return updated_node
        return self._clean_isolated_block(original_node, updated_node, "ClassDef")

    def leave_FunctionDef(
        self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef
    ) -> cst.FunctionDef:
        """Clean FunctionDef blocks in isolation (skip if decorated)."""
        if original_node.decorators:
            return updated_node
        return self._clean_isolated_block(original_node, updated_node, "FunctionDef")

    def leave_AsyncFunctionDef(
        self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef
    ) -> cst.FunctionDef:
        """Clean async FunctionDef blocks in isolation (skip if decorated)."""
        if original_node.decorators:
            return updated_node
        return self._clean_isolated_block(original_node, updated_node, "FunctionDef")

    def _clean_isolated_block(
        self, original_node: cst.CSTNode, updated_node: cst.CSTNode, block_type: str
    ) -> cst.CSTNode:
        """Clean an isolated code block while preserving indentation."""
        if self._check_ignore(original_node):
            return updated_node

        if hasattr(original_node, "decorators") and original_node.decorators:
            return updated_node

        try:
            block_code = cst.Module([]).code_for_node(original_node)

            if not block_code.strip():
                return updated_node

            block_file = CodeFile(path=None, content=block_code)
            result = self.import_cleaner.apply(block_file)

            if result.success and result.has_changes:
                cleaned_module = cst.parse_module(result.transformed_content)

                if not cleaned_module.body:
                    return updated_node

                if hasattr(original_node, "body"):
                    current_body = updated_node.body
                elif hasattr(original_node, "orelse"):
                    current_body = updated_node.orelse
                else:
                    return updated_node

                if isinstance(current_body, cst.IndentedBlock) and current_body.body:
                    first_stmt = cleaned_module.body[0]
                    if isinstance(first_stmt, cst.SimpleStatementLine):
                        return updated_node.with_changes(body=cst.IndentedBlock(
                            body=[first_stmt] + list(current_body.body[1:])
                        ))

                for change in result.changes_made:
                    self.changes.append(f"{block_type} block: {change}")

                return updated_node

        except Exception as e:
            self.changes.append(f"{block_type} block cleaning failed: {str(e)}")

        return updated_node