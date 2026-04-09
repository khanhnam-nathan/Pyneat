"""Rule for fixing 'x != None' -> 'x is not None' comparisons.

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

from typing import List

import libcst as cst

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class IsNotNoneRule(Rule):
    """Fixes != None to is not None for PEP8 compliance.

    Converts:
      - x != None -> x is not None
      - x is not None is kept as-is (no change)
      - None != x -> x is not None
    """

    @property
    def description(self) -> str:
        return "Fixes != None to is not None for PEP8 compliance"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            content = code_file.content

            # Use cached CST tree if available (RuleEngine pre-parses)
            if hasattr(code_file, 'cst_tree') and code_file.cst_tree is not None:
                tree = code_file.cst_tree
            else:
                try:
                    tree = cst.parse_module(content)
                except Exception:
                    return self._create_result(code_file, content, [])

            transformer = _IsNotNoneTransformer()
            new_tree = tree.visit(transformer)
            new_content = new_tree.code

            return self._create_result(code_file, new_content, transformer.changes)

        except Exception as e:
            return self._create_error_result(
                code_file, f"IsNotNoneRule failed: {str(e)}"
            )


# ----------------------------------------------------------------------
# LibCST Transformer
# ----------------------------------------------------------------------


class _IsNotNoneTransformer(cst.CSTTransformer):
    """Transformer that fixes != None comparisons."""

    def __init__(self):
        super().__init__()
        self.changes: List[str] = []

    def leave_Comparison(self, original: cst.Comparison,
                          updated: cst.Comparison) -> cst.BaseExpression:
        """Convert 'x != None' -> 'x is not None'."""
        # Check if this comparison is x != None
        result = self._fix_not_eq_none(updated)
        if result is not None:
            self.changes.append(f"Fixed != None to is not None")
            return result
        return updated

    def _fix_not_eq_none(self, comp: cst.Comparison) -> cst.BaseExpression | None:
        """Convert 'x != None' to 'x is not None'."""
        if len(comp.comparisons) != 1:
            return None

        target = comp.comparisons[0]
        op = target.operator
        left = comp.left
        right = target.comparator

        # Case 1: x != None
        if isinstance(op, cst.NotEqual) and self._is_none_literal(right):
            return cst.Comparison(
                left=left,
                comparisons=[
                    cst.ComparisonTarget(
                        operator=cst.IsNot(),
                        comparator=cst.Name('None'),
                    )
                ],
            )

        # Case 2: None != x (rare but possible)
        if isinstance(op, cst.NotEqual) and self._is_none_literal(left):
            return cst.Comparison(
                left=right,
                comparisons=[
                    cst.ComparisonTarget(
                        operator=cst.IsNot(),
                        comparator=cst.Name('None'),
                    )
                ],
            )

        return None

    def _is_none_literal(self, node: cst.BaseExpression) -> bool:
        """Check if node is the literal None (represented as Name('None') in libcst)."""
        if isinstance(node, cst.Name):
            return node.value == 'None'
        return False
