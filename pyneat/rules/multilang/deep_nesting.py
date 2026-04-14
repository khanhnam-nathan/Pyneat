"""Detect deeply nested control flow (arrow anti-pattern) in non-Python languages.

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

from typing import List, Tuple

from pyneat.rules.multilang.base import MultilangCleanRule
from pyneat.core.types import CodeFile, TransformationResult


# Comment marker for refactoring hints
REFACTOR_HINT = "// PYNAGENT: deep nesting refactor needed"


class DeepNestingRule(MultilangCleanRule):
    """Detect and warn about deeply nested control flow (arrow anti-pattern).

    Uses LN-AST's `deep_nesting` field (depth >= 4) from tree-sitter.
    Adds a refactoring hint comment instead of auto-refactoring,
    since cross-language refactoring is complex.

    Supported languages: javascript, typescript, go, java, rust,
                         csharp, php, ruby.
    """

    @property
    def description(self) -> str:
        return "Detects deeply nested control flow (>= 4 levels)"

    def apply(self, cf: CodeFile) -> TransformationResult:
        try:
            if cf.ln_ast is None:
                return self._create_result(cf, cf.content, [])

            deep_nests = cf.ln_ast.get("deep_nesting", [])
            if not deep_nests:
                return self._create_result(cf, cf.content, [])

            changes: List[str] = []

            # Add refactoring hint at each deep nesting location
            for nesting in deep_nests:
                depth = nesting.get("depth", 0)
                line = nesting.get("line", 1)

                # Insert a hint comment before this line
                lines = cf.content.splitlines(keepends=True)
                if 0 <= line - 1 < len(lines):
                    hint_line = REFACTOR_HINT + f" (depth={depth})\n"
                    lines.insert(line - 1, hint_line)
                    changes.append(f"Deep nesting (depth={depth}) at line {line}")
                    cf_content_edited = "".join(lines)
                    # Update content for next iteration
                    cf = CodeFile(
                        path=cf.path,
                        content=cf_content_edited,
                        language=cf.language,
                    )
                    object.__setattr__(cf, 'ln_ast', cf.ln_ast)

            return self._create_result(cf, cf.content, changes)

        except Exception as e:
            return self._create_error_result(cf, f"DeepNestingRule failed: {e}")
