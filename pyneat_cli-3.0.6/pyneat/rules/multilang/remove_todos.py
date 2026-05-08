"""Remove TODO/FIXME/HACK comments in non-Python languages.

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

from typing import List, Tuple

from pyneat.rules.multilang.base import MultilangCleanRule
from pyneat.core.types import CodeFile, TransformationResult


class RemoveTodoRule(MultilangCleanRule):
    """Remove TODO/FIXME/HACK/XXX comments from code.

    Uses LN-AST's `todos` field which is populated by the Rust parser
    (tree-sitter based) for all supported languages.

    Supported languages: javascript, typescript, go, java, rust,
                         csharp, php, ruby.
    """

    @property
    def description(self) -> str:
        return "Removes TODO/FIXME/HACK comments"

    def apply(self, cf: CodeFile) -> TransformationResult:
        try:
            if cf.ln_ast is None:
                return self._create_result(cf, cf.content, [])

            todos = cf.ln_ast.get("todos", [])
            if not todos:
                return self._create_result(cf, cf.content, [])

            changes: List[str] = []
            removals: List[Tuple[int, int]] = []

            for todo in todos:
                marker = todo.get("marker", "TODO")
                description = todo.get("description", "")
                start = todo.get("start_line", 1)
                end = todo.get("end_line", start)

                removals.append((start, end))
                changes.append(
                    f"Removed {marker}: {description}" if description
                    else f"Removed {marker} comment"
                )

            # Apply in reverse order
            current = cf.content
            for start, end in sorted(removals, reverse=True):
                current = self._remove_lines(current, start, end)

            return self._create_result(cf, current, changes)

        except Exception as e:
            return self._create_error_result(cf, f"RemoveTodoRule failed: {e}")
