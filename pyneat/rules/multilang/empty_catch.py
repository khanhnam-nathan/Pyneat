"""Handle empty catch blocks in non-Python languages.

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

import re
from typing import List, Tuple

from pyneat.rules.multilang.base import MultilangCleanRule
from pyneat.core.types import CodeFile, TransformationResult


# Per-language catch block comment hints
CATCH_HINTS = {
    "javascript": "// PYNAGENT: handle exception",
    "typescript": "// PYNAGENT: handle exception",
    "go": "// PYNAGENT: handle error",
    "java": "// PYNAGENT: handle exception",
    "rust": "// PYNAGENT: handle error",
    "csharp": "// PYNAGENT: handle exception",
    "php": "// PYNAGENT: handle exception",
    "ruby": "# PYNAGENT: handle exception",
}


class EmptyCatchRule(MultilangCleanRule):
    """Handle empty catch blocks by adding a warning comment.

    Uses LN-AST's `catch_blocks` field from tree-sitter.
    Detects catch blocks with no body (is_empty=true) and replaces
    their content with a PYNAGENT marker comment.

    Supported languages: javascript, typescript, go, java, rust,
                         csharp, php, ruby.
    """

    @property
    def description(self) -> str:
        return "Handles empty catch blocks with warning comments"

    def apply(self, cf: CodeFile) -> TransformationResult:
        try:
            if cf.ln_ast is None:
                return self._create_result(cf, cf.content, [])

            catch_blocks = cf.ln_ast.get("catch_blocks", [])
            empty_blocks = [cb for cb in catch_blocks if cb.get("is_empty", False)]

            if not empty_blocks:
                return self._create_result(cf, cf.content, [])

            changes: List[str] = []
            hint = CATCH_HINTS.get(cf.language, "// PYNAGENT: handle exception")

            for cb in empty_blocks:
                start = cb.get("start_line", 1)
                end = cb.get("end_line", start)
                exc_type = cb.get("exception_type", "exception")

                # Replace empty catch with hint
                replacement = f"{hint} // {exc_type or 'exception'} not handled\n"
                current = cf.content
                lines = current.splitlines(keepends=True)
                if 0 <= start - 1 < len(lines) and 0 <= end - 1 < len(lines):
                    # Replace the range with the hint
                    lines[start - 1:end] = [replacement]
                    new_content = "".join(lines)
                    changes.append(f"Added hint to empty catch ({exc_type})")
                    cf = CodeFile(path=cf.path, content=new_content, language=cf.language)
                    object.__setattr__(cf, 'ln_ast', cf.ln_ast)

            return self._create_result(cf, cf.content, changes)

        except Exception as e:
            return self._create_error_result(cf, f"EmptyCatchRule failed: {e}")
