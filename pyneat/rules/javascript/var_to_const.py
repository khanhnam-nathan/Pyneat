"""PyNeat - AI Code Cleaner.

Copyright (C) 2026 PyNEAT Authors

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

"""Convert var to let/const in JavaScript/TypeScript.

This rule detects var declarations and converts them to const (preferred) or let.
"""

import re
from typing import List

from pyneat.rules.base import Rule
from pyneat.core.types import CodeFile, TransformationResult


class VarToConstRule(Rule):
    """Convert var declarations to let/const.

    Severity: LOW
    """

    VAR_PATTERN = re.compile(r'\bvar\s+(\w+)', re.MULTILINE)

    @property
    def supported_languages(self) -> List[str]:
        return ["javascript", "typescript"]

    @property
    def description(self) -> str:
        return "Convert var to let/const in JavaScript"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        if code_file.ln_ast is None:
            return self._create_result(code_file, code_file.content, [])

        current = code_file.content
        changes = []

        for match in self.VAR_PATTERN.finditer(current):
            var_name = match.group(1)
            start = match.start()
            end = match.end()

            # Default to const (safer)
            replacement = f"const {var_name}"

            current = current[:start] + replacement + current[end:]
            changes.append(f"Converted var {var_name} to const on line {current[:start].count(chr(10)) + 1}")

        return self._create_result(code_file, current, changes)
