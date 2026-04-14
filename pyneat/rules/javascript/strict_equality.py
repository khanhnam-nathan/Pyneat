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

"""Convert == to === and != to !== in JavaScript/TypeScript.

This rule detects loose equality operators and converts them to strict equality.
"""

import re
from typing import List, Dict

from pyneat.rules.base import Rule
from pyneat.core.types import CodeFile, TransformationResult


class StrictEqualityRule(Rule):
    """Convert loose equality to strict equality in JS/TS.

    Severity: MEDIUM
    """

    EQUALITY_PATTERN = re.compile(r'(?<![=!])={2,3}(?![=])')

    @property
    def supported_languages(self) -> List[str]:
        return ["javascript", "typescript"]

    @property
    def description(self) -> str:
        return "Convert == to === and != to !== in JavaScript/TypeScript"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        if code_file.ln_ast is None:
            return self._create_result(code_file, code_file.content, [])

        current = code_file.content
        changes = []

        for match in self.EQUALITY_PATTERN.finditer(current):
            op = match.group()
            start = match.start()
            end = match.end()

            if op == "==":
                replacement = "==="
            elif op == "!=":
                replacement = "!=="
            else:
                continue

            # Apply the fix
            current = current[:start] + replacement + current[end:]
            changes.append(f"Converted {op} to {replacement} on line {current[:start].count(chr(10)) + 1}")

        return self._create_result(code_file, current, changes)
