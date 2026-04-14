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

"""Detect unchecked error returns in Go.

Go functions that return (value, error) should always check the error.
This rule detects cases where error is ignored using _.
"""

import re
from typing import List

from pyneat.rules.base import Rule
from pyneat.core.types import CodeFile, TransformationResult


class UncheckedErrorRule(Rule):
    """Detect Go functions that return (value, error) where error is unchecked.

    Severity: MEDIUM
    """

    # Pattern: _, err := function() or _, _ = function()
    ERROR_IGNORE_PATTERN = re.compile(
        r',\s*_\s*:=\s*.*',  # x, _ := foo() - ignores error
        re.MULTILINE
    )

    @property
    def supported_languages(self) -> List[str]:
        return ["go"]

    @property
    def description(self) -> str:
        return "Detect unchecked error returns in Go"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        if code_file.ln_ast is None:
            return self._create_result(code_file, code_file.content, [])

        findings = []
        code = code_file.content

        for match in self.ERROR_IGNORE_PATTERN.finditer(code):
            line_num = code[:match.start()].count('\n') + 1

            # Get the full line
            line_start = code.rfind('\n', 0, match.start()) + 1
            line_end = code.find('\n', match.start())
            if line_end == -1:
                line_end = len(code)
            full_line = code[line_start:line_end].strip()

            findings.append({
                "rule_id": "GO-001",
                "start": match.start(),
                "end": match.end(),
                "severity": "medium",
                "problem": f"Unchecked error on line {line_num}: {full_line[:50]}",
                "fix_hint": "Handle the error: if err != nil { return err }",
                "auto_fix_available": False,
            })

        changes = [f"[GO-001] {f['problem']}" for f in findings]
        return self._create_result(code_file, code, changes)
