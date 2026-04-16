"""Detect deeply nested if/else chains (arrow anti-pattern) in any language.

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

This is a universal rule — works on all languages.
"""

from typing import List, Dict, Any

from pyneat.rules.universal.base import UniversalRule


NESTING_THRESHOLD = 4


class ArrowAntiPatternRule(UniversalRule):
    """Detect deeply nested control flow (arrow anti-pattern).

    Severity: MEDIUM
    """

    @property
    def rule_id(self) -> str:
        return "UNI-005"

    @property
    def description(self) -> str:
        return "Detect deeply nested if/else chains (arrow anti-pattern)"

    def analyze(self, code: str, ln_ast: dict) -> List[dict]:
        findings = []

        for nesting in ln_ast.get("deep_nesting", []):
            depth = nesting.get("depth", 0)
            if depth >= NESTING_THRESHOLD:
                line_num = nesting.get("line", 1)

                findings.append({
                    "rule_id": self.rule_id,
                    "start": 0,  # Not tracked
                    "end": 0,
                    "severity": "medium",
                    "problem": f"Nesting depth {depth} on line {line_num} (threshold: {NESTING_THRESHOLD})",
                    "fix_hint": "Extract inner logic into separate function or use early return",
                    "auto_fix_available": False,
                    "replacement": "",
                })

        return findings
