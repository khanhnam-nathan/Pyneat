"""Detect deeply nested if/else chains (arrow anti-pattern) in any language.

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
