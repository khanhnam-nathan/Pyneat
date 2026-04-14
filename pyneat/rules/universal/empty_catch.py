"""Detect empty except/catch blocks in any language.

This is a universal rule — works on all languages.
"""

from typing import List, Dict, Any

from pyneat.rules.universal.base import UniversalRule


class EmptyCatchRule(UniversalRule):
    """Detect empty except/catch blocks that silently swallow errors.

    Severity: MEDIUM
    """

    @property
    def rule_id(self) -> str:
        return "UNI-003"

    @property
    def description(self) -> str:
        return "Detect empty catch/except blocks"

    def analyze(self, code: str, ln_ast: dict) -> List[dict]:
        findings = []

        for catch in ln_ast.get("catch_blocks", []):
            if catch.get("is_empty", False):
                line_num = catch.get("start_line", 1)
                exc_type = catch.get("exception_type", "Exception")

                findings.append({
                    "rule_id": self.rule_id,
                    "start": 0,  # Not available in catch block data
                    "end": 0,
                    "severity": "medium",
                    "problem": f"Empty {exc_type} block on line {line_num} — errors will be silently swallowed",
                    "fix_hint": "Add error handling, logging, or re-raise the exception",
                    "auto_fix_available": False,
                    "replacement": "",
                })

        return findings
