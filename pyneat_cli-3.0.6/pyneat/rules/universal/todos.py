"""Detect TODO/FIXME/HACK comments in any language.

This is a universal rule — works on all languages.
"""

import re
from typing import List, Dict, Any

from pyneat.rules.universal.base import UniversalRule


# Pattern to match TODO/FIXME/HACK comments
TODO_PATTERN = re.compile(
    r'(#|//|/\*|--|<!--)\s*(TODO|FIXME|HACK|XXX|NOTE|BUG):?\s*(.*)',
    re.IGNORECASE | re.MULTILINE
)


class TodoCommentRule(UniversalRule):
    """Detect TODO/FIXME comments for cleanup.

    Severity: INFO
    """

    @property
    def rule_id(self) -> str:
        return "UNI-004"

    @property
    def description(self) -> str:
        return "Detect TODO/FIXME comments"

    def analyze(self, code: str, ln_ast: dict) -> List[dict]:
        findings = []

        for match in TODO_PATTERN.finditer(code):
            marker = match.group(2).upper()
            description = match.group(3).strip()
            line_num = code[:match.start()].count('\n') + 1

            findings.append({
                "rule_id": self.rule_id,
                "start": match.start(),
                "end": match.end(),
                "severity": "info",
                "problem": f"{marker}: {description}" if description else f"{marker} comment on line {line_num}",
                "fix_hint": "Address or remove the TODO comment",
                "auto_fix_available": True,
                "replacement": "",  # Delete the comment
            })

        return findings
