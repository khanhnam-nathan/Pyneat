"""Detect and remove debug print/log statements in any language.

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

import re
from typing import List, Dict, Any

from pyneat.rules.universal.base import UniversalRule


# Language-specific debug patterns (regex-based)
DEBUG_PATTERNS = {
    "python": [
        r'\bprint\s*\(',
        r'\bpprint\s*\(',
        r'\bpdb\.set_trace\s*\(',
        r'\bbreakpoint\s*\(',
        r'\bipdb\.set_trace\s*\(',
        r'\bicecream\.ic\s*\(',
        r'\bic\s*\(',
    ],
    "javascript": [
        r'\bconsole\.(log|warn|error|debug|info|trace|dir)\s*\(',
        r'\balert\s*\(',
        r'\bdebugger\s*;',
    ],
    "typescript": [
        r'\bconsole\.(log|warn|error|debug|info|trace|dir)\s*\(',
        r'\balert\s*\(',
        r'\bdebugger\s*;',
    ],
    "go": [
        r'\bfmt\.Print(?:f|ln)?\s*\(',
        r'\blog\.(Print|Fatal|Panic|Println|Printf)\s*\(',
    ],
    "java": [
        r'\bSystem\.out\.print(?:f|ln)?\s*\(',
        r'\bSystem\.err\.print(?:f|ln)?\s*\(',
        r'\bprintStackTrace\s*\(',
    ],
    "rust": [
        r'\bprintln!\s*\(',
        r'\beprintln!\s*\(',
        r'\bprint!\s*\(',
        r'\beprint!\s*\(',
        r'\bdbg!\s*\(',
    ],
    "csharp": [
        r'\bConsole\.(WriteLine|Write)\s*\(',
        r'\bDebug\.Print\s*\(',
        r'\bSystem\.Diagnostics\.Debug\.WriteLine\s*\(',
    ],
    "php": [
        r'\b(?:var_dump|print_r|echo|printf|var_export)\s*\(',
        r'\bdie\s*\(',
        r'\bexit\s*\(',
    ],
    "ruby": [
        r'\b(?:puts|p|pp)\s+',
        r'\bprint\s+',
        r'\bputs\s+',
    ],
}

# Language-independent debug patterns
LANG_INDEPENDENT_PATTERNS = [
    r'\bdebugger\s*;',  # Works in JS/TS/PHP/C#
]


class DebugArtifactsRule(UniversalRule):
    """Detect debug print/log statements in any language.

    Severity: LOW (cosmetic, easy to fix)
    """

    @property
    def rule_id(self) -> str:
        return "UNI-002"

    @property
    def description(self) -> str:
        return "Detect and remove debug statements"

    def analyze(self, code: str, ln_ast: dict) -> List[dict]:
        findings = []
        lang = ln_ast.get("language", "")

        # Get language-specific patterns
        patterns = DEBUG_PATTERNS.get(lang, [])

        # Add language-independent patterns
        if lang in ("javascript", "typescript", "php", "csharp"):
            patterns = list(patterns) + LANG_INDEPENDENT_PATTERNS

        for pattern in patterns:
            try:
                for match in re.finditer(pattern, code):
                    line_num = code[:match.start()].count('\n') + 1

                    findings.append({
                        "rule_id": self.rule_id,
                        "start": match.start(),
                        "end": match.end(),
                        "severity": "low",
                        "problem": f"Debug statement on line {line_num}: {match.group()[:50]}",
                        "fix_hint": "Remove or replace with proper logging framework",
                        "auto_fix_available": True,
                        "replacement": self._get_replacement(lang, match.group()),
                    })
            except re.error:
                continue

        return findings

    def _get_replacement(self, lang: str, matched: str) -> str:
        """Get language-appropriate replacement."""
        if lang in ("python", "ruby"):
            return f"# {matched.strip()}"
        return ""
