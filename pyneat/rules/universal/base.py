"""Base class for universal (cross-language) rules.

Universal rules work on LN-AST (Language-Neutral AST) which is the
same format for all languages. No language-specific branching needed.

Usage:
    from pyneat.rules.universal.base import UniversalRule

    class MyRule(UniversalRule):
        @property
        def rule_id(self) -> str:
            return "UNI-XXX"

        @property
        def description(self) -> str:
            return "Description of what this rule does"

        def analyze(self, code: str, ln_ast: dict) -> List[dict]:
            findings = []
            # Check ln_ast fields: functions, calls, strings, comments, etc.
            return findings
"""

from abc import abstractmethod
from typing import List, Dict, Any, Optional
import re

from pyneat.rules.base import Rule
from pyneat.core.types import CodeFile, TransformationResult


class UniversalRule(Rule):
    """Base for rules that work across ALL supported languages.

    Universal rules receive LN-AST (a dict) and produce fix hints.
    The fix hints are byte offsets + replacement text, which are
    applied directly or via the Rust fixer.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier like 'UNI-001'."""
        pass

    @property
    def supported_languages(self) -> List[str]:
        return ["*"]  # Universal — works on all languages

    @abstractmethod
    def analyze(self, code: str, ln_ast: Optional[dict]) -> List[dict]:
        """Analyze code and return list of findings.

        Args:
            code: Raw source code as string
            ln_ast: Language-Neutral AST dict (from Rust parser) or {} if not available

        Each Finding is a dict with keys:
            - rule_id: str
            - start: int (byte/char offset in code)
            - end: int
            - severity: str
            - problem: str
            - fix_hint: str
            - auto_fix_available: bool
            - replacement: str (optional, for auto-fix)
        """
        pass

    def apply(self, code_file: CodeFile) -> TransformationResult:
        """Apply this rule using LN-AST or raw code fallback.

        If pyneat_rs is not installed (ln_ast is None), fall back to
        raw code analysis (for regex-based rules like secrets, todos, debug).
        """
        # Collect raw code and ln_ast for the rule to analyze
        raw_code = code_file.content
        ln_ast = code_file.ln_ast  # May be None if pyneat_rs not installed

        try:
            findings = self.analyze(raw_code, ln_ast or {})

            if not findings:
                return self._create_result(code_file, code_file.content, [])

            # Apply fixes
            current = code_file.content
            applied = []

            for finding in findings:
                if not finding.get("auto_fix_available", False):
                    applied.append(f"[{finding.get('rule_id', self.rule_id)}] {finding.get('problem', '')}")
                    continue

                start = finding.get("start", 0)
                end = finding.get("end", 0)
                replacement = finding.get("replacement", "")

                try:
                    if start >= 0 and end > start and end <= len(current):
                        current = current[:start] + replacement + current[end:]
                    applied.append(f"[{finding.get('rule_id', self.rule_id)}] {finding.get('problem', '')}")
                except Exception:
                    pass

            return self._create_result(code_file, current, applied)
        except Exception as e:
            return self._create_error_result(code_file, str(e))
