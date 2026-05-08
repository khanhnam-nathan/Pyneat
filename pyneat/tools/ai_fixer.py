"""AI-powered fix suggestion engine for PyNEAT.

Copyright (c) 2026 PyNEAT Authors
License: AGPL-3.0

Uses pattern-based fix suggestions with:
  - Code context analysis
  - Multiple fix strategies per rule
  - Fix difficulty rating
  - Estimated impact assessment
  - Related patterns detection
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any, Tuple

from pyneat.core.types import SecurityFinding, SecuritySeverity


class FixDifficulty(Enum):
    """How difficult is the fix to implement."""
    TRIVIAL = "trivial"      # One-liner, no risk
    EASY = "easy"           # Small change, low risk
    MODERATE = "moderate"   # Requires refactoring
    COMPLEX = "complex"     # Needs architectural changes
    EXPERT = "expert"       # Requires deep domain knowledge


class FixImpact(Enum):
    """Impact of the fix on the codebase."""
    NONE = "none"           # No functional change
    MINOR = "minor"         # Cosmetic/style change
    BEHAVIORAL = "behavioral"  # Changes behavior (review needed)
    BREAKING = "breaking"   # May break existing code


@dataclass
class FixSuggestion:
    """A suggested fix for a security finding."""
    rule_id: str
    problem: str
    fix_code: str
    explanation: str
    difficulty: FixDifficulty
    impact: FixImpact
    confidence: float  # 0.0 - 1.0
    before_example: str = ""
    after_example: str = ""
    related_rules: List[str] = field(default_factory=list)
    estimated_lines: int = 0
    requires_test: bool = False
    deprecated_alternatives: List[str] = field(default_factory=list)


@dataclass
class FixContext:
    """Context around a finding to help generate better fixes."""
    file_path: str
    line_number: int
    snippet: str
    surrounding_lines: str = ""
    function_name: str = ""
    class_name: str = ""
    imports: List[str] = field(default_factory=list)
    language: str = "python"


class FixSuggestionEngine:
    """Generates AI-like fix suggestions for security findings.

    Uses pattern matching and rule-based reasoning to suggest fixes
    with multiple strategies per finding type.
    """

    def __init__(self):
        self.fix_registry: Dict[str, List[FixSuggestion]] = {}
        self._register_all_fixes()

    def _register_all_fixes(self):
        """Register all fix suggestions for each rule."""
        # SEC-001: os.system
        self.register(SEC001Fixes())

        # SEC-002: eval/exec
        self.register(SEC002Fixes())

        # SEC-003: pickle.loads
        self.register(SEC003Fixes())

        # SEC-010: hardcoded password
        self.register(SEC010Fixes())

        # SEC-024: SQL injection
        self.register(SEC024Fixes())

        # SEC-042: subprocess shell=True
        self.register(SEC042Fixes())

        # SEC-063: hardcoded secrets
        self.register(SEC063Fixes())

        # SEC-070: weak crypto (MD5)
        self.register(SEC070Fixes())

        # SEC-071: weak crypto (SHA1)
        self.register(SEC071Fixes())

        # Generic patterns
        self.register(GenericFixes())

    def register(self, fixes: "FixCollection"):
        """Register fix suggestions from a fix collection."""
        for suggestion in fixes.get_suggestions():
            if suggestion.rule_id not in self.fix_registry:
                self.fix_registry[suggestion.rule_id] = []
            self.fix_registry[suggestion.rule_id].append(suggestion)

    def suggest_fixes(self, finding: SecurityFinding,
                      context: Optional[FixContext] = None) -> List[FixSuggestion]:
        """Get fix suggestions for a security finding.

        Args:
            finding: The security finding to fix
            context: Optional context about the finding location

        Returns:
            List of fix suggestions, sorted by confidence
        """
        suggestions = self.fix_registry.get(finding.rule_id, [])

        # Add context-aware filtering
        if context:
            suggestions = self._filter_by_context(suggestions, context)

        # Sort by confidence (highest first)
        suggestions = sorted(suggestions, key=lambda s: s.confidence, reverse=True)

        return suggestions

    def _filter_by_context(self, suggestions: List[FixSuggestion],
                            context: FixContext) -> List[FixSuggestion]:
        """Filter suggestions based on context."""
        filtered = []
        for suggestion in suggestions:
            # Skip suggestions that don't match the language
            if context.language == "python" and "python" in suggestion.explanation.lower():
                filtered.append(suggestion)
            elif context.language == "javascript" and "javascript" in suggestion.explanation.lower():
                filtered.append(suggestion)
            elif context.language not in ("python", "javascript"):
                filtered.append(suggestion)
        return filtered if filtered else suggestions

    def get_fix_comparison(self, finding: SecurityFinding) -> str:
        """Get a comparison of fix options for a finding."""
        suggestions = self.suggest_fixes(finding)
        if not suggestions:
            return "No automated fix available. Manual review required."

        lines = []
        lines.append(f"Fix options for {finding.rule_id}:")
        lines.append("")

        for i, suggestion in enumerate(suggestions, 1):
            lines.append(f"{i}. {suggestion.difficulty.value.upper()} - {suggestion.impact.value}")
            lines.append(f"   Confidence: {suggestion.confidence * 100:.0f}%")
            if suggestion.before_example and suggestion.after_example:
                lines.append("   Before:")
                for line in suggestion.before_example.split('\n'):
                    lines.append(f"     {line}")
                lines.append("   After:")
                for line in suggestion.after_example.split('\n'):
                    lines.append(f"     {line}")
            lines.append("")

        return '\n'.join(lines)

    def apply_fix_preview(self, code: str, finding: SecurityFinding,
                           suggestion: FixSuggestion) -> str:
        """Preview what the code would look like with the fix applied.

        Args:
            code: Original source code
            finding: The finding to fix
            suggestion: The fix suggestion to apply

        Returns:
            Modified code with fix applied
        """
        # This is a simplified preview - real implementation would use AST
        lines = code.split('\n')
        if 0 < finding.start_line <= len(lines):
            # Replace the line with the fix
            original_line = lines[finding.start_line - 1]
            modified_line = self._apply_line_fix(original_line, suggestion)
            lines[finding.start_line - 1] = modified_line
        return '\n'.join(lines)

    def _apply_line_fix(self, line: str, suggestion: FixSuggestion) -> str:
        """Apply a simple line-level fix."""
        # This is pattern-based and limited
        if "SEC-001" in suggestion.rule_id and "os.system" in line:
            return "# TODO: Replace os.system with subprocess.run()"
        return line


# ============================================================================
# Fix Collections for Each Rule
# ============================================================================

class SEC001Fixes(FixCollection):
    """Fixes for SEC-001: os.system command injection."""

    def get_suggestions(self) -> List[FixSuggestion]:
        return [
            FixSuggestion(
                rule_id="SEC-001",
                problem="os.system() is vulnerable to command injection",
                fix_code="import subprocess\nsubprocess.run(['ls', '-la'], check=True)",
                explanation="Use subprocess.run() with a list of arguments instead of a shell string. "
                           "This prevents shell injection because the arguments are passed directly "
                           "to the executable without shell interpretation.",
                difficulty=FixDifficulty.EASY,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.95,
                before_example="import os\nos.system('ls -la')",
                after_example="import subprocess\nsubprocess.run(['ls', '-la'], check=True)",
                related_rules=["SEC-042"],
                estimated_lines=2,
                requires_test=True,
            ),
            FixSuggestion(
                rule_id="SEC-001",
                problem="os.system() is vulnerable to command injection",
                fix_code="import subprocess\noutput = subprocess.check_output(['ls', '-la'], text=True)",
                explanation="For capturing output, use subprocess.check_output() with argument list.",
                difficulty=FixDifficulty.EASY,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.90,
                before_example="import os\noutput = os.popen('ls -la').read()",
                after_example="import subprocess\noutput = subprocess.check_output(['ls', '-la'], text=True)",
                related_rules=["SEC-042"],
                estimated_lines=2,
                requires_test=True,
            ),
        ]


class SEC002Fixes(FixCollection):
    """Fixes for SEC-002: eval/exec usage."""

    def get_suggestions(self) -> List[FixSuggestion]:
        return [
            FixSuggestion(
                rule_id="SEC-002",
                problem="eval() can execute arbitrary code",
                fix_code="ast.literal_eval(user_input)",
                explanation="Use ast.literal_eval() for parsing Python literals (strings, numbers, "
                           "lists, dicts). This is safe because it only evaluates Python literals, "
                           "not arbitrary code.",
                difficulty=FixDifficulty.EASY,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.95,
                before_example="result = eval(user_input)",
                after_example="import ast\nresult = ast.literal_eval(user_input)",
                related_rules=[],
                estimated_lines=1,
                requires_test=True,
            ),
            FixSuggestion(
                rule_id="SEC-002",
                problem="exec() can execute arbitrary code",
                fix_code="ast.parse(user_code)",
                explanation="Use ast.parse() to safely parse code without executing it. "
                           "This validates the syntax without running the code.",
                difficulty=FixDifficulty.EASY,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.90,
                before_example="exec(user_code)",
                after_example="import ast\nast.parse(user_code)  # Validate syntax only",
                related_rules=[],
                estimated_lines=1,
                requires_test=True,
            ),
        ]


class SEC003Fixes(FixCollection):
    """Fixes for SEC-003: pickle deserialization RCE."""

    def get_suggestions(self) -> List[FixSuggestion]:
        return [
            FixSuggestion(
                rule_id="SEC-003",
                problem="pickle.loads() can execute arbitrary code on crafted input",
                fix_code="import json\ndata = json.loads(user_data)",
                explanation="Use JSON for data exchange instead of pickle. JSON is a widely "
                           "supported, language-independent format that cannot execute code.",
                difficulty=FixDifficulty.MODERATE,
                impact=FixImpact.BREAKING,
                confidence=0.95,
                before_example="import pickle\ndata = pickle.loads(user_data)",
                after_example="import json\ndata = json.loads(user_data)",
                related_rules=[],
                estimated_lines=1,
                requires_test=True,
            ),
            FixSuggestion(
                rule_id="SEC-003",
                problem="pickle.loads() is vulnerable to RCE",
                fix_code="from restricted_unpickler import RestrictedUnpickler\ndata = RestrictedUnpickler.loads(user_data)",
                explanation="Use restricted-unpickler to limit which classes can be unpickled. "
                           "This prevents RCE by only allowing known safe classes.",
                difficulty=FixDifficulty.COMPLEX,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.80,
                before_example="import pickle\ndata = pickle.loads(user_data)",
                after_example="from restricted_unpickler import RestrictedUnpickler\np = RestrictedUnpickler(['__builtins__', 'list', 'dict'])\ndata = p.loads(user_data)",
                related_rules=[],
                estimated_lines=10,
                requires_test=True,
            ),
        ]


class SEC010Fixes(FixCollection):
    """Fixes for SEC-010: hardcoded password."""

    def get_suggestions(self) -> List[FixSuggestion]:
        return [
            FixSuggestion(
                rule_id="SEC-010",
                problem="Hardcoded password found in source code",
                fix_code="import os\npassword = os.environ.get('DB_PASSWORD')",
                explanation="Use environment variables for sensitive configuration. "
                           "Environment variables are not stored in source control and "
                           "can be set differently per environment.",
                difficulty=FixDifficulty.EASY,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.95,
                before_example="password = 'secret123'",
                after_example="import os\npassword = os.environ.get('DB_PASSWORD')",
                related_rules=["SEC-SECRET-001", "SEC-SECRET-030"],
                estimated_lines=1,
                requires_test=False,
            ),
            FixSuggestion(
                rule_id="SEC-010",
                problem="Hardcoded password found in source code",
                fix_code="from keyring import get_password\npassword = get_password('myapp', 'db')",
                explanation="Use Python keyring library to store credentials securely in "
                           "the system keychain (macOS Keychain, Windows Credential Manager, etc.).",
                difficulty=FixDifficulty.MODERATE,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.85,
                before_example="password = 'secret123'",
                after_example="import keyring\npassword = keyring.get_password('myapp', 'db')",
                related_rules=["SEC-SECRET-001"],
                estimated_lines=1,
                requires_test=False,
            ),
        ]


class SEC024Fixes(FixCollection):
    """Fixes for SEC-024: SQL injection."""

    def get_suggestions(self) -> List[FixSuggestion]:
        return [
            FixSuggestion(
                rule_id="SEC-024",
                problem="SQL query uses string concatenation - vulnerable to SQL injection",
                fix_code="cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                explanation="Use parameterized queries (placeholders) instead of string formatting. "
                           "This separates SQL code from data, preventing injection attacks.",
                difficulty=FixDifficulty.MODERATE,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.95,
                before_example="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                after_example="cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                related_rules=[],
                estimated_lines=1,
                requires_test=True,
            ),
            FixSuggestion(
                rule_id="SEC-024",
                problem="SQL query uses string concatenation",
                fix_code="cursor.execute('SELECT * FROM users WHERE name = %(name)s', {'name': name})",
                explanation="Use named parameters for complex queries. This makes the code more readable "
                           "while still being safe from injection.",
                difficulty=FixDifficulty.EASY,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.90,
                before_example="query = 'SELECT * FROM users WHERE name = ' + repr(name)",
                after_example="cursor.execute('SELECT * FROM users WHERE name = %(name)s', {'name': name})",
                related_rules=[],
                estimated_lines=1,
                requires_test=True,
            ),
        ]


class SEC042Fixes(FixCollection):
    """Fixes for SEC-042: subprocess with shell=True."""

    def get_suggestions(self) -> List[FixSuggestion]:
        return [
            FixSuggestion(
                rule_id="SEC-042",
                problem="subprocess.run() with shell=True is vulnerable to shell injection",
                fix_code="subprocess.run(['command', arg1, arg2], check=True)",
                explanation="Pass command arguments as a list without shell=True. "
                           "This avoids shell interpretation of special characters.",
                difficulty=FixDifficulty.EASY,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.95,
                before_example="subprocess.run('command ' + user_input, shell=True)",
                after_example="subprocess.run(['command', user_input], check=True)",
                related_rules=["SEC-001"],
                estimated_lines=1,
                requires_test=True,
            ),
        ]


class SEC063Fixes(FixCollection):
    """Fixes for SEC-063: hardcoded secrets."""

    def get_suggestions(self) -> List[FixSuggestion]:
        return [
            FixSuggestion(
                rule_id="SEC-063",
                problem="Hardcoded API key detected",
                fix_code="import os\napi_key = os.environ.get('API_KEY')",
                explanation="Move API keys to environment variables. Use a .env file (with .env.example) "
                           "or a secrets manager like AWS Secrets Manager, HashiCorp Vault, or Docker secrets.",
                difficulty=FixDifficulty.EASY,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.95,
                before_example="API_KEY = 'sk_live_abc123...'",
                after_example="import os\nAPI_KEY = os.environ.get('API_KEY')",
                related_rules=["SEC-SECRET-001", "SEC-SECRET-003"],
                estimated_lines=1,
                requires_test=False,
            ),
            FixSuggestion(
                rule_id="SEC-063",
                problem="Hardcoded API key detected",
                fix_code="from dotenv import load_dotenv\nload_dotenv()\nAPI_KEY = os.environ.get('API_KEY')",
                explanation="Use python-dotenv for local development. Keep .env in .gitignore "
                           "and commit .env.example with placeholder values.",
                difficulty=FixDifficulty.EASY,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.90,
                before_example="API_KEY = 'sk_live_abc123...'",
                after_example="from dotenv import load_dotenv\nimport os\nload_dotenv()\nAPI_KEY = os.environ.get('API_KEY')",
                related_rules=["SEC-SECRET-001"],
                estimated_lines=2,
                requires_test=False,
            ),
        ]


class SEC070Fixes(FixCollection):
    """Fixes for SEC-070: MD5 usage for security."""

    def get_suggestions(self) -> List[FixSuggestion]:
        return [
            FixSuggestion(
                rule_id="SEC-070",
                problem="MD5 is cryptographically broken - do not use for security",
                fix_code="import hashlib\nhash_value = hashlib.sha256(data).hexdigest()",
                explanation="Use SHA-256 or better (SHA-3, Blake2) for cryptographic hashing. "
                           "MD5 has known collision attacks and is too weak for security purposes.",
                difficulty=FixDifficulty.EASY,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.95,
                before_example="import hashlib\nhashlib.md5(data).hexdigest()",
                after_example="import hashlib\nhashlib.sha256(data).hexdigest()",
                related_rules=["SEC-071", "SEC-072"],
                estimated_lines=1,
                requires_test=True,
            ),
        ]


class SEC071Fixes(FixCollection):
    """Fixes for SEC-071: SHA1 usage for security."""

    def get_suggestions(self) -> List[FixSuggestion]:
        return [
            FixSuggestion(
                rule_id="SEC-071",
                problem="SHA1 is deprecated for security purposes",
                fix_code="import hashlib\nhash_value = hashlib.sha256(data).hexdigest()",
                explanation="Use SHA-256 or SHA-3 instead of SHA-1. SHA-1 has known weaknesses "
                           "and is being phased out by browsers and security standards.",
                difficulty=FixDifficulty.EASY,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.95,
                before_example="import hashlib\nhashlib.sha1(data).hexdigest()",
                after_example="import hashlib\nhashlib.sha256(data).hexdigest()",
                related_rules=["SEC-070", "SEC-072"],
                estimated_lines=1,
                requires_test=True,
            ),
        ]


class GenericFixes(FixCollection):
    """Generic fix suggestions for common patterns."""

    def get_suggestions(self) -> List[FixSuggestion]:
        return [
            FixSuggestion(
                rule_id="GENERIC-INSECURE-RANDOM",
                problem="random module is not cryptographically secure",
                fix_code="import secrets\ntoken = secrets.token_hex(32)",
                explanation="Use the secrets module for cryptographic randomness. "
                           "The random module uses a predictable Mersenne Twister PRNG.",
                difficulty=FixDifficulty.EASY,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.95,
                before_example="import random\ntoken = random.randint(0, 2**32)",
                after_example="import secrets\ntoken = secrets.token_hex(32)",
                related_rules=["SEC-069"],
                estimated_lines=1,
                requires_test=True,
            ),
            FixSuggestion(
                rule_id="GENERIC-INSECURE-TLS",
                problem="Insecure SSL/TLS configuration",
                fix_code="import ssl\ncontext = ssl.create_default_context()",
                explanation="Use Python's default SSL context which has secure defaults. "
                           "Avoid ssl._create_unverified_context() which bypasses certificate validation.",
                difficulty=FixDifficulty.EASY,
                impact=FixImpact.BEHAVIORAL,
                confidence=0.95,
                before_example="import ssl\nctx = ssl._create_unverified_context()",
                after_example="import ssl\nctx = ssl.create_default_context()",
                related_rules=["SEC-044"],
                estimated_lines=1,
                requires_test=True,
            ),
        ]


class FixCollection:
    """Base class for fix collections."""

    def get_suggestions(self) -> List[FixSuggestion]:
        raise NotImplementedError


def suggest_fix(finding: SecurityFinding, context: Optional[FixContext] = None) -> List[FixSuggestion]:
    """Convenience function to get fix suggestions for a finding."""
    engine = FixSuggestionEngine()
    return engine.suggest_fixes(finding, context)


def compare_fixes(finding: SecurityFinding) -> str:
    """Convenience function to compare fix options."""
    engine = FixSuggestionEngine()
    return engine.get_fix_comparison(finding)


__all__ = [
    "FixSuggestion",
    "FixContext",
    "FixSuggestionEngine",
    "FixDifficulty",
    "FixImpact",
    "FixCollection",
    "suggest_fix",
    "compare_fixes",
]
