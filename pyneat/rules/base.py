"""Abstract base class for all cleaning rules.

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

For commercial licensing, contact: khanhnam.copywriting@gmail.com
"""

from abc import ABC, abstractmethod
from typing import List, Set, Optional
import re
from datetime import datetime

from pyneat.core.types import CodeFile, TransformationResult, RuleConfig, AgentMarker, MarkerIdGenerator


class Rule(ABC):
    """Base class for all code cleaning rules."""

    # --------------------------------------------------------------------------
    # Subclass-overridable defaults
    # --------------------------------------------------------------------------

    #: Node types this rule class is designed to change semantically.
    #: The engine checks this to avoid flagging expected structural changes
    #: as unsafe semantic diffs.  For example, DeadCodeRule sets
    #: ``{"FunctionDef", "AsyncFunctionDef", "ClassDef"}``.
    ALLOWED_SEMANTIC_NODES: Set[str] = set()

    # --------------------------------------------------------------------------
    # Init
    # --------------------------------------------------------------------------

    def __init__(self, config: RuleConfig = None):
        self.config = config or RuleConfig()
        self.name = self.__class__.__name__

    # --------------------------------------------------------------------------
    # Public API
    # --------------------------------------------------------------------------

    @abstractmethod
    def apply(self, code_file: CodeFile) -> TransformationResult:
        """Apply this rule to the given code file."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this rule does."""
        pass

    @property
    def allowed_semantic_nodes(self) -> Set[str]:
        """Node types this rule is allowed to change.

        Combines the class-level ``ALLOWED_SEMANTIC_NODES`` with any
        nodes declared in the per-instance ``config.allowed_semantic_nodes``.
        """
        return self.ALLOWED_SEMANTIC_NODES | set(self.config.allowed_semantic_nodes or [])

    # --------------------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    # AgentMarker support (Phase 1.1 — killing feature foundation)
    # --------------------------------------------------------------------------

    #: Counter for generating unique marker IDs within this rule class.
    _marker_counter: int = 0

    #: Default severity for markers produced by this rule.
    #: Subclasses can override this.  Valid values: critical, high, medium, low, info.
    DEFAULT_SEVERITY: str = "medium"

    def _next_marker_id(self, category: Optional[str] = None) -> str:
        """Generate a unique marker ID.

        Uses MarkerIdGenerator for cross-session uniqueness, but also
        increments an instance counter for per-rule ordering.
        """
        Rule._marker_counter += 1
        generator = MarkerIdGenerator()
        return generator.generate(self.name, category)

    def _extract_line_from_change(self, change: str) -> int:
        """Extract line number from a change string like 'RULE: msg at line 42'."""
        match = re.search(r"\bat line\s+(\d+)", change, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return 1

    def _extract_snippet_from_change(
        self, change: str, code_file: CodeFile, line: int
    ) -> Optional[str]:
        """Extract a code snippet around the line of the change."""
        lines = code_file.content.splitlines()
        if line < 1 or line > len(lines):
            return None
        start = max(0, line - 2)
        end = min(len(lines), line + 1)
        snippet = "\n".join(lines[start:end])
        return snippet[:200] if snippet else None

    def build_agent_marker(
        self,
        change: str,
        code_file: CodeFile,
        issue_type: Optional[str] = None,
        severity: Optional[str] = None,
        hint: Optional[str] = None,
        why: Optional[str] = None,
        impact: Optional[str] = None,
        confidence: float = 0.85,
        confidence_note: Optional[str] = None,
        can_auto_fix: bool = False,
        fix_constraints: Optional[tuple] = None,
        do_not: Optional[tuple] = None,
        verify: Optional[tuple] = None,
        resources: Optional[tuple] = None,
        category: Optional[str] = None,
        language: Optional[str] = None,
    ) -> AgentMarker:
        """Build an AgentMarker from a change message string.

        This is the primary helper for non-security rules to emit markers.
        It parses the change string for line numbers and generates a
        fully-populated AgentMarker with all fields.

        Args:
            change: Change message, optionally containing "at line N".
            code_file: The CodeFile being processed.
            issue_type: Issue type slug (e.g. "unused_import"). Defaults to rule name.
            severity: One of critical/high/medium/low/info. Defaults to DEFAULT_SEVERITY.
            hint: Suggested fix.
            why: Why this is a problem.
            impact: Consequences if exploited.
            confidence: 0.0-1.0 detection confidence.
            confidence_note: Explanation of confidence level.
            can_auto_fix: Whether auto-fix is possible.
            fix_constraints: Tuple of fix constraints.
            do_not: Tuple of common mistakes to avoid.
            verify: Tuple of verification steps.
            resources: Tuple of documentation links.
            category: MarkerIdGenerator category override.
            language: Language override (defaults to code_file.language).
        """
        line = self._extract_line_from_change(change)
        snippet = self._extract_snippet_from_change(change, code_file, line)

        # Build why from change message if not provided
        if why is None:
            why = re.sub(r"\s+at line\s+\d+", "", change).strip()
            if not why:
                why = self.description

        return AgentMarker(
            marker_id=self._next_marker_id(category),
            issue_type=issue_type or self.name.lower().replace("rule", "").replace("_", "-"),
            rule_id=self.name,
            severity=severity or self.DEFAULT_SEVERITY,
            line=line,
            hint=hint,
            why=why,
            impact=impact,
            confidence=confidence,
            confidence_note=confidence_note or "detected via AST pattern matching",
            can_auto_fix=can_auto_fix,
            snippet=snippet,
            fix_constraints=fix_constraints or (),
            do_not=do_not or (),
            verify=verify or (),
            resources=resources or (),
            file_path=str(code_file.path),
            language=language or code_file.language,
            detected_at=datetime.now().isoformat() + "Z",
        )

    def _create_result(
        self,
        original: CodeFile,
        transformed: str,
        changes: List[str],
        markers: Optional[List[AgentMarker]] = None,
    ) -> TransformationResult:
        """Helper to create consistent transformation results with optional markers."""
        return TransformationResult(
            original=original,
            transformed_content=transformed,
            changes_made=changes,
            success=True,
            agent_markers=markers or [],
        )

    def _create_error_result(self, original: CodeFile, error: str) -> TransformationResult:
        """Helper to create error results."""
        return TransformationResult(
            original=original,
            transformed_content=original.content,
            changes_made=[],
            success=False,
            error=error,
        )
