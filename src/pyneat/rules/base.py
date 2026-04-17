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
from typing import List, Set
from pyneat.core.types import CodeFile, TransformationResult, RuleConfig


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

    def _create_result(self, original: CodeFile, transformed: str, changes: List[str]) -> TransformationResult:
        """Helper to create consistent transformation results."""
        return TransformationResult(
            original=original,
            transformed_content=transformed,
            changes_made=changes,
            success=True
        )

    def _create_error_result(self, original: CodeFile, error: str) -> TransformationResult:
        """Helper to create error results."""
        return TransformationResult(
            original=original,
            transformed_content=original.content,
            changes_made=[],
            success=False,
            error=error
        )
