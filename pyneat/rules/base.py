"""Abstract base class for all cleaning rules."""

from abc import ABC, abstractmethod
from typing import List
from pyneat.core.types import CodeFile, TransformationResult, RuleConfig

class Rule(ABC):
    """Base class for all code cleaning rules."""
    
    def __init__(self, config: RuleConfig = None):
        self.config = config or RuleConfig()
        self.name = self.__class__.__name__
    
    @abstractmethod
    def apply(self, code_file: CodeFile) -> TransformationResult:
        """Apply this rule to the given code file."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this rule does."""
        pass
    
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
