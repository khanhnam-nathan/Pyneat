"""Domain types and data models."""

from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from pathlib import Path

@dataclass(frozen=True)
class CodeFile:
    """Represents a code file with its content and metadata."""
    path: Path
    content: str
    language: str = "python"
    
    @property
    def filename(self) -> str:
        return self.path.name

@dataclass(frozen=True)
class TransformationResult:
    """Result of a code transformation operation."""
    original: CodeFile
    transformed_content: str
    changes_made: List[str]
    success: bool
    error: Optional[str] = None
    
    @property
    def has_changes(self) -> bool:
        return len(self.changes_made) > 0

@dataclass(frozen=True)
class RuleConfig:
    """Configuration for a cleaning rule."""
    enabled: bool = True
    params: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.params is None:
            object.__setattr__(self, 'params', {})
