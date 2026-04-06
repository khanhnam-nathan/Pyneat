# pyneat/__init__.py
"""PyNeat - Neat Python AI Code Cleaner."""

from .core.engine import RuleEngine
from .core.types import CodeFile, RuleConfig
from .rules.imports import ImportCleaningRule
from .rules.naming import NamingConventionRule
from .rules.refactoring import RefactoringRule
from .rules.security import SecurityScannerRule
from .rules.quality import CodeQualityRule
from .rules.performance import PerformanceRule
from .rules.debug import DebugCleaner
from .rules.comments import CommentCleaner
from .rules.unused import UnusedImportRule
from .rules.redundant import RedundantExpressionRule
from .rules.is_not_none import IsNotNoneRule
from .rules.magic_numbers import MagicNumberRule
from .rules.range_len_pattern import RangeLenRule

__version__ = "2.0.0"
__all__ = [
    'RuleEngine',
    'CodeFile',
    'RuleConfig',
    'ImportCleaningRule',
    'NamingConventionRule',
    'RefactoringRule',
    'SecurityScannerRule',
    'CodeQualityRule',
    'PerformanceRule',
    'DebugCleaner',
    'CommentCleaner',
    'UnusedImportRule',
    'RedundantExpressionRule',
    'IsNotNoneRule',
    'MagicNumberRule',
    'RangeLenRule',
]
