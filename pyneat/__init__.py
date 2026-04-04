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

__version__ = "1.0.0"
__all__ = [
    'RuleEngine',
    'CodeFile', 
    'RuleConfig',
    'ImportCleaningRule',
    'NamingConventionRule',
    'RefactoringRule',
    'SecurityScannerRule', 
    'CodeQualityRule',
    'PerformanceRule'
]
