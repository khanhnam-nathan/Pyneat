"""PyNeat - Neat Python AI Code Cleaner.

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

For commercial licensing, contact: license@pyneat.dev

A quick-start example:

    from pyneat import clean_code, RuleEngine, CodeFile

    # Simplest usage - just pass code as a string
    result = clean_code("x == None")
    print(result)  # "x is None"

    # With options
    result = clean_code("print('debug')", remove_debug=True)
    print(result)  # "pass"

    # Advanced: custom engine
    from pyneat import RuleEngine, DebugCleaner, IsNotNoneRule
    engine = RuleEngine([DebugCleaner(mode="safe"), IsNotNoneRule()])
    result = engine.process_code_file(CodeFile(path=Path("demo.py"), content=source))
"""

from pathlib import Path
from typing import List, Optional, Dict, Any

from .core.engine import RuleEngine
from .core.types import (
    CodeFile,
    RuleConfig,
    TransformationResult,
    RuleConflict,
    RuleRange,
    AgentMarker,
    # Security types
    SecuritySeverity,
    SecurityFinding,
    DependencyFinding,
    CWE_SEVERITY_MAP,
    OWASP_SEVERITY_MAP,
)
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
from .rules.deadcode import DeadCodeRule
from .rules.fstring import FStringRule
from .rules.typing import TypingRule
from .rules.match_case import MatchCaseRule
from .rules.dataclass import DataclassSuggestionRule
from .rules.init_protection import InitFileProtectionRule

# Security registry
from .rules.security_registry import SECURITY_RULES_REGISTRY, get_security_rule, get_all_rule_ids

# Manifest export
from .core.manifest import ManifestExporter, MarkerParser, export_to_sarif, export_to_codeclimate, export_to_markdown
from .core.marker_cleanup import MarkerCleanup

# AI bug rules
from .rules.ai_bugs import AIBugRule
from .rules.duplication import CodeDuplicationRule
from .rules.naming import NamingInconsistencyRule

__version__ = "2.3.0"

__all__ = [
    # Core
    'RuleEngine', 'CodeFile', 'RuleConfig', 'TransformationResult',
    'RuleConflict', 'RuleRange', 'AgentMarker',
    # Security types
    'SecuritySeverity', 'SecurityFinding', 'DependencyFinding',
    'CWE_SEVERITY_MAP', 'OWASP_SEVERITY_MAP',
    # Rules — Default-on (safe)
    'SecurityScannerRule', 'CodeQualityRule', 'PerformanceRule',
    'TypingRule', 'RangeLenRule', 'IsNotNoneRule',
    # Rules — Conservative (use --enable-* flags)
    'UnusedImportRule', 'InitFileProtectionRule', 'FStringRule',
    'DataclassSuggestionRule', 'MagicNumberRule',
    # Rules — Destructive (use --enable-* flags, can break code)
    'ImportCleaningRule', 'NamingConventionRule', 'RefactoringRule',
    'DebugCleaner', 'CommentCleaner', 'RedundantExpressionRule',
    'DeadCodeRule', 'MatchCaseRule',
    # Security registry
    'SECURITY_RULES_REGISTRY', 'get_security_rule', 'get_all_rule_ids',
    # Manifest export
    'ManifestExporter', 'MarkerParser', 'export_to_sarif', 'export_to_codeclimate',
    'export_to_markdown', 'MarkerCleanup',
    # AI bug rules
    'AIBugRule', 'CodeDuplicationRule', 'NamingInconsistencyRule',
    # Convenience functions
    'clean_code', 'clean_file', 'analyze_code',
    # Fuzz testing tool
    'github_fuzz',
]

# Lazy import for the fuzz testing module (avoids import overhead for normal users)
def __getattr__(name: str):
    if name == 'github_fuzz':
        from pyneat.tools import github_fuzz
        return github_fuzz
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# --------------------------------------------------------------------------
# Convenience functions
# --------------------------------------------------------------------------

def clean_code(
    content: str,
    remove_debug: bool = False,
    fix_is_not_none: bool = True,
    fix_redundant: bool = False,
    convert_fstrings: bool = False,
    remove_dead_code: bool = False,
    remove_unused_imports: bool = False,
    enable_security: bool = False,
    check_conflicts: bool = False,
    path: Optional[Path] = None,
    # Aggressive rules — must be explicitly enabled
    enable_import_cleaning: bool = False,
    enable_naming: bool = False,
    enable_refactoring: bool = False,
    enable_comment_clean: bool = False,
) -> str:
    """Clean Python source code and return the transformed result.

    This is the simplest way to use PyNeat — just pass a code string.

    Args:
        content: The Python source code to clean.
        remove_debug: Remove debug print/log calls (default: False).
        fix_is_not_none: Fix `x != None` -> `x is not None` (default: True, safe).
        fix_redundant: Simplify redundant expressions (default: False).
        convert_fstrings: Convert .format() to f-strings (default: False).
        remove_dead_code: Remove unused functions/classes (default: False).
        remove_unused_imports: Remove genuinely unused imports (default: False).
        enable_security: Enable security scanning (default: False).
        check_conflicts: Detect overlapping rule modifications (default: False).
        path: Optional file path for error messages.
        enable_import_cleaning: Rewrite/reorder all imports (default: False, destructive).
        enable_naming: Rename classes to PascalCase (default: False, destructive).
        enable_refactoring: Refactor nested if, change except behavior (default: False, destructive).
        enable_comment_clean: Remove TODO/FIXME comments (default: False, destructive).

    Returns:
        The transformed code as a string.

    Example:
        from pyneat import clean_code
        result = clean_code("x != None")
        print(result)  # "x is not None"

        result = clean_code("print('debug')", remove_debug=True)
        print(result)  # ""
    """
    path = path or Path("<string>")

    # SAFE rules — always available, on by default for safe fixes
    rules: List[Any] = []
    if fix_is_not_none:
        rules.append(IsNotNoneRule(RuleConfig(enabled=True)))

    # CONSERVATIVE rules — opt-in
    if remove_debug:
        rules.append(DebugCleaner(mode="safe"))
    if fix_redundant:
        rules.append(RedundantExpressionRule(RuleConfig(enabled=True)))
    if convert_fstrings:
        rules.append(FStringRule(RuleConfig(enabled=True)))
    if remove_dead_code:
        rules.append(DeadCodeRule(RuleConfig(enabled=True)))
    if remove_unused_imports:
        rules.append(InitFileProtectionRule(RuleConfig(enabled=True)))
        rules.append(UnusedImportRule(RuleConfig(enabled=True)))
    if enable_security:
        rules.append(SecurityScannerRule(RuleConfig(enabled=True)))

    # DESTRUCTIVE rules — opt-in, must be explicitly enabled
    if enable_import_cleaning:
        rules.append(ImportCleaningRule(RuleConfig(enabled=True)))
    if enable_naming:
        rules.append(NamingConventionRule(RuleConfig(enabled=True)))
    if enable_refactoring:
        rules.append(RefactoringRule(RuleConfig(enabled=True)))
    if enable_comment_clean:
        rules.append(CommentCleaner(RuleConfig(enabled=True)))

    if not rules:
        return content

    engine = RuleEngine(rules)
    result = engine.process_code_file(
        CodeFile(path=path, content=content),
        check_conflicts=check_conflicts,
    )
    return result.transformed_content


def clean_file(
    path: Path,
    in_place: bool = False,
    backup: bool = False,
    remove_debug: bool = False,
    fix_is_not_none: bool = True,
    fix_redundant: bool = False,
    convert_fstrings: bool = False,
    remove_dead_code: bool = False,
    remove_unused_imports: bool = False,
    enable_security: bool = False,
    # Aggressive rules — must be explicitly enabled
    enable_import_cleaning: bool = False,
    enable_naming: bool = False,
    enable_refactoring: bool = False,
    enable_comment_clean: bool = False,
) -> TransformationResult:
    """Clean a Python file and return the result.

    Args:
        path: Path to the Python file to clean.
        in_place: Write changes back to the file (default: False).
        backup: Create a .bak backup before modifying (default: False).
        remove_debug: Remove debug print/log calls (default: False).
        fix_is_not_none: Fix `x != None` -> `x is not None` (default: True, safe).
        fix_redundant: Simplify redundant expressions (default: False).
        convert_fstrings: Convert .format() to f-strings (default: False).
        remove_dead_code: Remove unused functions/classes (default: False).
        remove_unused_imports: Remove genuinely unused imports (default: False).
        enable_security: Enable security scanning (default: False).
        enable_import_cleaning: Rewrite/reorder all imports (default: False, destructive).
        enable_naming: Rename classes to PascalCase (default: False, destructive).
        enable_refactoring: Refactor nested if, change except behavior (default: False, destructive).
        enable_comment_clean: Remove TODO/FIXME comments (default: False, destructive).

    Returns:
        TransformationResult with success status and details.

    Example:
        from pyneat import clean_file
        result = clean_file(Path("my_script.py"), in_place=True)
        if result.success:
            print(f"Made {len(result.changes_made)} changes")
    """
    import shutil

    # SAFE rules
    rules: List[Any] = []
    if fix_is_not_none:
        rules.append(IsNotNoneRule(RuleConfig(enabled=True)))

    # CONSERVATIVE rules
    if remove_debug:
        rules.append(DebugCleaner(mode="safe"))
    if fix_redundant:
        rules.append(RedundantExpressionRule(RuleConfig(enabled=True)))
    if convert_fstrings:
        rules.append(FStringRule(RuleConfig(enabled=True)))
    if remove_dead_code:
        rules.append(DeadCodeRule(RuleConfig(enabled=True)))
    if remove_unused_imports:
        rules.append(InitFileProtectionRule(RuleConfig(enabled=True)))
        rules.append(UnusedImportRule(RuleConfig(enabled=True)))
    if enable_security:
        rules.append(SecurityScannerRule(RuleConfig(enabled=True)))

    # DESTRUCTIVE rules — opt-in
    if enable_import_cleaning:
        rules.append(ImportCleaningRule(RuleConfig(enabled=True)))
    if enable_naming:
        rules.append(NamingConventionRule(RuleConfig(enabled=True)))
    if enable_refactoring:
        rules.append(RefactoringRule(RuleConfig(enabled=True)))
    if enable_comment_clean:
        rules.append(CommentCleaner(RuleConfig(enabled=True)))

    engine = RuleEngine(rules)
    result = engine.process_file(path)

    if in_place and result.success and result.original.content != result.transformed_content:
        if backup:
            backup_path = path.with_suffix(path.suffix + ".bak")
            shutil.copy2(path, backup_path)

        with open(path, 'w', encoding='utf-8') as f:
            f.write(result.transformed_content)

    return result


def analyze_code(
    content: str,
    path: Optional[Path] = None,
    check_conflicts: bool = False,
) -> Dict[str, Any]:
    """Analyze code without auto-fixing, returning a report of detected issues.

    Use this when you want to audit code quality without modifying it.

    Args:
        content: Python source code to analyze.
        path: Optional file path.
        check_conflicts: Include rule conflict detection (default: False).

    Returns:
        Dictionary with analysis results:
        {
            'success': bool,
            'issues': List[str],      # issues detected by rules
            'conflicts': List[str],   # rule conflicts (if check_conflicts=True)
            'change_count': int,
            'error': Optional[str],
        }

    Example:
        from pyneat import analyze_code
        report = analyze_code("x == None; print('debug')")
        for issue in report['issues']:
            print(f"  - {issue}")
    """
    path = path or Path("<string>")
    rules: List[Any] = [
        SecurityScannerRule(RuleConfig(enabled=True)),
        CodeQualityRule(RuleConfig(enabled=True)),
        PerformanceRule(RuleConfig(enabled=True)),
        TypingRule(RuleConfig(enabled=True)),
        RangeLenRule(RuleConfig(enabled=True)),
        IsNotNoneRule(RuleConfig(enabled=True)),
        RedundantExpressionRule(RuleConfig(enabled=True)),
    ]

    engine = RuleEngine(rules)
    result = engine.process_code_file(
        CodeFile(path=path, content=content),
        check_conflicts=check_conflicts,
    )

    conflicts = [
        c for c in result.changes_made
        if "CONFLICT" in c
    ]

    return {
        'success': result.success,
        'issues': result.changes_made,
        'conflicts': conflicts,
        'change_count': len(result.changes_made),
        'error': result.error,
    }
