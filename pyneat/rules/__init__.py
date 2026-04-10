"""Rule groupings and exports.

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
"""

from pyneat.rules.base import Rule
from pyneat.rules.imports import ImportCleaningRule
from pyneat.rules.naming import NamingConventionRule
from pyneat.rules.refactoring import RefactoringRule
from pyneat.rules.security import SecurityScannerRule
from pyneat.rules.security_registry import SECURITY_RULES_REGISTRY, get_security_rule, get_all_rule_ids
from pyneat.rules.quality import CodeQualityRule
from pyneat.rules.performance import PerformanceRule
from pyneat.rules.isolated import IsolatedBlockCleaner
from pyneat.rules.debug import DebugCleaner
from pyneat.rules.comments import CommentCleaner
from pyneat.rules.unused import UnusedImportRule
from pyneat.rules.redundant import RedundantExpressionRule
from pyneat.rules.deadcode import DeadCodeRule
from pyneat.rules.is_not_none import IsNotNoneRule
from pyneat.rules.magic_numbers import MagicNumberRule
from pyneat.rules.range_len_pattern import RangeLenRule
from pyneat.rules.typing import TypingRule
from pyneat.rules.match_case import MatchCaseRule
from pyneat.rules.dataclass import DataclassSuggestionRule, DataclassAdderRule
from pyneat.rules.init_protection import InitFileProtectionRule
from pyneat.rules.fstring import FStringRule, StringConcatRule
from pyneat.rules.ai_bugs import AIBugRule
from pyneat.rules.duplication import CodeDuplicationRule
from pyneat.rules.naming import NamingInconsistencyRule

# Rule groupings for easier discovery
from pyneat.rules import safe
from pyneat.rules import conservative
from pyneat.rules import destructive

# Security pack - organized by severity
from pyneat.rules import security_pack

# Core types for security scanning
from pyneat.core.types import (
    SecuritySeverity,
    SecurityFinding,
    DependencyFinding,
    IgnoreEntry,
    CWE_SEVERITY_MAP,
    OWASP_SEVERITY_MAP,
)
