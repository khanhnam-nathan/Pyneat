"""Destructive rules — opt-in, may break code.

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

These rules can modify or remove code in ways that may break imports
or change program behavior. Always review changes when using these rules.
Enable with --enable-import-cleaning, --enable-naming, --enable-refactoring, etc.
"""

from pyneat.rules.imports import ImportCleaningRule
from pyneat.rules.naming import NamingConventionRule
from pyneat.rules.refactoring import RefactoringRule
from pyneat.rules.debug import DebugCleaner
from pyneat.rules.comments import CommentCleaner
from pyneat.rules.redundant import RedundantExpressionRule
from pyneat.rules.deadcode import DeadCodeRule
from pyneat.rules.match_case import MatchCaseRule

__all__ = [
    'ImportCleaningRule',
    'NamingConventionRule',
    'RefactoringRule',
    'DebugCleaner',
    'CommentCleaner',
    'RedundantExpressionRule',
    'DeadCodeRule',
    'MatchCaseRule',
]
