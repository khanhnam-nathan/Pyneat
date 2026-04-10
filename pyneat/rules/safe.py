"""Safe rules — always available, on by default.

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

These rules are conservative and unlikely to break code.
"""

from pyneat.rules.is_not_none import IsNotNoneRule
from pyneat.rules.range_len_pattern import RangeLenRule
from pyneat.rules.security import SecurityScannerRule
from pyneat.rules.typing import TypingRule
from pyneat.rules.quality import CodeQualityRule
from pyneat.rules.performance import PerformanceRule

__all__ = [
    'IsNotNoneRule',
    'RangeLenRule',
    'SecurityScannerRule',
    'TypingRule',
    'CodeQualityRule',
    'PerformanceRule',
]
