"""Security Pack - Organized security rules by severity level.

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

This module organizes the 50+ security rules into severity-based submodules:
- critical: Critical severity rules (SEC-001 to SEC-005)
- high: High severity rules (SEC-010 to SEC-019)
- medium: Medium severity rules (SEC-020 to SEC-034)
- low: Low severity rules (SEC-040 to SEC-049)
- info: Informational rules (SEC-050 to SEC-059)
- ruby: Ruby-specific security rules (RUBY-SEC-001 to RUBY-SEC-034)
- php: PHP-specific security rules (PHP2-SEC-001 to PHP2-SEC-038)
- go: Go-specific security rules (GO-SEC-001 to GO-SEC-048, gosec G-series)

Usage:
    from pyneat.rules.security_pack import (
        get_all_security_rules,
        get_rules_by_severity,
        RUBY_SECURITY_RULES,
        PHP_SECURITY_RULES,
    )
"""

from pyneat.rules.security_pack.critical import CRITICAL_RULES
from pyneat.rules.security_pack.high import HIGH_RULES
from pyneat.rules.security_pack.medium import MEDIUM_RULES
from pyneat.rules.security_pack.low import LOW_RULES
from pyneat.rules.security_pack.info import INFO_RULES
from pyneat.rules.security_pack.ruby import RUBY_SECURITY_RULES, RUBY_CRITICAL_RULES, RUBY_HIGH_RULES, RUBY_MEDIUM_RULES, RUBY_LOW_RULES
from pyneat.rules.security_pack.php import PHP_SECURITY_RULES, PHP_CRITICAL_RULES, PHP_HIGH_RULES, PHP_MEDIUM_RULES, PHP_LOW_RULES

# --------------------------------------------------------------------------
# Combined export
# --------------------------------------------------------------------------

__all__ = [
    "CRITICAL_RULES",
    "HIGH_RULES",
    "MEDIUM_RULES",
    "LOW_RULES",
    "INFO_RULES",
    "RUBY_SECURITY_RULES",
    "RUBY_CRITICAL_RULES",
    "RUBY_HIGH_RULES",
    "RUBY_MEDIUM_RULES",
    "RUBY_LOW_RULES",
    "PHP_SECURITY_RULES",
    "PHP_CRITICAL_RULES",
    "PHP_HIGH_RULES",
    "PHP_MEDIUM_RULES",
    "PHP_LOW_RULES",
    "get_all_security_rules",
    "get_rules_by_severity",
]


def get_all_security_rules() -> list:
    """Return all security rules from all severity levels (Python + Ruby + PHP)."""
    return (
        CRITICAL_RULES
        + HIGH_RULES
        + MEDIUM_RULES
        + LOW_RULES
        + INFO_RULES
        + RUBY_SECURITY_RULES
        + PHP_SECURITY_RULES
    )


def get_rules_by_severity(severity: str) -> list:
    """Return rules for a specific severity level."""
    from pyneat.core.types import SecuritySeverity

    mapping = {
        SecuritySeverity.CRITICAL: CRITICAL_RULES,
        SecuritySeverity.HIGH: HIGH_RULES,
        SecuritySeverity.MEDIUM: MEDIUM_RULES,
        SecuritySeverity.LOW: LOW_RULES,
        SecuritySeverity.INFO: INFO_RULES,
    }
    return mapping.get(severity, [])
