"""Informational security rules (SEC-050 to SEC-059).

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

These rules cover deprecated APIs, missing access controls, and business logic
patterns that may indicate vulnerabilities.
"""

from pyneat.core.types import SecuritySeverity

__all__ = ["INFO_RULES"]

INFO_RULES = [
    {"rule_id": "SEC-050", "name": "Deprecated Security Function", "severity": SecuritySeverity.INFO, "description": "Use of deprecated security-related Python functions"},
    {"rule_id": "SEC-051", "name": "Missing Function-Level Access Control", "severity": SecuritySeverity.INFO, "description": "Sensitive functions without explicit authorization checks"},
    {"rule_id": "SEC-052", "name": "Improper Error Handling", "severity": SecuritySeverity.INFO, "description": "Error handling that may leak information or cause unexpected behavior"},
    {"rule_id": "SEC-053", "name": "Integer Overflow", "severity": SecuritySeverity.INFO, "description": "Potential integer overflow conditions in numeric operations"},
    {"rule_id": "SEC-054", "name": "TOCTOU Race Condition", "severity": SecuritySeverity.INFO, "description": "Time-of-check-time-of-use patterns that could be exploited"},
    {"rule_id": "SEC-055", "name": "Improper Certificate Validation", "severity": SecuritySeverity.INFO, "description": "Incomplete SSL/TLS certificate validation"},
    {"rule_id": "SEC-056", "name": "Missing Encryption for Sensitive Data", "severity": SecuritySeverity.INFO, "description": "Storage or transmission of sensitive data without encryption"},
    {"rule_id": "SEC-057", "name": "Improper Restriction of Rendered UI Layer", "severity": SecuritySeverity.INFO, "description": "UI rendering that may allow clickjacking or UI redress attacks"},
    {"rule_id": "SEC-058", "name": "Server-Side Request Forgery (Cloud)", "severity": SecuritySeverity.MEDIUM, "description": "SSRF targeting cloud metadata services (169.254.169.254)"},
    {"rule_id": "SEC-059", "name": "Business Logic Vulnerability", "severity": SecuritySeverity.INFO, "description": "Patterns indicating business logic flaws (price manipulation, etc.)"},
]
