"""Low severity security rules (SEC-040 to SEC-049).

Copyright (c) 2024-2026 PyNEAT Authors

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

Low severity issues are informational and may leak sensitive information or violate
best practices but are unlikely to cause direct harm.
"""

from pyneat.core.types import SecuritySeverity

__all__ = ["LOW_RULES"]

LOW_RULES = [
    {"rule_id": "SEC-040", "name": "Sensitive Information in Comments", "severity": SecuritySeverity.LOW, "description": "TODO/HACK/FIXME comments containing sensitive patterns"},
    {"rule_id": "SEC-041", "name": "Information Disclosure in Errors", "severity": SecuritySeverity.LOW, "description": "Error handlers exposing stack traces or sensitive details"},
    {"rule_id": "SEC-042", "name": "Sensitive Data in Logs", "severity": SecuritySeverity.LOW, "description": "Logging of sensitive data (passwords, tokens, PII)"},
    {"rule_id": "SEC-043", "name": "Missing Security Headers", "severity": SecuritySeverity.LOW, "description": "Missing recommended security headers (X-Frame-Options, CSP, etc.)"},
    {"rule_id": "SEC-044", "name": "EXIF Data in Uploads", "severity": SecuritySeverity.LOW, "description": "Image uploads preserving EXIF metadata with sensitive info"},
    {"rule_id": "SEC-045", "name": "Missing Referrer Policy", "severity": SecuritySeverity.LOW, "description": "Missing Referrer-Policy header"},
    {"rule_id": "SEC-046", "name": "Security Feature Disabled", "severity": SecuritySeverity.MEDIUM, "description": "Explicit disabling of security features"},
    {"rule_id": "SEC-047", "name": "Insufficient Anti-Automation", "severity": SecuritySeverity.LOW, "description": "Missing CAPTCHA or bot detection on public forms"},
    {"rule_id": "SEC-048", "name": "Privacy Violation - PII in Logs", "severity": SecuritySeverity.LOW, "description": "Logging or storage of PII without consent"},
    {"rule_id": "SEC-049", "name": "Weak Password Policy", "severity": SecuritySeverity.LOW, "description": "Password validation allowing weak passwords"},
]
