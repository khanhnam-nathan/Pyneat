"""Medium severity security rules (SEC-020 to SEC-034).

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

Medium severity issues may lead to security breaches under specific conditions
or in combination with other vulnerabilities.
"""

from pyneat.core.types import SecuritySeverity

__all__ = ["MEDIUM_RULES"]

MEDIUM_RULES = [
    {"rule_id": "SEC-020", "name": "LDAP Injection", "severity": SecuritySeverity.MEDIUM, "description": "LDAP query built by string concatenation"},
    {"rule_id": "SEC-021", "name": "Cross-Site Scripting (XSS)", "severity": SecuritySeverity.MEDIUM, "description": "User input in template rendering without sanitization"},
    {"rule_id": "SEC-022", "name": "Server-Side Request Forgery (SSRF)", "severity": SecuritySeverity.MEDIUM, "description": "URL fetching with user-controlled URLs"},
    {"rule_id": "SEC-023", "name": "Open Redirect", "severity": SecuritySeverity.MEDIUM, "description": "URL redirects based on user-controlled parameters"},
    {"rule_id": "SEC-024", "name": "Mass Assignment", "severity": SecuritySeverity.MEDIUM, "description": "Direct assignment of request data to model objects"},
    {"rule_id": "SEC-025", "name": "Race Condition (TOCTOU)", "severity": SecuritySeverity.MEDIUM, "description": "Time-of-check-time-of-use race conditions in file operations"},
    {"rule_id": "SEC-026", "name": "Insecure Temporary Files", "severity": SecuritySeverity.MEDIUM, "description": "Use of insecure temporary file creation patterns"},
    {"rule_id": "SEC-027", "name": "Predictable Random", "severity": SecuritySeverity.MEDIUM, "description": "Mersenne Twister random for non-security-sensitive operations"},
    {"rule_id": "SEC-028", "name": "Password in URL", "severity": SecuritySeverity.MEDIUM, "description": "Credentials passed in URL query strings"},
    {"rule_id": "SEC-029", "name": "Missing Rate Limiting", "severity": SecuritySeverity.MEDIUM, "description": "API endpoints without rate limiting"},
    {"rule_id": "SEC-030", "name": "Insufficient Session Timeout", "severity": SecuritySeverity.MEDIUM, "description": "Sessions with excessive or missing timeout"},
    {"rule_id": "SEC-031", "name": "Trust Boundary Violation", "severity": SecuritySeverity.MEDIUM, "description": "Mixing trusted and untrusted data without proper separation"},
    {"rule_id": "SEC-032", "name": "Cookie Missing Security Flags", "severity": SecuritySeverity.MEDIUM, "description": "Cookies without HttpOnly, Secure, or SameSite flags"},
    {"rule_id": "SEC-033", "name": "Missing Content Security Policy", "severity": SecuritySeverity.LOW, "description": "Web apps missing Content-Security-Policy headers"},
    {"rule_id": "SEC-034", "name": "XML External Entity Partial", "severity": SecuritySeverity.MEDIUM, "description": "XML parsing configurations that partially allow DTD processing"},
]
