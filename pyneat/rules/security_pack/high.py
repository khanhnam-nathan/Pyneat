"""High severity security rules (SEC-010 to SEC-019).

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

High severity issues can lead to data breaches, credential theft, or significant
security misconfigurations.
"""

from pyneat.core.types import SecuritySeverity

__all__ = ["HIGH_RULES"]

HIGH_RULES = [
    {"rule_id": "SEC-010", "name": "Hardcoded Secrets", "severity": SecuritySeverity.HIGH, "description": "Hardcoded API keys, passwords, tokens in source code"},
    {"rule_id": "SEC-011", "name": "Weak Cryptography", "severity": SecuritySeverity.HIGH, "description": "MD5/SHA1 for security, weak encryption algorithms"},
    {"rule_id": "SEC-012", "name": "Insecure SSL/TLS", "severity": SecuritySeverity.HIGH, "description": "ssl._create_unverified_context disables cert verification"},
    {"rule_id": "SEC-013", "name": "XML External Entity (XXE)", "severity": SecuritySeverity.HIGH, "description": "XML parsing without safe settings allows XXE"},
    {"rule_id": "SEC-014", "name": "YAML Unsafe Load", "severity": SecuritySeverity.HIGH, "description": "yaml.load without SafeLoader - auto-fixable"},
    {"rule_id": "SEC-015", "name": "Assert in Production", "severity": SecuritySeverity.HIGH, "description": "assert statements may be disabled in production"},
    {"rule_id": "SEC-016", "name": "Debug Mode Enabled", "severity": SecuritySeverity.HIGH, "description": "DEBUG=True exposes internal details in production"},
    {"rule_id": "SEC-017", "name": "CORS Wildcard", "severity": SecuritySeverity.HIGH, "description": "CORS allowing all origins exposes APIs"},
    {"rule_id": "SEC-018", "name": "JWT None Algorithm", "severity": SecuritySeverity.HIGH, "description": "JWT verification with 'none' algorithm bypasses signature"},
    {"rule_id": "SEC-019", "name": "Weak Random Number Generator", "severity": SecuritySeverity.HIGH, "description": "random module for security-sensitive operations"},
]
