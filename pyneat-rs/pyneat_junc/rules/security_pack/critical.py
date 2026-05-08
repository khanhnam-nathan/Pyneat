"""Critical severity security rules (SEC-001 to SEC-005).

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

Critical issues require immediate attention - they typically allow remote code
execution, data breach, or complete system compromise.
"""

from pyneat.core.types import SecuritySeverity

__all__ = ["CRITICAL_RULES"]

CRITICAL_RULES = [
    {
        "rule_id": "SEC-001",
        "name": "Command Injection",
        "severity": SecuritySeverity.CRITICAL,
        "description": "OS Command Injection via os.system, subprocess shell=True, os.popen",
    },
    {
        "rule_id": "SEC-002",
        "name": "SQL Injection",
        "severity": SecuritySeverity.CRITICAL,
        "description": "SQL Injection via string concatenation in queries",
    },
    {
        "rule_id": "SEC-003",
        "name": "Eval/Exec Usage",
        "severity": SecuritySeverity.CRITICAL,
        "description": "Dangerous eval/exec with dynamic code execution",
    },
    {
        "rule_id": "SEC-004",
        "name": "Deserialization RCE",
        "severity": SecuritySeverity.CRITICAL,
        "description": "pickle.loads/yaml.unsafe_load leading to RCE",
    },
    {
        "rule_id": "SEC-005",
        "name": "Path Traversal",
        "severity": SecuritySeverity.CRITICAL,
        "description": "Unsafitized file path operations allowing directory traversal",
    },
]
