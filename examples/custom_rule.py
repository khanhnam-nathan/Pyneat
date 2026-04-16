#!/usr/bin/env python3
"""
PyNeat Custom Rule Example

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

This example demonstrates creating and using custom rules:
1. Define a custom rule class
2. Register the rule with the engine
3. Scan for custom patterns

Run: python examples/custom_rule.py
"""

import sys
import re
from pathlib import Path
from typing import List, Any, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyneat.core import RuleEngine, SecurityFinding
from pyneat.core.types import AgentMarker, MarkerIdGenerator


class CustomRule:
    """Base class for custom PyNeat rules."""

    RULE_ID = "CUSTOM-001"
    SEVERITY = "medium"
    LANGUAGES = ["python"]

    def detect(self, source_code: str, language: str = "python") -> List[Dict[str, Any]]:
        """Detect issues. Override in subclass."""
        return []


class TodoCommentRule(CustomRule):
    """
    Detects TODO comments that should be converted to issues.

    Pattern: # TODO: <description>
    Fix: Create actual issue tracking entries
    """

    RULE_ID = "CUSTOM-TODO"
    SEVERITY = "low"

    def detect(self, source_code: str, language: str = "python") -> List[Dict[str, Any]]:
        findings = []
        for i, line in enumerate(source_code.split("\n"), 1):
            if re.search(r"#\s*TODO:", line, re.IGNORECASE):
                findings.append({
                    "rule_id": self.RULE_ID,
                    "line": i,
                    "message": f"TODO comment found: {line.strip()}",
                    "code_snippet": line.strip(),
                    "severity": self.SEVERITY,
                })
        return findings


class PrintDebugRule(CustomRule):
    """
    Detects debug print statements that should be removed.

    Pattern: print(...)
    Fix: Remove print statements in production code
    """

    RULE_ID = "CUSTOM-DEBUG"
    SEVERITY = "medium"

    def detect(self, source_code: str, language: str = "python") -> List[Dict[str, Any]]:
        findings = []
        lines = source_code.split("\n")
        for i, line in enumerate(lines, 1):
            # Skip if already in a try-except for debugging
            if "try:" in source_code[:source_code.find(line)]:
                continue
            if re.search(r"\bprint\s*\(", line):
                # Check if it's a debug-style print
                findings.append({
                    "rule_id": self.RULE_ID,
                    "line": i,
                    "message": f"Debug print statement: {line.strip()}",
                    "code_snippet": line.strip(),
                    "severity": self.SEVERITY,
                    "auto_fix_hint": "Remove this print statement",
                })
        return findings


class HardcodedPathRule(CustomRule):
    """
    Detects hardcoded file paths that should be configurable.

    Pattern: "/home/", "C:\\Users\\", "/tmp/"
    Fix: Use environment variables or configuration
    """

    RULE_ID = "CUSTOM-HARDCODED-PATH"
    SEVERITY = "medium"

    def detect(self, source_code: str, language: str = "python") -> List[Dict[str, Any]]:
        findings = []
        # Common path patterns
        path_patterns = [
            r'["\']/[a-zA-Z]+/[a-zA-Z]+',  # Unix paths
            r'["\'][A-Z]:\\[^"\']+',  # Windows paths
            r'["\']/tmp/',  # Temp directory
        ]

        for i, line in enumerate(source_code.split("\n"), 1):
            for pattern in path_patterns:
                if re.search(pattern, line):
                    findings.append({
                        "rule_id": self.RULE_ID,
                        "line": i,
                        "message": f"Hardcoded path detected: {line.strip()}",
                        "code_snippet": line.strip(),
                        "severity": self.SEVERITY,
                        "auto_fix_hint": "Use os.path.expanduser() or environment variables",
                    })
                    break
        return findings


def run_custom_rule_example():
    """Run custom rule example."""
    sample_code = '''
import os

# TODO: Refactor this function
def process_file(filename):
    # Debug logging
    print(f"Processing {filename}")

    # Hardcoded paths
    config_path = "/etc/myapp/config.json"
    temp_path = "/tmp/output.txt"
    windows_path = "C:\\Users\\Admin\\data.txt"

    # More debug prints
    print("Step 1 complete")

    # TODO: Add error handling
    with open(filename, "r") as f:
        return f.read()

    print("Done")
'''

    print("=" * 60)
    print("PyNeat Custom Rule Example")
    print("=" * 60)

    # Initialize custom rules
    custom_rules = [
        TodoCommentRule(),
        PrintDebugRule(),
        HardcodedPathRule(),
    ]

    print("\n[1] Custom rules registered:")
    for rule in custom_rules:
        print(f"    - {rule.RULE_ID}: {rule.__doc__.split(chr(10))[0]}")

    # Scan with custom rules
    print("\n[2] Scanning with custom rules...")
    all_findings = []

    for rule in custom_rules:
        findings = rule.detect(sample_code)
        all_findings.extend(findings)
        print(f"    {rule.RULE_ID}: {len(findings)} issues")

    # Convert to AgentMarkers
    print("\n[3] Creating AgentMarkers...")
    generator = MarkerIdGenerator()
    markers = []

    for finding in all_findings:
        marker = AgentMarker(
            marker_id=generator.generate(finding["rule_id"], "custom"),
            issue_type=finding["rule_id"],
            rule_id=finding["rule_id"],
            severity=finding["severity"],
            line=finding["line"],
            snippet=finding["code_snippet"],
            hint=finding.get("auto_fix_hint"),
            language="python",
        )
        markers.append(marker)

    # Display results
    print(f"\n[4] Total issues found: {len(markers)}")
    print("\n[5] Issue details:")
    for marker in markers:
        print(f"    [{marker.marker_id}] {marker.issue_type}")
        print(f"        Severity: {marker.severity}")
        print(f"        Line: {marker.line}")
        print(f"        Code: {marker.snippet}")
        if marker.hint:
            print(f"        Fix: {marker.hint}")
        print()

    # Auto-fixable count
    auto_fixable = [m for m in markers if m.can_auto_fix]
    print(f"[6] Auto-fixable issues: {len(auto_fixable)}/{len(markers)}")

    print("\n" + "=" * 60)
    print("Custom rule example completed!")
    print("=" * 60)

    return markers


if __name__ == "__main__":
    run_custom_rule_example()
