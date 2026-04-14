#!/usr/bin/env python3
"""
PyNeat Basic Usage Example

This example demonstrates the fundamental PyNeat workflow:
1. Scan a file for issues
2. Apply auto-fixes
3. Generate a report

Run: python examples/basic_usage.py
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyneat.core import RuleEngine
from pyneat.core.types import AgentMarker, MarkerIdGenerator
from pyneat.rules import ALL_RULES


def run_basic_example():
    """Run basic PyNeat scanning and fixing example."""
    sample_code = '''
import utils
import helpers
import ai

def process_data(data):
    param1 = data.get("key")
    if param1 != None:
        return param1

    file = open("data.txt")
    content = file.read()
    return content

def calculate(x, y):
    if x is 200:
        return x + y
    return x - y
'''

    print("=" * 60)
    print("PyNeat Basic Usage Example")
    print("=" * 60)

    # Initialize rule engine
    engine = RuleEngine(rules=ALL_RULES)

    # Scan the code
    print("\n[1] Scanning code for issues...")
    findings = engine.scan_code(sample_code, language="python")
    print(f"    Found {len(findings)} issues")

    for finding in findings:
        print(f"    - {finding.rule_id}: {finding.message} (line {finding.line})")

    # Convert to AgentMarkers
    print("\n[2] Converting findings to AgentMarkers...")
    generator = MarkerIdGenerator()
    markers = []
    for finding in findings:
        marker = AgentMarker(
            marker_id=generator.generate(finding.rule_id, "quality"),
            issue_type=finding.rule_id,
            rule_id=finding.rule_id,
            severity="medium",
            line=finding.line,
            snippet=finding.code_snippet,
        )
        markers.append(marker)

    print(f"    Created {len(markers)} AgentMarkers")

    # Show marker details
    print("\n[3] Marker details:")
    for marker in markers:
        print(f"    [{marker.marker_id}] {marker.issue_type}")
        print(f"        Severity: {marker.severity}")
        print(f"        Location: line {marker.line}")
        if marker.snippet:
            snippet = marker.snippet[:50] + "..." if len(marker.snippet) > 50 else marker.snippet
            print(f"        Snippet: {snippet}")

    # Apply fixes (dry-run)
    print("\n[4] Applying fixes (dry-run mode)...")
    for marker in markers:
        if marker.can_auto_fix:
            print(f"    Would fix: {marker.marker_id}")
        else:
            print(f"    Cannot auto-fix: {marker.marker_id}")

    # Generate summary
    print("\n[5] Summary:")
    print(f"    Total markers: {len(markers)}")
    severities = {}
    for m in markers:
        severities[m.severity] = severities.get(m.severity, 0) + 1
    for sev, count in sorted(severities.items()):
        print(f"    - {sev}: {count}")

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)

    return markers


if __name__ == "__main__":
    run_basic_example()
