#!/usr/bin/env python3
"""
PyNeat Security Scanning Example

This example demonstrates security scanning with SARIF export:
1. Scan for security vulnerabilities
2. Export results to SARIF format
3. Integrate with CI/CD pipelines

Run: python examples/security_scan.py
"""

import sys
import json
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyneat.core import RuleEngine
from pyneat.core.types import AgentMarker, MarkerIdGenerator
from pyneat.core.manifest import export_to_sarif, export_to_junit_xml
from pyneat.rules.security import SecurityScannerRule
from pyneat.rules.quality import CodeQualityRule


def run_security_example():
    """Run security scanning example with multiple export formats."""
    vulnerable_code = '''
import pickle
import os
import hashlib

def load_user_data(user_input):
    # Security issue: pickle with user input
    data = pickle.loads(user_input)
    return data

def execute_command(cmd):
    # Security issue: command injection
    os.system(cmd)
    return "Done"

def hash_password(password):
    # Security issue: weak hashing
    return hashlib.md5(password.encode())

def verify_token(token):
    # Security issue: timing attack vulnerability
    secret = "secret123"
    return token == secret

def load_yaml_config(unsafe_data):
    # Security issue: yaml.load without SafeLoader
    import yaml
    config = yaml.load(unsafe_data)
    return config

def connect_database():
    # Security issue: hardcoded credentials
    conn = connect("root", "password123", "localhost")
    return conn
'''

    print("=" * 60)
    print("PyNeat Security Scanning Example")
    print("=" * 60)

    # Initialize security-focused rule engine
    security_rules = [SecurityScannerRule(), CodeQualityRule()]
    engine = RuleEngine(rules=security_rules)

    # Scan for vulnerabilities
    print("\n[1] Scanning for security vulnerabilities...")
    findings = engine.scan_code(vulnerable_code, language="python")
    print(f"    Found {len(findings)} potential issues")

    # Convert to AgentMarkers with full metadata
    print("\n[2] Creating AgentMarkers with security metadata...")
    generator = MarkerIdGenerator()
    markers = []

    for finding in findings:
        marker = AgentMarker(
            marker_id=generator.generate(finding.rule_id, "security"),
            issue_type=finding.rule_id,
            rule_id=finding.rule_id,
            severity="high",
            line=finding.line,
            why=finding.message,
            impact="Potential security vulnerability if exploited",
            confidence=0.9,
            cwe_id=finding.cwe_id,
            detected_at=datetime.now().isoformat(),
            language="python",
        )
        markers.append(marker)

    # Print findings
    print("\n[3] Security findings:")
    for marker in markers:
        cwe = marker.cwe_id or "N/A"
        print(f"    [{marker.marker_id}] {marker.issue_type}")
        print(f"        CWE: {cwe}")
        print(f"        Severity: {marker.severity}")
        print(f"        Line: {marker.line}")
        if marker.why:
            print(f"        Why: {marker.why}")

    # Export to SARIF
    print("\n[4] Exporting to SARIF format...")
    sarif_output = export_to_sarif(markers, "examples/security_scan.py")
    sarif_file = Path("security_report.sarif")
    sarif_file.write_text(json.dumps(sarif_output, indent=2))
    print(f"    Saved to: {sarif_file}")

    # Export to JUnit XML
    print("\n[5] Exporting to JUnit XML format...")
    junit_output = export_to_junit_xml(markers, source_file=Path("examples/security_scan.py"))
    junit_file = Path("security_report.xml")
    junit_file.write_text(junit_output)
    print(f"    Saved to: {junit_file}")

    # Summary statistics
    print("\n[6] Security Summary:")
    critical = len([m for m in markers if m.severity == "critical"])
    high = len([m for m in markers if m.severity == "high"])
    medium = len([m for m in markers if m.severity == "medium"])
    low = len([m for m in markers if m.severity == "low"])

    print(f"    Critical: {critical}")
    print(f"    High: {high}")
    print(f"    Medium: {medium}")
    print(f"    Low: {low}")

    if critical > 0:
        print("\n    WARNING: Critical vulnerabilities found!")
        print("    Please address these before deploying.")

    print("\n" + "=" * 60)
    print("Security scan completed successfully!")
    print("=" * 60)

    return markers


if __name__ == "__main__":
    run_security_example()
