"""Test the Rust security scanner.

Run this to verify the scanner works correctly.
"""

from pathlib import Path
import sys

# Import from site-packages (Rust extension), not local pyneat_rs
local_path = str(Path(__file__).parent.parent / "pyneat_rs")
if local_path in sys.path:
    sys.path.remove(local_path)

from pyneat_rs import scan, SecurityScanner


# Test cases
TEST_CASES = [
    {
        "name": "Command Injection - os.system",
        "code": '''
import os
import subprocess

def run_command(cmd):
    # Vulnerable: user input to shell
    os.system(cmd)
''',
        "expected": ["SEC-001"],
    },
    {
        "name": "Command Injection - subprocess shell=True",
        "code": '''
import subprocess

def run(cmd):
    subprocess.run(cmd, shell=True)
''',
        "expected": ["SEC-001"],
    },
    {
        "name": "SQL Injection",
        "code": '''
cursor.execute("SELECT * FROM users WHERE id=" + user_id)
''',
        "expected": ["SEC-002"],
    },
    {
        "name": "Eval Usage",
        "code": '''
result = eval(user_input)
''',
        "expected": ["SEC-003"],
    },
    {
        "name": "Exec Usage",
        "code": '''
exec("print('hello')")
''',
        "expected": ["SEC-003"],
    },
    {
        "name": "Pickle RCE",
        "code": '''
import pickle

data = pickle.loads(user_data)
''',
        "expected": ["SEC-004"],
    },
    {
        "name": "YAML Unsafe Load",
        "code": '''
import yaml

config = yaml.load(user_yaml)
''',
        "expected": ["SEC-004"],
    },
    {
        "name": "Path Traversal",
        "code": '''
filename = request.args.get("filename")
with open(filename) as f:
    content = f.read()
''',
        "expected": ["SEC-005"],
    },
    {
        "name": "Multiple Issues",
        "code": '''
import os
import pickle
import eval

os.system(cmd)
pickle.loads(data)
''',
        "expected": ["SEC-001", "SEC-004", "SEC-003"],
    },
    {
        "name": "No Issues",
        "code": '''
def safe_function():
    return "hello"

def another_safe():
    with open("config.json") as f:
        return json.load(f)
''',
        "expected": [],
    },
    {
        "name": "Safe YAML (with Loader)",
        "code": '''
import yaml

config = yaml.load(user_yaml, Loader=yaml.SafeLoader)
''',
        "expected": [],
    },
]


def test_scanner():
    """Run all test cases."""
    scanner = SecurityScanner()

    passed = 0
    failed = 0
    errors = []

    print("Testing Security Scanner")
    print("=" * 60)

    for i, tc in enumerate(TEST_CASES, 1):
        code = tc["code"]
        expected = set(tc["expected"])

        findings = scanner.scan(code)
        found = set(f.rule_id for f in findings)

        if found == expected:
            print(f"[PASS] {i}. {tc['name']}")
            passed += 1
        else:
            print(f"[FAIL] {i}. {tc['name']}")
            print(f"       Expected: {expected}")
            print(f"       Found:    {found}")
            if found - expected:
                print(f"       Extra:    {found - expected}")
            if expected - found:
                print(f"       Missing:  {expected - found}")
            failed += 1
            errors.append(tc["name"])

    print("=" * 60)
    print(f"\nResults: {passed} passed, {failed} failed")

    if failed > 0:
        print(f"Failed tests: {', '.join(errors)}")
        return False

    return True


def test_file_scanning():
    """Test scanning real files."""
    print("\n\nTesting File Scanning")
    print("=" * 60)

    scanner = SecurityScanner()

    # Scan the security.py file itself
    security_file = Path(__file__).parent.parent / "pyneat" / "rules" / "security.py"
    if security_file.exists():
        findings = scanner.scan_file(str(security_file))
        print(f"\nScanned: {security_file}")
        print(f"Findings: {len(findings)}")

        # Group by rule
        by_rule = {}
        for f in findings:
            by_rule.setdefault(f.rule_id, []).append(f)

        for rule_id, rule_findings in sorted(by_rule.items()):
            print(f"  {rule_id}: {len(rule_findings)} occurrences")

        # Show first few findings
        if findings:
            print("\nSample findings:")
            for f in findings[:3]:
                print(f"  [{f.rule_id}] {f.snippet[:50]}...")
    else:
        print(f"File not found: {security_file}")


def main():
    success = test_scanner()
    test_file_scanning()

    print("\n" + "=" * 60)
    if success:
        print("All tests passed!")
    else:
        print("Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
