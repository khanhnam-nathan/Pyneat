"""Test using the CLI directly to reproduce error."""
import subprocess
import sys
import tempfile
import os

# Create test file
content = """# SQL Injection vulnerability
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# Hardcoded secret
api_key = "sk_live_abc123xyz789secret"

# Magic number
timeout = 300

# Empty except
try:
    risky_operation()
except:
    pass
"""

with open('test_sample.py', 'w', encoding='utf-8') as f:
    f.write(content)

# Run pyneat clean (the installed package, not the local src)
result = subprocess.run(
    [sys.executable, '-m', 'pyneat', 'clean', 'test_sample.py'],
    capture_output=True,
    text=True
)
print('STDOUT:', result.stdout)
print('STDERR:', result.stderr)
print('Return code:', result.returncode)
