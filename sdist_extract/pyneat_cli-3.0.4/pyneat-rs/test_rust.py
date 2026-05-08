"""Quick test of the Rust security scanner."""

import pyneat_rs
import json

code = '''
import os
def run(cmd):
    os.system(cmd)

cursor.execute('SELECT * FROM users WHERE id=' + user_id)
'''

result = pyneat_rs.scan_security(code)
findings = json.loads(result)
print(f"Found {len(findings)} issues:")
for f in findings:
    print(f"  [{f['rule_id']}] {f['problem'][:60]}...")
