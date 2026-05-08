"""Smoke test for MCP server."""
import subprocess
import json
import sys
import os
import time

os.chdir(os.path.join(os.path.dirname(__file__), "pyneat-rs"))

proc = subprocess.Popen(
    [sys.executable, '-m', 'pyneat.tools.mcp_server'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

msgs = [
    {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
     'params': {'protocolVersion': '2024-11-05', 'capabilities': {}}},
    {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}},
    {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
     'params': {'name': 'pyneat_list_rules', 'arguments': {}}},
]

for m in msgs:
    line = json.dumps(m) + '\n'
    proc.stdin.write(line.encode('utf-8'))
    proc.stdin.flush()

proc.stdin.close()

# Read output with timeout
stdout_chunks = []
start = time.time()
while time.time() - start < 10:
    chunk = proc.stdout.read(4096)
    if not chunk:
        break
    stdout_chunks.append(chunk)

proc.wait()
stdout_bytes = b''.join(stdout_chunks)
stderr_bytes = proc.stderr.read()

with open(os.path.join(os.path.dirname(__file__), "test_mcp_out.txt"), "wb") as f:
    f.write(stdout_bytes)
with open(os.path.join(os.path.dirname(__file__), "test_mcp_err.txt"), "wb") as f:
    f.write(stderr_bytes)

print("stdout written to test_mcp_out.txt")
print("stderr written to test_mcp_err.txt")
print(f"stdout size: {len(stdout_bytes)}, stderr size: {len(stderr_bytes)}")
