"""Find all set_trace lines in debug.py"""
content = open(r'd:\pyneat-final\pyneat-rs\pyneat\rules\debug.py', 'r', encoding='utf-8').read()
lines = content.split('\n')
for i, line in enumerate(lines):
    if "'set_trace'" in line:
        print(f'Line {i+1}: {repr(line)}')
