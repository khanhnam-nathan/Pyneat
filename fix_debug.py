"""Fix debug.py: add breakpoint() to set_trace detection."""
content = open(r'd:\pyneat-final\pyneat-rs\pyneat\rules\debug.py', 'r', encoding='utf-8').read()
old = "'pdb.set_trace', 'ipdb.set_trace', 'pudb.set_trace', 'set_trace'"
new = "'pdb.set_trace', 'ipdb.set_trace', 'pudb.set_trace', 'set_trace', 'breakpoint'"
count = content.count(old)
if count > 0:
    content = content.replace(old, new)
    open(r'd:\pyneat-final\pyneat-rs\pyneat\rules\debug.py', 'w', encoding='utf-8').write(content)
    print(f"Replaced {count} occurrences")
else:
    print("Pattern not found")
