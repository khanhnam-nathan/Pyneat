#!/usr/bin/env python3
with open('pyneat/config_loader.py', 'rb') as f:
    content = f.read()

lines = content.split(b'\n')

# Show lines 34-40
print('Lines 34-40:')
for i in range(33, 40):
    print('  {0}: {1}'.format(i+1, repr(lines[i])))

# Show lines 80-90
print('\nLines 80-90:')
for i in range(79, 90):
    print('  {0}: {1}'.format(i+1, repr(lines[i])))

# Show lines 280-292
print('\nLines 280-292:')
for i in range(279, 292):
    print('  {0}: {1}'.format(i+1, repr(lines[i])))
