#!/usr/bin/env python3
"""Use tokenize to see exactly what Python sees."""
import tokenize
import io

with open('pyneat/config_loader.py', 'rb') as f:
    content = f.read()

tokens = list(tokenize.tokenize(io.BytesIO(content).readline))

for tok in tokens:
    print(tok)
