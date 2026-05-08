#!/usr/bin/env python3
"""Sample Python file with various AI-generated code issues."""

import os
import sys
import json
import pickle
import hashlib
import subprocess
from typing import List, Dict, Optional

# Phantom imports - common AI hallucinations
import utils
import helpers
import ai
from ai import chatbot, assistant
from typing import Dict, List

# Security issues
def load_config(filename):
    """Load configuration - VULNERABLE to path traversal."""
    with open(filename) as f:
        return json.load(f)

def execute_command(cmd):
    """Execute shell command - DANGEROUS."""
    return os.system(cmd)

def unsafe_eval(code):
    """Evaluate arbitrary code - CRITICAL SECURITY ISSUE."""
    return eval(code)

def insecure_hash(password):
    """Hash password with MD5 - WEAK algorithm."""
    return hashlib.md5(password.encode()).hexdigest()

def deserialize_data(data):
    """Deserialize untrusted data - RCE risk."""
    return pickle.loads(data)

# AI bugs - identity comparison (INTENTIONAL BAD PATTERNS for testing)
def check_status(status):
    """Check if status is success - BAD: should use == not 'is'.

    This is an INTENTIONALLY BAD pattern to test AI bug detection.
    The 'is' operator checks identity, not equality. For literals,
    Python may cache small integers and strings, making 'is' appear
    to work, but it's unreliable and triggers SyntaxWarning.
    """
    # noqa: intentionally use 'is' with string literal to test detection
    if status is "success":  # BAD: should be ==
        return True
    return False

def compare_value(x):
    """Compare with integer - BAD: should use == not 'is'.

    This is an INTENTIONALLY BAD pattern to test AI bug detection.
    Using 'is' with integer literals is unreliable and triggers SyntaxWarning.
    """
    # noqa: intentionally use 'is' with integer literal to test detection
    if x is 200:  # BAD: should be ==
        return "ok"
    return "error"

# Resource leaks
def read_file_bad(filename):
    """Read file without context manager - RESOURCE LEAK."""
    f = open(filename, 'r')
    return f.read()

def connect_bad(url):
    """Connect without proper cleanup - RESOURCE LEAK."""
    conn = open(url, 'r')  # wrong usage
    return conn

# Unused imports
import math  # used?
import datetime  # unused
from collections import defaultdict, OrderedDict  # partially unused

def use_collections():
    """Use some imports."""
    d = defaultdict(int)
    return d

# Magic numbers
def calculate_price(quantity, unit_price):
    """Calculate total price."""
    tax_rate = 1.1  # Should be named constant
    discount = 0.05  # 5% discount
    subtotal = quantity * unit_price
    total = subtotal * tax_rate - subtotal * discount
    return total * 0.95  # Another magic number

# Redundant code
def redundant_check(value):
    """Check redundant conditions."""
    if value == True:
        return True
    if value == False:
        return False
    x = (True if value else False)
    return bool(x == True)

# Debug prints
def process_data(data):
    """Process some data."""
    print("DEBUG: Starting processing")
    print(f"Input data: {data}")
    result = data * 2
    print("DEBUG: Result is", result)
    return result

# f-string vs format
def format_old_way(name, age):
    """Use old format instead of f-string."""
    greeting = "Hello, {}! You are {} years old.".format(name, age)
    return greeting

# Dead code
def unused_function(x, y):
    """This function is never called."""
    return x + y

class DataStore:
    """Data store class."""

    def __init__(self):
        self.data = []
        self.temp = None  # should be _temp

    def add(self, item):
        """Add item to store."""
        # Phantom parameter
        self.data.append(item)

    def get(self, index, fake=True, dummy_arg=None):
        """Get item - has fake parameters."""
        return self.data[index]

# Type hints missing
def process_items(items):
    """Process items without type hints."""
    result = []
    for item in items:
        result.append(str(item))
    return result

# match-case suggestion (Python 3.10+)
def get_status_code(code):
    """Get status message - could use match-case."""
    if code == 200:
        return "OK"
    elif code == 404:
        return "Not Found"
    elif code == 500:
        return "Server Error"
    return "Unknown"

# AI: Dataclass suggestion
class Point:
    """Point class that could be a dataclass."""
    def __init__(self, x, y, label=""):
        self.x = x
        self.y = y
        self.label = label

    def distance(self, other):
        """Calculate distance to another point."""
        return ((self.x - other.x)**2 + (self.y - other.y)**2)**0.5
