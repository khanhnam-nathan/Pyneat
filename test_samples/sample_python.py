"""Sample Python file with common AI-generated code issues."""

import os
import sys
import utils  # phantom import
import helpers  # phantom import
import pickle
import yaml
from typing import List, Dict, Optional

API_KEY = "sk-1234567890abcdef"  # hardcoded secret
PASSWORD = "admin123"  # hardcoded password

def get_user_data(user_id: str):
    """Fetch user data from database."""
    query = "SELECT * FROM users WHERE id = " + user_id  # SQL injection
    return os.system("curl http://api.example.com/data")  # command injection

def process_file(filename: str):
    """Process a file."""
    data = open(filename, "r").read()  # resource leak
    return data

def authenticate(username, password):
    """Authenticate user."""
    if password == "admin":  # identity comparison with string
        return True
    return False

def check_status(code: int):
    """Check HTTP status code."""
    if code is 200:  # identity comparison with int
        return "OK"
    if code is 404:
        return "Not Found"
    return "Unknown"

def parse_config(path: str):
    """Parse YAML config file."""
    with open(path) as f:
        config = yaml.load(f)  # yaml.load without Loader
    return config

def vulnerable_deserialize(data: bytes):
    """Deserialize pickled data."""
    return pickle.loads(data)  # pickle RCE risk

def weak_hash(data: str) -> str:
    """Hash a string."""
    import hashlib
    return hashlib.md5(data.encode()).hexdigest()  # weak hash

def make_token(length: int = 32) -> str:
    """Generate a random token."""
    import random
    import string
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for i in range(length))  # random for security

def bad_example(param1, param2="dummy", param3=None):  # fake parameters
    """Example with fake parameters."""
    if param1 is not None:  # is comparison
        return True
    if param2 is not None:  # is comparison
        return True
    return False

def debug_function():
    """Debug function with prints left behind."""
    print("DEBUG: entering function")
    print("DEBUG: processing data")
    print("DEBUG: done")
    result = x + y  # undefined variable
    return result

def range_len_anti_pattern(items: List):
    """Bad pattern using range(len())."""
    for i in range(len(items)):  # anti-pattern
        print(items[i])

def type_check_bad(obj):
    """Bad type checking."""
    if type(obj) == list:  # should be isinstance
        return True
    if type(obj) == dict:
        return False

def empty_except():
    """Empty except block."""
    try:
        x = 1 / 0
    except:
        pass  # should raise or log

def magic_number():
    """Function with magic numbers."""
    if value > 42:  # magic number
        return value * 3.14159  # another magic number

def long_function():
    """A very long function that should be refactored."""
    a = 1
    b = 2
    c = 3
    d = 4
    e = 5
    f = 6
    g = 7
    h = 8
    i = 9
    j = 10
    if a and b and c and d and e and f and g and h and i and j:
        if a and b and c and d and e and f and g and h and i and j:
            if a and b and c and d and e and f and g and h and i and j:
                print("deeply nested")

class myClass:  # camelCase class name
    def __init__(self):
        self.Debug_Mode = True  # mixed naming
        self.user_name = "test"
        self.apiToken = "secret"

    def get_data(self, url):
        """Fetch data from URL."""
        result = os.system(f"curl {url}")  # command injection
        return result
