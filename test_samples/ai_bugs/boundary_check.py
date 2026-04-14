"""Sample code for testing boundary check detection.

This file contains examples of code that should trigger boundary check warnings.
"""

# BAD: Accessing [0] without checking if list is empty
def get_first_item(items):
    return items[0]  # BOUNDARY: IndexError if items is empty


# BAD: split()[0] without guard
def get_first_part(text):
    return text.split(',')[0]  # BOUNDARY: IndexError if no comma


# GOOD: With proper guard
def get_first_item_safe(items):
    if items:
        return items[0]
    return None


# BAD: Negative indexing
def get_last_item(items):
    return items[-1]  # BOUNDARY: IndexError if empty


# BAD: Multiple chained operations
def parse_config(config_str):
    parts = config_str.split('=')
    key = parts[0].strip()
    value = parts[1].strip()  # BOUNDARY: No check for parts[1]
    return {key: value}


# BAD: Accessing dict key without check
def get_first_key(data):
    keys = list(data.keys())
    return keys[0]  # BOUNDARY: IndexError if dict is empty


# GOOD: Proper handling
def get_first_key_safe(data):
    if not data:
        return None
    keys = list(data.keys())
    return keys[0]
