"""Sample code for testing code duplication detection (duplicate file).

This file contains duplicate functions from code_duplication_primary.py.
Used to test cross-file duplication detection.
"""


def calculate_sum(a, b):
    """Calculate the sum of two numbers. (DUPLICATE from another file)"""
    result = a + b
    return result


def calculate_product(x, y):
    """Calculate the product of two numbers. (UNIQUE)"""
    return x * y


def process_data(data):
    """Process data by adding a prefix. (DUPLICATE from another file)"""
    processed = "DATA: " + str(data)
    return processed


def transform_input(value):
    """Transform input value. (UNIQUE)"""
    return str(value).upper().strip()
