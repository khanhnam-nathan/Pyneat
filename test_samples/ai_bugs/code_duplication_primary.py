"""Sample code for testing code duplication detection.

This file is part of a pair used to test cross-file duplication detection.
See duplication_helper.py for the duplicate function.
"""


def calculate_sum(a, b):
    """Calculate the sum of two numbers."""
    result = a + b
    return result


def calculate_sum_duplicate(a, b):
    """Calculate the sum of two numbers. (DUPLICATE)"""
    result = a + b
    return result


def process_data(data):
    """Process data by adding a prefix."""
    processed = "DATA: " + str(data)
    return processed


def process_data_duplicate(data):
    """Process data by adding a prefix. (DUPLICATE)"""
    processed = "DATA: " + str(data)
    return processed


def format_output(items):
    """Format items as a comma-separated string."""
    return ", ".join(str(item) for item in items)


def format_output_dup(items):
    """Format items as a comma-separated string. (DUPLICATE)"""
    return ", ".join(str(item) for item in items)
