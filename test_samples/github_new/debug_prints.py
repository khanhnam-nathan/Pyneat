"""Code with debug prints."""
import os
import sys


def process_data(data):
    """Process data."""
    print("Processing data:", data)
    result = data * 2
    print("Result:", result)
    return result


def validate_input(input_str):
    """Validate input."""
    print("Validating input:", input_str)
    if not input_str:
        print("Error: Empty input")
        return False
    print("Validation passed")
    return True


def complex_calculation(a, b, c):
    """Complex calculation."""
    print("a:", a, "b:", b, "c:", c)
    result = a + b * c
    print("Intermediate result:", result)
    result = result / 2
    print("Final result:", result)
    return result


class DataProcessor:
    """Data processor."""

    def __init__(self):
        print("Initializing DataProcessor")
        self.data = []

    def add(self, item):
        print("Adding item:", item)
        self.data.append(item)

    def process(self):
        print("Processing", len(self.data), "items")
        return [x * 2 for x in self.data]
