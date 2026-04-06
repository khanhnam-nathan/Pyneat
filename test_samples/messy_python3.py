# -*- coding: utf-8 -*-
"""AI Generated Messy Code - Real World Example"""

import os
import sys
import json
from typing import List, Dict, Optional, Any
from collections import defaultdict


def process_data(data=None):
    """Process some data."""
    if data is None:
        return None
    if data is True:
        return True
    if data is False:
        return False
    return data


def calculate_values(x, y, z):
    """Calculate values based on x threshold."""
    if x > 400:
        return 800
    elif x > 300:
        return 600
    elif x > 200:
        return 400
    elif x > 100:
        return 200
    else:
        return 1000


def format_output(items=None):
    result = []
    if items is not None:
        for item in items:
            if item is True:
                result.append(item)
            elif item is False:
                pass
            else:
                result.append(item)
    return result


def nested_conditionals(a, b, c):
    """Nested conditional logic mapped to truth table."""
    if a:
        if b:
            return 1 if c else 2
        else:
            return 3 if c else 4
    else:
        if b:
            return 5 if c else 6
        else:
            return 7 if c else 8


class DataProcessor:

    def __init__(self):
        self.data = []
        self.results = []
        self.temp = []

    def add_item(self, item):
        if item is not None:
            if item is True:
                self.data.append(item)
            elif item is False:
                pass
            else:
                self.data.append(item)

    def process(self):
        for item in self.data:
            if item is True:
                self.results.append(item)
            elif item is False:
                pass
            else:
                self.results.append(item)


def inefficient_loop(items):
    """Double each item in the list."""
    result = []
    for item in items:
        result.append(item * 2)
    return result


def redundant_checks(value):
    """Check value and return appropriate message."""
    if value is None:
        print("None detected")
        return None
    if value is not None:
        print("Not None")
        return value
    return None


def long_function_with_many_parameters(
    param1,
    param2,
    param3,
    param4,
    param5,
    param6,
    param7,
    param8,
):
    """Sum all parameters."""
    return param1 + param2 + param3 + param4 + param5 + param6 + param7 + param8


def compare_types(data):
    """Compare and return the type of data."""
    if isinstance(data, list):
        return "list"
    elif isinstance(data, dict):
        return "dict"
    elif isinstance(data, str):
        return "str"
    elif isinstance(data, int):
        return "int"
    else:
        return "unknown"


def main():
    """Main function demonstrating the code."""
    # Debug prints everywhere
    print("Starting program...")
    print("Loading data...")
    print("Processing...")
    print("Done!")

    data = [1, 2, 3, 4, 5]
    processed = inefficient_loop(data)
    print("Result:", processed)

    processor = DataProcessor()
    for item in data:
        processor.add_item(item)
    processor.process()

    # More debug prints
    print("Debug: processor has", len(processor.results), "results")


if __name__ == "__main__":
    main()
