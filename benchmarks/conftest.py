"""PyNeat Performance Benchmarks.

Run with: pytest benchmarks/ --benchmark-only
Or: python -m pytest benchmarks/ -v
"""

import time
from pathlib import Path
from typing import List

import pytest


def generate_python_code(num_lines: int) -> str:
    """Generate Python code with specified number of lines."""
    lines = [
        "import os",
        "import sys",
        "import json",
        "from typing import List, Dict, Optional",
        "",
        "",
        "class DataProcessor:",
        "    def __init__(self, data: List[dict]):",
        "        self.data = data",
        "        self.processed = []",
        "",
        "    def process(self) -> List[dict]:",
        "        for item in self.data:",
        "            if item.get('active'):",
        "                result = self._transform(item)",
        "                self.processed.append(result)",
        "        return self.processed",
        "",
        "    def _transform(self, item: dict) -> dict:",
        "        return {",
        "            'id': item.get('id', 0),",
        "            'name': item.get('name', ''),",
        "            'value': item.get('value', 0) * 2,",
        "            'active': item.get('active', False),",
        "        }",
        "",
        "    def validate(self) -> bool:",
        "        for item in self.processed:",
        "            if not isinstance(item.get('id'), int):",
        "                return False",
        "            if not isinstance(item.get('value'), (int, float)):",
        "                return False",
        "        return True",
        "",
        "def main():",
        "    data = [",
        "        {'id': i, 'name': f'Item {i}', 'value': i * 10, 'active': i % 2 == 0}",
        "        for i in range(100)",
        "    ]",
        "    processor = DataProcessor(data)",
        "    result = processor.process()",
        "    print(f'Processed {len(result)} items')",
        "    return processor.validate()",
        "",
        "if __name__ == '__main__':",
        "    main()",
    ]

    # Add more lines to reach the target
    current_lines = len(lines)
    if current_lines < num_lines:
        extra = num_lines - current_lines
        lines.extend([f"# Line {i}: This is extra code for benchmarking" for i in range(extra)])

    return "\n".join(lines[:num_lines])


def generate_code_with_issues(num_lines: int) -> str:
    """Generate Python code with security issues for benchmarking security scans."""
    issues = [
        "import os",
        "import subprocess",
        "import pickle",
        "import hashlib",
        "import random",
        "",
        "# Security issues",
        "API_KEY = 'sk-1234567890abcdef'",  # SEC-010: Hardcoded secret
        "hashlib.md5(b'data')",  # SEC-011: Weak crypto
        "hashlib.sha1(b'data')",  # SEC-011: Weak crypto
        "random.choice([1, 2, 3])",  # SEC-019: Insecure random
        "random.randint(0, 100)",  # SEC-019: Insecure random
        "",
        "# More issues",
        "os.system('ls')",  # SEC-001: Command injection
        "subprocess.run('ls', shell=True)",  # SEC-001: Command injection
        "pickle.loads(data)",  # SEC-004: Pickle RCE
        "",
    ]

    base_code = generate_python_code(max(num_lines - len(issues), 50))
    return base_code + "\n\n" + "\n".join(issues)
