# Quick Start - PyNEAT

## Quick Setup

### 1. Installation

```bash
pip install pyneat-cli
```

### 2. Verify

```bash
pyneat --version
```

### 3. List rules

```bash
pyneat rules
```

## Basic Usage

### Security Scan

```bash
# Scan a single file
pyneat check file.py

# Scan a directory
pyneat check ./src

# Scan with verbose output
pyneat check file.py --verbose

# Scan with SARIF output (GitHub Security tab)
pyneat check ./src --output-format sarif --output security-results.sarif
```

### Clean Code

```bash
# Preview changes (dry-run)
pyneat clean file.py --dry-run --diff

# Apply changes
pyneat clean file.py

# Clean a directory
pyneat clean-dir ./src

# Check only, do not fix
pyneat clean file.py --check
```

### Packages

PyNEAT has 3 packages with different aggression levels:

#### Safe (Default)
```bash
pyneat clean file.py --package safe
```
- Will not break code
- Fix `!= None` → `is not None`
- Fix `range(len())` anti-pattern
- Suggest type annotations

#### Conservative
```bash
pyneat clean file.py --package conservative
```
- Add cleanup rules
- Remove unused imports
- Convert `.format()` → f-strings
- Suggest `@dataclass`

#### Destructive (Use with Caution!)
```bash
pyneat clean file.py --package destructive
```
- Aggressive rules
- May change behavior
- Remove dead code
- Rename classes

### Debug Modes

```bash
# Keep all prints (default)
pyneat clean file.py --keep-all-prints

# Only remove debug-like prints
pyneat clean file.py --safe-debug-clean

# Remove all prints
pyneat clean file.py --aggressive-clean
```

## CI/CD Integration

### GitHub Actions

```yaml
name: PyNEAT Security

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install PyNEAT
        run: pip install pyneat-cli
      - name: Security Scan
        run: pyneat check . --output-format sarif --output results.sarif
      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
pyneat-security:
  image: python:3.12-slim
  before_script:
    - pip install pyneat-cli
  script:
    - pyneat check . --output sarif --output security.sarif
  artifacts:
    reports:
      sast: security.sarif
```

### Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pyneat-check
        name: PyNEAT Security Check
        entry: pyneat check
        language: system
        files: \.py$
```

## Real-World Examples

### Before clean

```python
# demo/before.py
import os
from typing import List

def find_user(users, user_id):
    for user in users:
        if user.get("id") != None:  # Bug: should be is not None
            return user
    return None

def process_items(items):
    for i in range(len(items)):  # Bug: should iterate directly
        print(items[i])

def calculate_total(items):
    print("Debug: calculating...")  # Debug artifact
    total = 0
    for item in items:
        total = total + item["price"]
    return total
```

### After clean

```python
# After running: pyneat clean demo/before.py

from typing import List, Optional

def find_user(users: List[dict], user_id: int) -> Optional[dict]:
    for user in users:
        if user.get("id") is not None:  # Fixed
            return user
    return None

def process_items(items: List) -> None:
    for item in items:  # Fixed - iterate directly
        print(item)

def calculate_total(items: List[dict]) -> float:
    # Debug print removed
    total = 0.0
    for item in items:
        total += item["price"]  # Optimized
    return total
```

## Configuration

### pyproject.toml

```toml
[tool.pyneat]
enable_security = true
enable_quality = true
enable_performance = true
enable_unused_imports = true
enable_redundant = true
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--package PACKAGE` | Select package (safe/conservative/destructive) |
| `--dry-run` | Preview changes |
| `--diff` | Show diff |
| `--check` | Check only, do not fix |
| `--verbose` | Verbose output |
| `--backup` | Backup file before fixing |
| `--output-format FORMAT` | Output format (text/json/sarif) |

## Troubleshooting

### "Module not found" error

```bash
pip install --upgrade pyneat
```

### Permission error

```bash
# Linux/macOS
sudo pip install pyneat-cli

# Or use virtual environment
python -m venv venv
source venv/bin/activate
pip install pyneat-cli
```

### Undo changes

```bash
# If you have a backup
pyneat clean file.py --restore

# Or restore from git
git checkout file.py
```
