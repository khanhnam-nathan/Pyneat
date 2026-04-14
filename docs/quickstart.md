# PyNeat Quick Start Guide

Get up and running with PyNeat in 5 minutes!

## Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

## Installation

### From PyPI (Recommended)

```bash
pip install pyneat
```

### From Source

```bash
git clone https://github.com/khanhnam-nathan/Pyneat.git
cd Pyneat
pip install -e .
```

### With Rust Backend

For better performance on large codebases:

```bash
pip install pyneat[rust]
# Or install from source
cd pyneat-rs
cargo build --release
```

## Quick Examples

### 1. Scan a File for Issues

```bash
pyneat check your_file.py
```

### 2. Clean AI-Generated Code

```bash
# Dry run (preview changes)
pyneat clean your_file.py --dry-run --diff

# Apply fixes in-place
pyneat clean your_file.py --in-place
```

### 3. Security Scan

```bash
pyneat check your_file.py --severity
```

### 4. Multi-Language Support

```bash
# Scan entire directory
pyneat check ./src

# Specify language
pyneat clean script.py --lang python
```

### 5. Use with Pre-commit Hooks

```bash
pip install pre-commit
pre-commit install

# Add to .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pyneat-security
        name: PyNeat Security Scan
        entry: pyneat check
        language: system
        types: [python]
        stages: [pre-commit]
```

## Python API Usage

### Basic Scanning

```python
from pyneat.core import RuleEngine
from pyneat.rules import ALL_RULES

engine = RuleEngine(rules=ALL_RULES)
findings = engine.scan_code("your code here", language="python")

for finding in findings:
    print(f"{finding.rule_id}: {finding.message}")
```

### Security Scanning

```python
from pyneat.rules.security import SecurityScannerRule

security_rules = [SecurityScannerRule()]
engine = RuleEngine(rules=security_rules)
findings = engine.scan_code(code, language="python")
```

### Auto-fixing

```python
from pyneat.fixer import AutoFixer

fixer = AutoFixer()
result = fixer.fix_file("your_file.py", dry_run=True)
print(result.diff)  # Preview changes
```

### Export Reports

```python
from pyneat.core.manifest import export_to_sarif, export_to_junit_xml

# SARIF for GitHub Code Scanning
sarif = export_to_sarif(markers, "file.py")

# JUnit XML for CI/CD
junit = export_to_junit_xml(markers, source_file="file.py")
```

## Configuration

### Package Levels

PyNeat has three package levels for different safety needs:

| Package | Use Case | Command |
|---------|----------|---------|
| `safe` (default) | Zero-risk fixes | `pyneat clean file.py` |
| `conservative` | Cleaner code | `pyneat clean file.py --package conservative` |
| `destructive` | Full cleanup | `pyneat clean file.py --package destructive` |

### Rule Configuration

```yaml
# pyneat.yaml
rules:
  enabled:
    - IsNotNoneRule
    - SecurityScannerRule
  disabled:
    - PrintDebugRule
```

### Ignore Specific Issues

```bash
# Ignore a specific rule
pyneat clean file.py --ignore SecurityScannerRule

# Ignore specific lines
# pyneat: ignore-line
x != None  # pyneat: ignore-line
```

## Common Workflows

### CI/CD Integration

```yaml
# GitHub Actions
- name: PyNeat Security Scan
  run: |
    pip install pyneat
    pyneat check . --export-sarif results.sarif
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Git Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
pyneat check $(git diff --cached --name-only --diff-filter=ACM) || exit 1
```

### IDE Integration

VSCode: Install the PyNeat extension from the Marketplace.

## Troubleshooting

### Installation Issues

**Problem:** `pyneat: command not found`

```bash
# Solution: Reinstall
pip uninstall pyneat
pip install pyneat

# Or use python -m
python -m pyneat check file.py
```

**Problem:** Rust backend not working

```bash
# Check Rust installation
rustc --version

# Rebuild
cd pyneat-rs
cargo build --release
```

### Scan Issues

**Problem:** No issues found

- Check if the file contains AI-generated patterns
- Try with `--verbose` flag
- Verify language is correctly detected

**Problem:** Too many false positives

- Use `--package safe` for fewer aggressive rules
- Configure specific rules in `pyneat.yaml`
- Use `--ignore` for specific rules

## Next Steps

- Read the full [README.md](../README.md)
- Explore [examples/](../examples/) for more use cases
- Check out [rules documentation](writing-rules.md) to create custom rules
- Review [architecture documentation](architecture.md) for technical details

## Getting Help

- GitHub Issues: Report bugs and request features
- Documentation: Check the [docs/](../docs/) folder
- Examples: See the [examples/](../examples/) directory
