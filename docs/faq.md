# PyNeat FAQ

Frequently Asked Questions about PyNeat.

## Installation

### Q: Python 3.12/3.13 is not supported?

PyNeat supports Python 3.10 and higher. If you encounter issues with newer Python versions, please report them on GitHub.

### Q: How do I install the Rust backend?

```bash
pip install pyneat[rust]
```

For manual installation:
```bash
cd pyneat-rs
cargo build --release
```

### Q: Installation fails with "Microsoft Visual C++" error

You need the Visual C++ Build Tools. Install from:
https://visualstudio.microsoft.com/visual-cpp-build-tools/

## Usage

### Q: How do I scan multiple files?

```bash
# Scan a directory
pyneat check ./src

# Scan specific files
pyneat check file1.py file2.py file3.py
```

### Q: How do I see what changes PyNeat will make?

```bash
pyneat clean file.py --dry-run --diff
```

### Q: How do I apply fixes automatically?

```bash
# Creates a backup before modifying
pyneat clean file.py --in-place --backup

# Or without backup
pyneat clean file.py --in-place
```

### Q: Can I exclude certain files or directories?

Create a `pyneat.yaml` config:

```yaml
exclude:
  - "**/test_*.py"
  - "**/venv/**"
  - "**/__pycache__/**"
```

### Q: How do I ignore specific rules?

```bash
# Ignore one rule
pyneat clean file.py --ignore SecurityScannerRule

# Ignore multiple rules
pyneat clean file.py --ignore "Rule1,Rule2,Rule3"
```

Or in code:
```python
from pyneat.rules import exclude_rules

engine = RuleEngine(rules=exclude_rules(["SecurityScannerRule"]))
```

## Rules

### Q: What rules are available?

```bash
pyneat rules
```

### Q: How do I create a custom rule?

See [writing-rules.md](writing-rules.md) for a complete guide.

Basic example:
```python
from pyneat.rules.base import AIBugRule

class MyRule(AIBugRule):
    RULE_ID = "MYRULE-001"
    SEVERITY = "medium"

    def detect(self, node, context):
        # Your detection logic
        return []
```

### Q: What package level should I use?

| Package | When to Use |
|---------|-------------|
| `safe` (default) | Production code, want zero risk |
| `conservative` | Want additional cleanup, minor risk |
| `destructive` | Want aggressive refactoring, review changes |

### Q: Why are some issues not being detected?

- The issue may not match a known AI-generated pattern
- The rule might be disabled in your configuration
- The code pattern might be too complex for detection

## Security

### Q: Does PyNeat send my code anywhere?

No. PyNeat runs entirely locally on your machine. No code is sent to external servers.

### Q: How accurate is the security scanner?

PyNeat detects common security issues in AI-generated code. It should be used as a supplement to, not a replacement for, comprehensive security testing.

### Q: Can PyNeat fix security vulnerabilities automatically?

Some security issues can be auto-fixed:
- `yaml.load()` without SafeLoader
- Empty `except: pass`

Other issues are reported but require manual intervention.

## Performance

### Q: PyNeat is running slowly on large projects

- Use the Rust backend for better performance
- Run on specific files instead of entire directories
- Increase memory with `--max-memory` flag

### Q: How do I benchmark PyNeat?

```bash
python pyneat/benchmark.py --iterations 10 --output results.json
```

## Integrations

### Q: How do I use PyNeat with GitHub Actions?

See [github-actions-guide.md](github-actions-guide.md).

### Q: How do I use PyNeat with pre-commit?

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pyneat-check
        name: PyNeat Check
        entry: pyneat clean --check
        language: system
        types: [python]
```

### Q: Can I use PyNeat in my IDE?

- VSCode: Use the PyNeat extension
- PyCharm: Use the command line tool
- Cursor: Use with pre-commit or command line

## Export & Reports

### Q: How do I export to SARIF format?

```bash
pyneat check file.py --export-sarif results.sarif
```

### Q: How do I integrate with SonarQube?

```bash
pyneat check file.py --export-sonarqube results.json
```

### Q: How do I create a HTML report?

```python
from pyneat.core.manifest import export_to_html_report

html = export_to_html_report(markers, title="My Report")
with open("report.html", "w") as f:
    f.write(html)
```

## Troubleshooting

### Q: "command not found: pyneat" after installation

```bash
# Check installation
pip show pyneat

# Try running as module
python -m pyneat check file.py

# Reinstall if needed
pip uninstall pyneat
pip install pyneat
```

### Q: PyNeat hangs or crashes

- Check available memory
- Try running on smaller files
- Report the issue with the file causing the crash

### Q: False positives on legitimate code

- Use `--package safe` for fewer aggressive rules
- Configure specific rules in `pyneat.yaml`
- Use inline ignores: `# pyneat: ignore-line`

### Q: Config file not being read

PyNeat looks for config in:
1. `./pyneat.yaml`
2. `./pyneat.yml`
3. `~/.pyneat.yaml`

Make sure the file is in the correct location.

## Contributing

### Q: How do I contribute to PyNeat?

See [CONTRIBUTING.md](../CONTRIBUTING.md).

### Q: How do I report a bug?

Open an issue on GitHub with:
- PyNeat version
- Python version
- Sample code that triggers the bug
- Expected vs actual behavior

### Q: How do I request a new feature?

Open a feature request on GitHub with:
- Description of the feature
- Use case
- Example code patterns to detect

## License

PyNeat is licensed under the MIT License. See [LICENSE](LICENSE) for details.
