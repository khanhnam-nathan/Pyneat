# PyNeat: The Anti-Spaghetti Code Cleaner

**PyNeat** is an aggressive, AST-based Python code refactoring tool designed to clean up messy, legacy, or AI-generated code. Unlike standard formatters that only fix whitespace, PyNeat performs deep structural surgery on your logic in a single optimized pass using LibCST.

## Features

### Core Cleaning Rules (Always-on)

| Rule | Description |
|------|-------------|
| `ImportCleaningRule` | Standardizes and deduplicates import statements |
| `NamingConventionRule` | Enforces PEP8 naming conventions |
| `RefactoringRule` | Refactors complex nested code structures (Arrow Anti-pattern) |
| `DebugCleaner` | Removes print/log/pdb debug artifacts |
| `CommentCleaner` | Removes empty TODO/AI boilerplate comments |

### Optional Rules (Flags)

| Flag | Rule | Description |
|------|------|-------------|
| `--enable-security` | `SecurityScannerRule` | Detects SQL injection, hardcoded secrets, eval() |
| `--enable-quality` | `CodeQualityRule` | Detects magic numbers, empty except blocks |
| `--enable-performance` | `PerformanceRule` | Detects inefficient loops and patterns |
| `--enable-unused` | `UnusedImportRule` | Removes genuinely unused imports via AST analysis |
| `--enable-redundant` | `RedundantExpressionRule` | Simplifies `x == True`, `str(str(x))`, etc. |

### What It Fixes

1. Flattens deeply nested `if/else` (Arrow Anti-pattern)
2. Converts `x == None` to `x is None`
3. Fixes literal identity comparisons (`is 200` to `== 200`)
4. Upgrades `type(x) == list` to `isinstance()`
5. Removes debug artifacts: `print()`, `pdb`, `console.log`
6. Cleans empty TODO/FIXME comments
7. Standardizes and deduplicates imports
8. Detects silent failures (`except: pass`)
9. Removes unused imports via AST analysis
10. Simplifies redundant expressions (`x == True` -> `x`)
11. Auto-fixes `yaml.load()` to use `SafeLoader`
12. Warns about command injection, pickle RCE, weak crypto

### Security Scanning (`--enable-security`)

When enabled, detects and auto-fixes security vulnerabilities in AI-generated code:

| Vulnerability | Detection | Auto-fix |
|-------------|-----------|----------|
| Command Injection | `os.system()`, `subprocess.run(shell=True)` | Warning only |
| YAML Unsafe Load | `yaml.load()` without Loader | **Auto-fixed to SafeLoader** |
| Weak Crypto | `random` for tokens, `hashlib.md5/sha1` | Warning only |
| Pickle Deserialize | `pickle.loads()` | Warning only (RCE risk) |
| Debug Mode | `DEBUG=True` in production | Warning only |
| Weak SECRET_KEY | Short/common keys | Warning + suggestion |
| Hardcoded Secrets | `api_key`, `password`, `token` in code | Warning + env vars suggestion |
| Template Injection | `render_template_string()` | Warning only (SSTI risk) |
| Empty except blocks | `except: pass` | **Auto-fixed to `raise`** |

## Installation

```bash
pip install pyneat-cli
```

Or install from source:

```bash
git clone https://github.com/khanhnam-nathan/Pyneat.git
cd Pyneat
pip install -e .
```

## Usage

### Clean a single file

```bash
pyneat clean your_messy_file.py
```

With in-place modification:

```bash
pyneat clean your_messy_file.py --in-place
```

### Clean entire directory

```bash
pyneat clean-dir ./src
```

### Verbose output

```bash
pyneat clean your_file.py --verbose
```

### Enable optional rules

```bash
pyneat clean your_file.py --enable-security --enable-unused --enable-redundant
```

### List all rules

```bash
pyneat rules
```

## Configuration

PyNeat respects `pyproject.toml` settings under `[tool.pyneat]`:

```toml
[tool.pyneat]
enable_security = false
enable_quality = false
enable_performance = false
enable_unused_imports = true
enable_redundant = true
```

## Pre-commit Integration

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: pyneat-clean
        name: PyNeat AI Code Cleaner
        entry: pyneat clean --in-place --verbose
        language: system
        types: [python]
        pass_filenames: true
        args: ['--enable-unused', '--enable-redundant']
```

Install:

```bash
# Linux/macOS
bash scripts/setup-pre-commit.sh

# Windows
scripts\setup-pre-commit.bat
```

## GitHub Actions

Add code quality checks to your CI/CD pipeline:

```yaml
# .github/workflows/pyneat.yml
name: PyNeat Code Quality
on: [push, pull_request]
jobs:
  pyneat:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - name: Install PyNeat
        run: pip install pyneat
      - name: Run PyNeat
        run: pyneat clean-dir . --dry-run
```

Or copy the full template from [`.github/workflows/pyneat.yml`](.github/workflows/pyneat.yml).

## VSCode Extension

See [`vscode-extension/`](vscode-extension/) for the full VSCode extension with:

- Command Palette integration
- Real-time diagnostics
- Quick Fix suggestions
- Auto-clean on save

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Build distribution
python -m build
```

## Editions & Commercial Support

PyNeat is built with a dual-licensing / freemium model to support both independent developers and large-scale enterprise codebases.

### PyNeat Community (Current Version)
* **Status:** Free & Open Source (MIT License)
* **Engine:** Pure Python orchestrator
* **Best for:** Individual developers, students, and small projects

### PyNeat Standard (Available Upon Request)
* **Engine:** Rewritten in Rust (`pyneat-rs`) for extreme performance
* **Features:** Multi-threading, 50x-100x faster, deep CI/CD integration
* **Best for:** Mid-sized teams and repositories with 1,000+ files

### PyNeat Enterprise (Available Upon Request)
* **Features:** Everything in Standard, Custom Ruleset API, Audit Reports, Dedicated SLA
* **Best for:** Large enterprises

**Interested in Standard or Enterprise?** Contact: `khanhnam.copywriting@gmail.com`

## License

MIT License - see [LICENSE](LICENSE) for details.
