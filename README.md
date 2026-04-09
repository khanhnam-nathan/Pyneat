# PyNeat: The Anti-Spaghetti Code Cleaner

**PyNeat 2.0.0** is an aggressive, AST-based Python code refactoring tool designed to clean up messy, legacy, or AI-generated code. Unlike standard formatters that only fix whitespace, PyNeat performs deep structural surgery on your logic in a single optimized pass using LibCST.

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
| `--enable-dead-code` | `DeadCodeRule` | Removes unused functions and classes via AST analysis |
| `--enable-fstring` | `FStringRule` | Converts `.format()` and string concatenation to f-strings |
| `--enable-range-len` | `RangeLenRule` | Fixes `range(len())` anti-pattern with direct iteration |
| `--enable-typing` | `TypingRule` | Suggests type annotations for untyped functions |
| `--enable-match-case` | `MatchCaseRule` | Suggests converting if-elif chains to match-case (Python 3.10+) |
| `--enable-dataclass` | `DataclassSuggestionRule` | Suggests `@dataclass` for simple data classes |

### What It Fixes

## What's New in v2.0.0

| Category | Feature |
|----------|---------|
| **New Rule** | `IsNotNoneRule` - Converts `x is not None` patterns |
| **New Rule** | `MagicNumberRule` - Detects and flags magic numbers |
| **New Rule** | `RangeLenRule` - Fixes `range(len())` anti-pattern |
| **New Rule** | `DeadCodeRule` - Removes unused functions and classes via AST analysis |
| **New Rule** | `FStringRule` - Converts `.format()` to f-strings |
| **New Rule** | `TypingRule` - Suggests type annotations for untyped functions |
| **New Rule** | `MatchCaseRule` - Suggests match-case for if-elif chains (Python 3.10+) |
| **New Rule** | `DataclassSuggestionRule` - Suggests `@dataclass` for simple classes |
| **Improvement** | Refactored comprehensive rule system with priority ordering |
| **Improvement** | Added comprehensive test samples for real-world scenarios |
| **Improvement** | Cleaner CI/CD workflow with lint and stress tests |
| **Improvement** | Enhanced isolated block processing for nested code |
| **Improvement** | Fixed Unicode encoding issues in CLI output |
| **Bug Fix** | Fixed CI configuration to use proper Linux Python paths |
| **Bug Fix** | Fixed compileall verification for package integrity |
| **Cleanup** | Removed redundant test files for leaner test suite |
| **Cleanup** | Simplified CI pipeline (single pytest run instead of multiple jobs) |

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
| SQL Injection | String concatenation in SQL queries | Warning only |
| Eval/Exec | Dynamic code execution | Warning only |
| YAML Unsafe Load | `yaml.load()` without Loader | **Auto-fixed to SafeLoader** |
| Weak Crypto | `random` for tokens, `hashlib.md5/sha1` | Warning only |
| Pickle Deserialize | `pickle.loads()` | Warning only (RCE risk) |
| Debug Mode | `DEBUG=True` in production | Warning only |
| Weak SECRET_KEY | Short/common keys | Warning + suggestion |
| Hardcoded Secrets | `api_key`, `password`, `token` in code | Warning + env vars suggestion |
| Template Injection | `render_template_string()` | Warning only (SSTI risk) |
| Empty except blocks | `except: pass` | **Auto-fixed to `raise`** |
| Path Traversal | `open()` with user input | Warning only |
| XXE | XML parsing without safe settings | Warning only |

### Rust Acceleration (`--rust`)

For maximum performance, enable the Rust scanner:

```bash
pip install pyneat[rust]
pyneat clean your_file.py --rust
```

The Rust backend uses:
- **tree-sitter** for AST parsing
- **Pre-compiled regex** patterns
- **Rayon** for parallel processing
- **No GIL contention** for true parallelism

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

> **Coming Soon** — VSCode extension is planned for v3.0.0. Track progress at the [GitHub Issues](https://github.com/YOUR_USERNAME/pyneat/issues) page.

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Build distribution
python -m build
```

## Architecture: 7-Layer Protection System

PyNeat implements a comprehensive 7-layer protection system:

| Layer | Component | Description |
|-------|-----------|-------------|
| 1 | **AST Guard** | Validates code structure before processing |
| 2 | **Semantic Guard** | Preserves code semantics during transformations |
| 3 | **Type Shield** | Prevents type-related regressions |
| 4 | **Atomic Operations** | Ensures atomic transformations |
| 5 | **Scope Guard** | Isolates changes within safe boundaries |
| 6 | **Type Checking** | Validates with mypy/pyright |
| 7 | **Fuzz Testing** | Stress tests with malformed inputs |

## Editions & Commercial Support

PyNeat is built with a dual-licensing / freemium model to support both independent developers and large-scale enterprise codebases.

### PyNeat Community (Current Version)
* **Status:** Free & Open Source (GNU AGPLv3)
* **Engine:** Pure Python + Rust hybrid (pyneat-rs)
* **Best for:** Individual developers, students, and small projects
* **Rust coverage:** ~30% of rules (security + quality)

### PyNeat Standard (Available Upon Request)
* **Engine:** Full Rust (`pyneat-rs`) for extreme performance
* **Features:** Multi-threading, 50x-100x faster, deep CI/CD integration
* **Best for:** Mid-sized teams and repositories with 1,000+ files

### PyNeat Enterprise (Available Upon Request)
* **Features:** Everything in Standard, Custom Ruleset API, Audit Reports, Dedicated SLA
* **Best for:** Large enterprises

**Commercial License Exemption:** If you cannot comply with AGPLv3
(e.g., proprietary SaaS, closed-source embedding), contact the author
for a commercial license. Email: `khanhnam.copywriting@gmail.com`

## License

PyNeat is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

PyNeat is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

AGPLv3 with Commercial Exception: Commercial use of this software
(e.g., bundling in paid products, SaaS services) is permitted,
provided that you comply with the open source obligations under AGPLv3 §11.
Contact the author for alternative licensing arrangements.
