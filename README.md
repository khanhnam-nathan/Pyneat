# PyNeat: The Anti-Spaghetti Code Cleaner

**PyNeat 2.4.0** is an aggressive, AST-based Python code refactoring tool designed to clean up messy, legacy, or AI-generated code. Unlike standard formatters that only fix whitespace, PyNeat performs deep structural surgery on your logic in a single optimized pass using LibCST.

## Features

### Package System

PyNeat uses a **3-tier package system** to balance safety vs. aggressiveness:

| Package | Description | Safety |
|---------|-------------|--------|
| `safe` (default) | Always-on rules that won't break code | **100% safe** |
| `conservative` | Adds cleanup rules, may change style | Safe |
| `destructive` | Aggressive refactoring, may break code | **Review changes** |

### Safe Package (Default — Always On)

These rules run automatically, no flags needed:

| Rule | Description |
|------|-------------|
| `IsNotNoneRule` | Fixes `x != None` → `x is not None` (PEP8) |
| `RangeLenRule` | Fixes `range(len())` anti-pattern |
| `TypingRule` | Suggests type annotations |
| `CodeQualityRule` | Detects magic numbers, empty except blocks |
| `PerformanceRule` | Detects inefficient loops |
| `SecurityScannerRule` | Detects vulnerabilities (os.system, pickle, secrets) |

### Conservative Package (`--package conservative`)

Adds cleanup rules, safe to use:

| Flag | Rule | Description |
|------|------|-------------|
| `--enable-unused` | `UnusedImportRule` | Removes genuinely unused imports |
| `--enable-fstring` | `FStringRule` | Converts `.format()` to f-strings |
| `--enable-dataclass` | `DataclassSuggestionRule` | Suggests `@dataclass` decorator |
| `--enable-magic-numbers` | `MagicNumberRule` | Flags magic numbers |
| `--safe-debug-clean` | `DebugCleaner` (safe) | Removes debug-like prints |

### Destructive Package (`--package destructive`)

Aggressive rules that **may break code** — always review changes:

| Flag | Rule | Description |
|------|------|-------------|
| `--enable-all` | All rules | Enable everything (shortcut) |
| `--enable-import-cleaning` | `ImportCleaningRule` | Rewrite/reorder all imports |
| `--enable-naming` | `NamingConventionRule` | Rename classes to PascalCase |
| `--enable-refactoring` | `RefactoringRule` | Flatten nested if (Arrow Anti-pattern) |
| `--enable-comment-clean` | `CommentCleaner` | Remove TODO/FIXME comments |
| `--enable-redundant` | `RedundantExpressionRule` | Simplify `x == True`, `str(str(x))` |
| `--enable-dead-code` | `DeadCodeRule` | Remove unused functions/classes |
| `--enable-match-case` | `MatchCaseRule` | Suggest match-case (Python 3.10+) |
| `--aggressive-clean` | `DebugCleaner` (aggressive) | Remove ALL print calls |

## What It Fixes

### AgentMarker — Issue Tracking Metadata
- `AgentMarker` dataclass tracks each issue with full metadata (rule_id, severity, line, CWE, confidence, auto-fix diff)
- Auto-exports as `# PYNAGENT: {...}` comments in source code
- `to_dict()`, `to_json()`, `to_comment()` methods for integration

### Manifest Export — CI/CD Integration
- `ManifestExporter` writes `.pyneat.manifest.json` with all markers
- `export_to_sarif()` — SARIF 2.1.0 format (GitHub Security, Azure DevOps)
- `export_to_codeclimate()` — Code Climate format
- `export_to_markdown()` — Human-readable report

### MarkerCleanup — Stale Marker Removal
- `MarkerCleanup` class removes markers after issues are fixed
- `remove_stale_markers()` — only removes markers not in remaining_issues
- `remove_all_markers()` — strips all PYNAGENT comments

### AI Bug Detection (`AIBugRule`)
- **Resource Leaks**: `open()` without `with`, `requests` without timeout
- **Boundary Errors**: `list[0]` without empty check, `.split()[0]`
- **Phantom Packages**: generic import names (utils, helpers, ai)
- **Fake Parameters**: `param1=x`, `fake=True`, `dummy_arg`
- **Redundant I/O**: Same API call 3+ times with identical args
- **Naming Inconsistency**: Mixed camelCase/snake_case in same file

### CLI Enhancements
- `--package` system: `safe` (default) → `conservative` → `destructive`
- `--enable-all` — enable all destructive rules at once
- `--dry-run` + `--diff` — preview changes before writing
- `--backup` + `--in-place` — safe file modification
- `--export-manifest` — auto-export PYNAGENT manifest

### Interactive Feature Menu
After running `check` or `clean`, an interactive menu appears with smart suggestions:
- Shows 4-7 relevant features based on the last command
- Option names in English, descriptions in Vietnamese
- Press Enter or q to skip

```
┌─────────────────────────────────────────────────────────────┐
│                  EXPLORE MORE FEATURES                     │
└─────────────────────────────────────────────────────────────┘

[3] 🧹 Clean Code
    Thêm type hints, xóa unused imports, số magic, debug prints...
    → pyneat clean file.py

[2] 📖 Explain Rule
    Nguyên nhân, cách fix, CWE/OWASP, verification steps...
    → pyneat explain SEC-001

[4] 📊 Export Report (JSON/SARIF)
    Tích hợp CI/CD: GitHub Code Scanning, GitLab SAST...
    → pyneat report . -f sarif -o security.sarif

[q] Exit - return to terminal
[Enter] Skip this menu
```

### Pre-commit + GitHub Actions
- Auto-generate `.pyneat.manifest.json` on commit
- CI/CD job for automated manifest export on push/PR

---

## What It Fixes

1. Flattens deeply nested `if/else` (Arrow Anti-pattern)
2. Converts `x != None` to `x is not None` (PEP8)
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
13. Detects AI-generated code bugs (resource leaks, phantom packages, fake params)

### Security Scanning

`SecurityScannerRule` runs automatically in all packages. Detects and auto-fixes vulnerabilities:

| Vulnerability | Detection | Auto-fix |
|-------------|-----------|----------|
| Command Injection | `os.system()`, `subprocess.run(shell=True)` | Warning only |
| SQL Injection | String concatenation in SQL queries | Warning only |
| Eval/Exec | Dynamic code execution | Warning only |
| YAML Unsafe Load | `yaml.load()` without Loader | **Auto-fixed to SafeLoader** |
| Weak Crypto | `random` for tokens, `hashlib.md5/sha1` | Warning only |
| Pickle Deserialize | `pickle.loads()` | Warning only (RCE risk) |
| Debug Mode | `DEBUG=True` in production | Warning only |
| Hardcoded Secrets | `api_key`, `password`, `token` in code | Warning + env vars suggestion |
| Template Injection | `render_template_string()` | Warning only (SSTI risk) |
| Empty except blocks | `except: pass` | **Auto-fixed to `raise`** |
| Path Traversal | `open()` with user input | Warning only |
| XXE | XML parsing without safe settings | Warning only |

Use `pyneat check` for detailed scan with severity levels and CVSS scores.

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

### CLI — Clean a single file

```bash
# Default (safe package) — runs automatically, no flags needed
pyneat clean your_messy_file.py

# Preview changes without writing
pyneat clean your_messy_file.py --dry-run --diff

# In-place modification (with backup first)
pyneat clean your_messy_file.py --in-place --backup

# Conservative package — adds cleanup rules
pyneat clean your_messy_file.py --package conservative

# Destructive package — aggressive refactoring (may break code!)
pyneat clean your_messy_file.py --package destructive

# Enable ALL rules at once
pyneat clean your_messy_file.py --package destructive --enable-all
```

### CLI — Clean entire directory

```bash
# Preview all changes first
pyneat clean-dir ./src --dry-run --diff

# In-place with parallel processing
pyneat clean-dir ./src --pattern "*.py" --in-place --backup --parallel
```

### CLI — Security scan (no auto-fix)

```bash
# Scan for vulnerabilities
pyneat check your_file.py --severity --cvss

# Fail CI if CRITICAL issues found
pyneat check ./src --fail-on critical --format sarif --output report.sarif
```

### CLI — Other commands

```bash
# List all rules by package
pyneat rules

# Explain a security rule
pyneat explain SEC-001

# Ignore a rule (per-instance or global)
pyneat ignore SEC-003 --file app.py --line 42 --reason "already sanitized"
```

### Python API

```python
from pyneat import clean_code, clean_file, analyze_code

# Simplest — pass code as a string
result = clean_code("x == None")                          # "x is not None"
result = clean_code("print('debug')", remove_debug=True)  # ""

# Clean a file
from pathlib import Path
result = clean_file(Path("app.py"), in_place=True)
print(f"Made {len(result.changes_made)} changes")

# Analyze only — no auto-fix
report = analyze_code("x == None; print('debug')")
for issue in report['issues']:
    print(f"  - {issue}")
```

### Python API — Custom engine

```python
from pyneat import RuleEngine, CodeFile, RuleConfig
from pyneat.rules import IsNotNoneRule, DebugCleaner

engine = RuleEngine([
    IsNotNoneRule(),
    DebugCleaner(mode="safe"),
])
result = engine.process_code_file(CodeFile(path=Path("demo.py"), content=source))
```

## Configuration

PyNeat respects `pyproject.toml` settings under `[tool.pyneat]`:

```toml
[tool.pyneat]
# Default package: safe, conservative, or destructive
package = "safe"

# Conservative rules
enable_unused_imports = true
enable_fstring = false
enable_dataclass = false
enable_magic_numbers = false
debug_clean_mode = "off"   # off, safe, or aggressive

# Destructive rules (use with caution!)
enable_import_cleaning = false
enable_naming = false
enable_refactoring = false
enable_comment_clean = false
enable_redundant = false
enable_dead_code = false
enable_match_case = false

# Auto-export manifest on commit
export_manifest = false
```

## Pre-commit Integration

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: pyneat-clean
        name: PyNeat AI Code Cleaner
        entry: pyneat clean --package conservative --in-place
        language: system
        types: [python]
        pass_filenames: true
        args: ['--enable-unused', '--dry-run']
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
# .github/workflows/ci.yml
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

Or copy the full template from [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

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
