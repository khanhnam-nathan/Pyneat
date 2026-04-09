# PyNeat — Capabilities & Competitive Analysis

> Last updated: 2026-04-07 | Version: 2.0.0

---

## TL;DR — What PyNeat Does in One Sentence

**PyNeat** is an AI-generation-aware Python code cleaner that auto-fixes 24+ code quality issues (from `!= None` → `is not None` to cross-file class renaming) with safe defaults and granular opt-in controls for destructive rules.

---

## Quick Demo (What Running It Looks Like)

```bash
# Safe defaults — just clean a file, nothing dangerous happens
pyneat clean messy_ai_output.py

# One command to enable everything destructive
pyneat clean messy_ai_output.py --enable-all

# Batch clean a whole project, dry-run first
pyneat clean-dir src/ --dry-run --diff

# See what rules you have available
pyneat rules
```

---

## Complete Rule Catalog

### A. Auto-Fix Rules (Change Your Code)

| # | Rule | Detects | Fixes | Implementation | Default |
|---|---|---|---|---|---|
| 1 | `IsNotNoneRule` | `x != None` | `x is not None` | LibCST | **ON** |
| 2 | `RangeLenRule` | `for i in range(len(x))` | `for x in items` | LibCST | **ON** |
| 3 | `SecurityScannerRule` | Dangerous patterns (injection, pickle, eval, empty except) | Fixes YAML loader, subprocess shell, adds raise | LibCST + Regex | **ON** |
| 4 | `TypingRule` | Missing `-> None` returns | Auto-adds `-> None` when safe | AST + LibCST | **ON** |
| 5 | `FStringRule` | `.format()` calls, string concat | `f"{x}"` | LibCST | Opt-in |
| 6 | `RedundantExpressionRule` | `x == True`, `str(str(x))` | `x`, `str(x)` | LibCST | Opt-in |
| 7 | `ImportCleaningRule` | Duplicate imports, wrong order | De-dup, re-sort imports | LibCST | Opt-in |
| 8 | `NamingConventionRule` | snake_case class names | Rename + **cross-file import update** | LibCST | Opt-in |
| 9 | `RefactoringRule` | Arrow anti-pattern (4+ nested if), empty except | Early return, add `raise`, replace `eval()` | Regex + text | Opt-in |
| 10 | `DebugCleaner` | Debug prints, pdb imports | Remove prints (safe/aggressive) | LibCST + Regex | Opt-in |
| 11 | `CommentCleaner` | Empty TODO/FIXME, AI boilerplate comments | Delete matching comment lines | Regex | Opt-in |
| 12 | `DeadCodeRule` | Unused functions/classes | Delete entire definitions | AST | Opt-in |
| 13 | `DataclassAdderRule` | Classes that should be dataclasses | Add `@dataclass` decorator | LibCST | Opt-in |

### B. Analysis-Only Rules (Report, Don't Change)

| # | Rule | Detects | Implementation | Default |
|---|---|---|---|---|
| 14 | `CodeQualityRule` | Magic numbers (>=100), empty except blocks | AST | **ON** |
| 15 | `PerformanceRule` | List concat in loops, nested same-iterable loops, `while True` without break | AST | **ON** |
| 16 | `UnusedImportRule` | Import names never referenced | AST | Opt-in |
| 17 | `MagicNumberRule` | Large integer literals (>=100) | Regex | Opt-in |
| 18 | `MatchCaseRule` | 3+ branch if-elif chains suitable for match-case | AST | Opt-in |
| 19 | `IsolatedBlockCleaner` | Imports inside if/try/for blocks | LibCST | Opt-in |

### C. Auxiliary Rules (Supporting, No CLI Flag)

| # | Rule | Purpose |
|---|---|---|
| 20 | `InitFileProtectionRule` | Marks `__all__`-related imports in `__init__.py` as protected |
| 21 | `MatchCaseAdderRule` | (Placeholder — not yet implemented) |

---

## Full CLI Reference

```
pyneat --version
pyneat --color [auto|always|never]

pyneat clean <file>                          # Clean single file
pyneat clean-dir <dir>                      # Clean entire directory
pyneat rules                                # List all rules

Flags (all commands):
  -o, --output PATH          Output file (clean only)
  -i, --in-place            Modify file in-place
  -v, --verbose             Show rule stats + cache stats
  --dry-run                 Preview changes without modifying
  -d, --diff                Show unified diff
  --check-conflicts         Detect overlapping rule changes
  --clear-cache             Clear AST cache before processing
  --no-color                Disable colored output

  # Conservative (opt-in)
  --enable-unused           Remove unused imports
  --enable-redundant        Simplify redundant expressions
  --enable-fstring          Convert .format() to f-strings
  --enable-dead-code        Remove unused functions/classes
  --enable-magic-numbers     Flag magic number literals
  --enable-range-len        Fix range(len()) patterns
  --enable-typing           Suggest/add type annotations
  --enable-match-case       Suggest match-case for if-elif chains
  --enable-dataclass        Suggest @dataclass decorator

  # Destructive (opt-in)
  --enable-all              Enable all destructive rules at once
  --enable-import-cleaning  Rewrite and de-duplicate all imports
  --enable-naming           Rename snake_case classes to PascalCase
  --enable-refactoring     Fix arrow anti-patterns, empty except
  --enable-comment-clean   Remove TODO/FIXME/AI boilerplate comments

  # DebugCleaner modes (mutually exclusive)
  --safe-debug-clean        Remove only debug-like prints
  --aggressive-clean        Remove ALL print/console.log calls
  --keep-all-prints         Keep all prints (default)

  # Directory-only
  -p, --pattern GLOB         File pattern, default "*.py"
  -b, --backup              Backup before in-place modification
  -P, --parallel            Enable parallel processing
  -w, --workers N           Number of parallel workers
  -R, --recursive           Recurse into subdirectories
```

---

## Python API

```python
# Quick string cleaning
from pyneat import clean_code
clean_code("x != None", fix_is_not_none=True)

# File cleaning with full result
from pyneat import clean_file
from pathlib import Path
result = clean_file(Path("file.py"), in_place=True)
print(result.changes_made)

# Analysis-only (read-only)
from pyneat import analyze_code
report = analyze_code("print('debug')")
print(report['issues'])

# Full engine for fine-grained control
from pyneat import RuleEngine
from pyneat.rules import IsNotNoneRule
from pyneat.core.types import RuleConfig
engine = RuleEngine([IsNotNoneRule(RuleConfig(priority=100))])
result = engine.process_file(Path("file.py"), check_conflicts=True)
```

---

## Special Features

| Feature | Details |
|---|---|
| **Safe defaults** | Only 6 rules on by default. All dangerous rules require `--enable-*` flags |
| `--enable-all` | One flag to enable all destructive rules |
| **Config file** | `pyproject.toml` `[tool.pyneat]` section — set rules per-project |
| **Cross-file updates** | `NamingConventionRule` tracks & updates imports when renaming classes |
| **Dual AST/CST parsing** | Every file parsed once (both trees cached), shared across rules |
| **Conflict detection** | `--check-conflicts` detects when two rules touch the same lines |
| **Parallel processing** | `clean-dir` uses `ThreadPoolExecutor`, auto-detects CPU cores |
| **Backup** | `clean-dir --in-place --backup` creates timestamped backup directory |
| **Multi-encoding** | Auto-detects utf-8 (with/without BOM), latin-1, cp1252 |
| **Dry-run + diff** | Preview all changes as unified diff before applying |
| **Safe __init__.py** | `InitFileProtectionRule` protects `__all__`-related imports from removal |
| **Rule grouping** | `pyneat.rules.safe`, `.conservative`, `.destructive` submodules |

---

## Config File Support

```toml
# pyproject.toml
[tool.pyneat]
enable_unused_imports = false
enable_import_cleaning = false
enable_naming = false
debug_clean_mode = "safe"
```

CLI flags override config file settings.

---

## Competitive Landscape

### vs. `ruff` (Astral — the 2024-2025 standard)

| | **PyNeat** | **ruff** |
|---|---|---|
| **Purpose** | AI-generated code cleaner + auto-fixer | General-purpose linter |
| **Language** | Python only | Python only |
| **Auto-fix** | Yes (15 rules) | Yes (many rules) |
| **Cross-file refactor** | Yes (class renames + import updates) | No (single-file at a time) |
| **AST-based transforms** | Yes (via libcst) | Yes (via Ruff's own IR) |
| **CST (structured editing)** | Yes (libcst) | No (string-based fixes) |
| **Config file** | pyproject.toml | pyproject.toml / ruff.toml |
| **Speed** | Moderate (interpreter) | Extremely fast (Rust) |
| **Output format** | Diff, CLI messages | JSON, grouped output |
| **Rule discovery** | `pyneat rules` command | `ruff rule <name>` |
| **AI-specific anti-patterns** | Yes (arrow anti-pattern, debug prints, placeholder functions) | No |
| **Library** | Python API (`clean_code`, `clean_file`) | Python + CLI |
| **Parallel** | ThreadPoolExecutor | Multi-threaded |

> **When to choose PyNeat over ruff**: You need structured AST/CST refactoring that preserves whitespace/comments, cross-file class renames, or AI-generation-specific anti-pattern detection (debug prints, arrow anti-patterns, empty except blocks, placeholder functions).

---

### vs. `autoflake` / `autopep8` / `yapf`

| | **PyNeat** | autoflake | autopep8 | yapf |
|---|---|---|---|---|
| **Removes unused imports** | Yes | Yes | No | No |
| **Removes unused vars** | No | Yes | No | No |
| **Fixes `!= None`** | Yes | No | No | No |
| **Range(len()) fix** | Yes | No | No | No |
| **Cross-file renames** | Yes | No | No | No |
| **f-string conversion** | Yes | No | No | Yes (only yapf style) |
| **Dead code removal** | Yes | No | No | No |
| **Formatting style** | No | No | PEP8 only | Google/YAPF style |
| **AI anti-patterns** | Yes | No | No | No |

> **When to choose PyNeat over these**: You need targeted fixes for specific AI-generation patterns (debug prints, placeholder functions) combined with cross-file refactoring. For pure formatting, use yapf.

---

### vs. `pyupgrade` + `flynt`

| | **PyNeat** | pyupgrade | flynt |
|---|---|---|---|
| **f-string conversion** | Yes | Partial | Yes |
| **`!= None` → `is not None`** | Yes | Yes | No |
| **String concat → f-string** | Yes | No | Yes |
| **`.format()` → f-string** | Yes | No | Yes |
| **Dead code removal** | Yes | No | No |
| **Unused imports** | Yes | No | No |
| **Cross-file renames** | Yes | No | No |

---

### vs. `mypy` / `pyright`

| | **PyNeat** | mypy | pyright |
|---|---|---|---|
| **Type checking** | No | Yes | Yes |
| **Add type annotations** | Partial (`-> None` only) | No | Partial |
| **Type error detection** | No | Yes | Yes |
| **Auto-fix types** | No | No | Partial |
| **Type-aware linting** | No | Yes | Yes |

> These are complementary — PyNeat + pyright is a strong combo.

---

### vs. `prospector` / `pylint` plugin ecosystem

| | **PyNeat** | prospector | pylint |
|---|---|---|---|
| **Multiple tools** | No (own rules) | Yes (pylint + others) | Yes |
| **Auto-fix** | Yes (15 rules) | Partial | Partial (refactoring messages) |
| **Custom rule API** | Yes (Rule base class) | Yes (plugin) | Yes (checker) |
| **AI anti-patterns** | Yes | No | No |
| **Setup complexity** | Simple | Moderate | Simple |

---

## Unique Selling Points (What PyNeat Does That No One Else Does)

1. **Cross-file class rename with import updates** — Rename a snake_case class in one file and all `from module import OldName` / `module.OldName` references are updated across the whole project. No other Python tool does this.

2. **AI-generation-specific anti-patterns**:
   - Arrow anti-pattern detection (4+ nested if → early return refactor)
   - Debug print removal (with keyword detection: `debug`, `test`, `tmp`, `log`, etc.)
   - Placeholder function detection (`def Default_Value(): return Default_Value`)
   - Empty TODO/FIXME comments and AI boilerplate comment removal
   - `# type: ignore` over-use detection

3. **Safe `__init__.py` import protection** — Understands `__all__` and protects imports used for public API re-exports from being removed as "unused".

4. **Structured cross-rule conflict detection** — Can detect when two rules modify overlapping lines and report it, helping users understand unexpected interactions.

5. **Dual-tree caching** — Parses each unique file content once (AST + CST), then reuses both trees across all rules, avoiding repeated parsing cost.

6. **Config-first + CLI-override** — Per-project `pyproject.toml` config with individual rule toggles, all overridable via CLI flags.

7. **Rule grouping for discoverability** — `pyneat.rules.safe`, `.conservative`, `.destructive` submodules make it easy to browse available rules by risk level.

---

## Roadmap Candidates (Not Yet Implemented)

| Feature | Priority | Status |
|---|---|---|
| `MatchCaseAdderRule` full implementation | High | Placeholder |
| DataclassAdderRule (add decorator + remove `__init__`) | Medium | Partial |
| `UnusedImportRule` partial removal (remove single name from multi-name import) | Medium | Disabled for safety |
| Rule config via TOML per-file | Low | Not planned |
| Editor integrations (VSCode, Neovim) | Low | Not planned |
| `ruff` as a backend accelerator | Low | Not planned |
| Pre-commit hook integration | Low | Not planned |
