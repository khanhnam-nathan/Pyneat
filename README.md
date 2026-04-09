# PyNEAT — Clean AI-Generated Python Code

[![PyPI version](https://img.shields.io/pypi/v/pyneat-cli.svg)](https://pypi.org/project/pyneat-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/pyneat-cli.svg)](https://pypi.org/project/pyneat-cli/)
[![License](https://img.shields.io/pypi/l/pyneat-cli.svg)](https://pypi.org/project/pyneat-cli/)

**The anti-spaghetti code cleaner** — PyNEAT goes beyond black/ruff-style formatting: it runs **AST + LibCST** rules in a single pipeline to fix **security issues**, **AI/legacy smell**, and **unsafe structure** (nested `if/else`, bad `except`, mutable defaults, and more).

**AI generates code fast. PyNEAT cleans what AI generates.**

| Install | One-liner |
|--------|-----------|
| PyPI | `pip install pyneat-cli` |
| CLI | `pyneat check file.py` · `pyneat clean file.py` · `pyneat clean-dir ./src` |

---

## The Problem

AI coding assistants (Cursor, Copilot, Claude Code) generate code at incredible speed. But AI-generated code has predictable patterns that introduce security vulnerabilities and code quality issues:

- **SQL injections** in f-strings: `f"SELECT * FROM users WHERE id = {user_id}"`
- **Hardcoded secrets**: `api_key = "sk_live_abc123..."`
- **Magic numbers**: `timeout = 300  # What does this mean?`
- **Empty except blocks**: `except: pass  # Silent failures`
- **Resource leaks**: `open()` without context manager

## The Solution

**PyNEAT = AI-Generated Code Preprocessor**

```
AI generates code → PyNEAT cleans it → Clean code continues
       ↑                                    ↓
       └────────── PYNAGENT Markers ────────┘
```

## Quick Demo

### Before PyNEAT

```python
# SQL Injection vulnerability
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# Hardcoded secret
api_key = "sk_live_abc123xyz789secret"

# Magic number
timeout = 300  # What is 300?

# Empty except
try:
    risky_operation()
except:
    pass
```

### After PyNEAT

```python
# Parameterized query
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))

# Environment variable
api_key = os.environ.get("API_KEY")

# Named constant
REQUEST_TIMEOUT_SECONDS = 300  # 5 minutes
timeout = REQUEST_TIMEOUT_SECONDS

# Proper error handling
try:
    risky_operation()
except Exception as e:
    logger.error(f"Operation failed: {e}")
    raise
```

## Features

| Feature | Description |
|---------|-------------|
| **50+ Security Rules** | Catch SQL injection, command injection, secrets, weak crypto |
| **AI Bug Patterns** | Magic numbers, empty excepts, resource leaks, naming inconsistencies |
| **LibCST structural surgery** | Deep refactors (not whitespace-only): flatten arrow anti-pattern `if/else`, `eval()` handling, `except: pass`, mutable defaults, `== None` → `is None`, bad `is` on literals, `type(x) == T` → `isinstance` |
| **Auto-fix** | One command to clean entire codebase |
| **Agent-to-Agent Handoff** | PYNAGENT markers for AI editors (Cursor, Copilot, Claude) |
| **LSP Integration** | Real-time diagnostics in VS Code, Neovim, JetBrains |
| **7-Layer Protection** | Semantic guard, type shield, scope protection |

## Security Rules

| Severity | Count | Examples |
|----------|-------|----------|
| CRITICAL | 9 | SQL injection, command injection, RCE |
| HIGH | 10 | Hardcoded secrets, weak crypto |
| MEDIUM | 20 | SSRF, XSS, open redirect |
| LOW | 10 | Information disclosure |
| INFO | 10 | Best practice hints |

## Installation

```bash
pip install pyneat-cli
```

**Optional:** where a platform wheel ships the native scanner, installs can use the compiled extension for faster scans; otherwise the pure-Python + LibCST path still works.

```bash
pip install pyneat-cli
```

## Quick Start

### CLI

```bash
# Scan for security vulnerabilities
pyneat check file.py

# Auto-fix all issues
pyneat clean file.py

# Export manifest for AI editors
pyneat manifest file.py --format sarif

# Clean entire directory
pyneat clean-dir ./src
```

### IDE Plugins

**VS Code**

1. Open VS Code → Extensions (`Ctrl+Shift+X`)
2. Search "PyNEAT"
3. Install

**Neovim**

```lua
-- init.lua
use 'pyneat/pyneat-vim'
```

**JetBrains**

1. Settings → Plugins → Marketplace
2. Search "PyNEAT"
3. Install

### LSP Server

```bash
pip install pyneat-cli[server]
python -m pyneat.lsp
```

## Agent-to-Agent Handoff

PyNEAT generates PYNAGENT markers that AI editors can read:

```python
import os  # PYNAGENT: {"id":"PYN-001","type":"unused_import","severity":"medium","fix":"Remove"}

def main():
    pass
```

AI editors (Cursor, Copilot, Claude Code) read these markers and:
1. Understand what issues exist
2. Ask the user about intent
3. Fix code correctly

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     IDE Layer                               │
│  VS Code  │  Neovim  │  Vim  │  JetBrains  │  CLI       │
└───────────┴──────────┴───────┴────────────┴───────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              PyNEAT Plugin Interface Layer                   │
│  LSP Server  │  CLI Commands  │  Manifest Export           │
└───────────────────────────┬───────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    PyNEAT Core Engine                       │
│  RuleEngine  │  AgentMarker  │  ManifestExporter           │
└─────────────────────────────────────────────────────────────┘
```

## Ecosystem

| Integration | Status |
|-------------|--------|
| VS Code Extension | Complete |
| Neovim Plugin | Complete |
| JetBrains Plugin | Beta |
| LSP Server | Complete |
| GitHub Actions | Complete |
| GitLab CI | Complete |
| Pre-commit Hook | Complete |

## License

GNU Affero General Public License v3 (AGPLv3+)

Commercial licensing: n.khanhnam@gmail.com
