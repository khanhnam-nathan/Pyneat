---
title: PyNEAT - AI Python Code Cleaner
description: Clean AI-generated Python code automatically. Detect security vulnerabilities, fix AI artifacts, and export markers for AI editors.
---

# PyNEAT: Clean AI-Generated Python Code

> **AI generates code fast. PyNEAT cleans what AI generates.**

[![PyPI Version](https://img.shields.io/pypi/v/pyneat.svg)](https://pypi.org/project/pyneat/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-green.svg)](https://www.python.org/)

---

## The Problem with AI-Generated Code

AI coding assistants like Cursor, Copilot, and Claude Code generate code incredibly fast. But AI-generated code has predictable patterns that introduce security vulnerabilities and maintainability issues:

### Common AI Code Issues

| Issue | Example | Risk |
|-------|---------|------|
| **SQL Injection** | `f"SELECT * FROM users WHERE id = {user_id}"` | CRITICAL |
| **Hardcoded Secrets** | `api_key = "sk_live_abc123..."` | HIGH |
| **Magic Numbers** | `timeout = 300` | LOW |
| **Empty Except** | `except: pass` | MEDIUM |
| **Resource Leaks** | `open(file).read()` | MEDIUM |

---

## The Solution: PyNEAT

PyNEAT is an **AI-Generated Code Preprocessor** that automatically detects and fixes these issues:

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│ AI Generates│   →     │   PyNEAT   │   →     │ Clean Code │
│   Code      │         │   Cleans   │         │   Ready    │
└─────────────┘         └─────────────┘         └─────────────┘
                                ↑
                                ↓
                    ┌───────────────────────┐
                    │   PYNAGENT Markers    │
                    │  (AI-to-AI Protocol)  │
                    └───────────────────────┘
```

---

## Features

### Security Scanning (50+ Rules)

| Severity | Count | Examples |
|----------|-------|----------|
| CRITICAL | 9 | SQL injection, command injection, RCE |
| HIGH | 10 | Hardcoded secrets, weak crypto |
| MEDIUM | 20 | SSRF, XSS, open redirect |
| LOW | 10 | Information disclosure |
| INFO | 10 | Best practice hints |

### AI Bug Detection

- **Magic Numbers**: Replace `300` with `TIMEOUT_SECONDS`
- **Empty Except**: Add proper error handling
- **Resource Leaks**: Add context managers
- **Naming Inconsistencies**: Detect `userId` vs `user_id`
- **Code Duplication**: Find repeated code patterns

### Agent-to-Agent Handoff

PyNEAT generates **PYNAGENT markers** that other AI editors can read:

```python
import os  # PYNAGENT: {"id":"PYN-001","type":"unused_import","fix":"Remove"}
```

---

## Quick Demo

### Before PyNEAT

```python
# SQL Injection - CRITICAL
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# Hardcoded Secret - HIGH
api_key = "sk_live_abc123xyz789secret"

# Magic Number - LOW
timeout = 300

# Empty Except - MEDIUM
try:
    risky_operation()
except:
    pass
```

### After PyNEAT

```python
# Parameterized Query - SAFE
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))

# Environment Variable - SAFE
api_key = os.environ.get("API_KEY")

# Named Constant - CLEAR
REQUEST_TIMEOUT_SECONDS = 300  # 5 minutes
timeout = REQUEST_TIMEOUT_SECONDS

# Proper Error Handling - ROBUST
try:
    risky_operation()
except Exception as e:
    logger.error(f"Operation failed: {e}")
    raise
```

---

## Installation

```bash
pip install pyneat-cli
```

With Rust acceleration (10x faster):

```bash
pip install pyneat-cli
# Rust binary downloads automatically
```

---

## Usage

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

**VS Code**: [Install from Marketplace](vscode:extension/pyneat.pyneat)
**Neovim**: `use 'pyneat/pyneat-vim'`
**JetBrains**: [Install from Marketplace](#)

---

## IDE Integration

### VS Code

```bash
code --install-extension pyneat.pyneat
```

Features:
- Real-time diagnostics
- Quick fix suggestions
- Save-on-clean option
- Problems panel integration

### Neovim

```lua
use 'pyneat/pyneat-vim'
```

Features:
- LSP integration
- Quickfix list
- ALE/Neovim LSP support
- Telescope integration

### JetBrains

Features:
- Tool window
- Quick fix intentions
- Action menu integration
- Backup management

---

## Architecture

PyNEAT uses a layered architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                     User Interface                           │
│   CLI  │  VS Code  │  Neovim  │  JetBrains  │  LSP       │
└────────┴──────────┴──────────┴────────────┴────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Core Engine                                │
│   RuleEngine  │  AgentMarker  │  ManifestExporter           │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Rules Layer                               │
│   Security  │  AI Bugs  │  Quality  │  Performance         │
└─────────────────────────────────────────────────────────────┘
```

---

## Safety First

PyNEAT protects your code with **7 layers of safety**:

1. **AST Validation**: Validates syntax before/after
2. **Semantic Guard**: Ensures meaning is preserved
3. **Safe Transform**: Uses LibCST for safe modifications
4. **Backup**: Creates `.pyneat.bak` before changes
5. **Scope Guard**: Only modifies declared scopes
6. **Type Shield**: Optional mypy verification
7. **Final Verify**: Confirms changes are correct

---

## Performance

| Metric | Value |
|--------|-------|
| Cold Start | ~40ms |
| Warm Run | ~10ms |
| Memory | ~0.7MB per file |
| Cache Hit | 98%+ |

---

## Testimonials

> "PyNEAT caught 50+ security issues in our AI-generated code that we would have missed."
> — Engineering Team

> "The Agent-to-Agent Handoff is a game-changer for our multi-AI workflow."
> — DevOps Lead

---

## License

GNU Affero General Public License v3 (AGPLv3+)

For commercial licensing: n.khanhnam@gmail.com

---

## Links

- [Documentation](docs/)
- [GitHub](https://github.com/pyneat/pyneat)
- [PyPI](https://pypi.org/project/pyneat/)
- [Issue Tracker](https://github.com/pyneat/pyneat/issues)

---

*Built with love for the AI coding community*
