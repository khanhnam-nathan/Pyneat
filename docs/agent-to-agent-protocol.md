# PyNEAT Agent-to-Agent Protocol

> **The killer feature that makes PyNEAT unique.**

## Overview

PyNEAT's Agent-to-Agent Handoff system enables seamless collaboration between different AI coding assistants. When PyNEAT scans code, it generates **PYNAGENT markers** that other AI editors can read to understand the context and continue fixing issues.

```
┌─────────────┐    PyNEAT Scan    ┌─────────────┐    PYNAGENT     ┌─────────────┐
│   Human     │ ────────────────→ │   PyNEAT    │ ──────────────→ │  AI Editor  │
│  Developer  │                   │   Engine    │                 │   (Cursor/  │
│            │ ← ─────────────── │             │ ← ───────────── │  Copilot/   │
└─────────────┘   Cleaned Code   └─────────────┘   User Intent    │  Claude)    │
                                                                       └─────────────┘
```

## The Problem

AI coding assistants often work in isolation:

1. **AI generates code** with security issues
2. **Another AI tries to help** but doesn't understand context
3. **User gets confused** by conflicting AI suggestions
4. **Issues remain** because AI doesn't know what other AI did

## The Solution

**PYNAGENT markers create a shared language between AIs:**

1. PyNEAT scans code and adds machine-readable markers
2. Next AI reads markers and understands context
3. AI asks user about intent (if needed)
4. AI fixes correctly based on marker hints

## PYNAGENT Format

PYNAGENT markers are embedded as comments in source code:

```python
# PYNAGENT: {"id":"PYN-001","type":"unused_import","severity":"medium",
#            "confidence":0.95,"file":"app.py","line":10,
#            "hint":"Remove unused import",
#            "can_auto_fix":true}
import os

def main():
    pass
```

### Marker Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique marker ID (e.g., "PYN-001") |
| `type` | string | Issue type (see below) |
| `severity` | string | critical/high/medium/low/info |
| `confidence` | float | Detection confidence 0.0-1.0 |
| `file` | string | Source file path |
| `line` | int | Line number (1-indexed) |
| `hint` | string | Short hint for AI |
| `why` | string | Explanation of the issue |
| `can_auto_fix` | bool | Whether PyNEAT can fix this |
| `fix` | string | Suggested fix (optional) |
| `requires_user_input` | bool | Whether user needs to decide |
| `related` | array | IDs of related markers |

### Issue Types

| Type | Description | Severity |
|------|-------------|----------|
| `sql_injection` | SQL injection vulnerability | critical |
| `command_injection` | OS command injection | critical |
| `eval_exec` | Dangerous eval/exec usage | critical |
| `hardcoded_secret` | API key or password in code | high |
| `weak_crypto` | MD5/SHA1 for security | high |
| `yaml_unsafe` | YAML without SafeLoader | high |
| `unused_import` | Import not used | low |
| `magic_number` | Number without constant | low |
| `empty_except` | Silent exception swallowing | medium |
| `resource_leak` | Unclosed resource | medium |

## Manifest Formats

PyNEAT can export markers in multiple formats:

### JSON (Default)

```json
{
  "version": "1.0",
  "source_file": "app.py",
  "generated_at": "2026-04-09T12:00:00Z",
  "tool": "PyNEAT",
  "tool_version": "2.2.0",
  "total_issues": 3,
  "markers": [
    {
      "marker_id": "PYN-001",
      "issue_type": "sql_injection",
      "severity": "critical",
      "confidence": 0.95,
      "line": 10,
      "hint": "Use parameterized queries",
      "can_auto_fix": true
    }
  ]
}
```

### SARIF (GitHub Code Scanning)

```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "PyNEAT",
        "version": "2.2.0"
      }
    },
    "results": [{
      "ruleId": "PYNEAT/SEC-002",
      "level": "error",
      "message": {
        "text": "SQL injection at line 10"
      }
    }]
  }]
}
```

### Markdown (Human-readable)

```markdown
# PyNEAT Security Report

| ID | Severity | Type | Line | Hint |
|----|----------|------|------|------|
| PYN-001 | critical | sql_injection | 10 | Use parameterized queries |
```

## Integration Examples

### Cursor AI

When Cursor AI opens a file with PYNAGENT markers:

1. Cursor reads the markers
2. Cursor shows markers in the problems panel
3. Cursor can suggest fixes based on `hint` field
4. User confirms or modifies the fix

```
┌─────────────────────────────────────────┐
│  Problems (PyNEAT)                      │
├─────────────────────────────────────────┤
│  ⚠ PYN-001: sql_injection (critical)   │
│     Line 10: Use parameterized queries │
│     [Fix] [Ignore] [Ask User]          │
└─────────────────────────────────────────┘
```

### GitHub Copilot

Copilot can use PYNAGENT markers to:

1. Avoid generating code with known issues
2. Suggest fixes for detected problems
3. Learn from PyNEAT's patterns

### Claude Code

Claude Code can:

1. Read PYNAGENT markers to understand context
2. Ask clarifying questions (using `requires_user_input`)
3. Generate contextually appropriate fixes

## CLI Usage

### Export Manifest

```bash
# JSON manifest (default)
pyneat manifest app.py

# SARIF for GitHub Actions
pyneat manifest app.py --format sarif

# Markdown report
pyneat manifest app.py --format markdown

# For AI editors
pyneat manifest app.py --format gjson
```

### Verify and Cleanup

```bash
# Check markers are still valid
pyneat verify app.py

# Remove resolved markers
pyneat verify app.py --cleanup
```

### IDE Integration

```bash
# Start LSP server for real-time markers
python -m pyneat.lsp

# Or use the CLI in watch mode
pyneat check app.py --watch
```

## Use Cases

### 1. Multi-AI Workflow

```
Human → Cursor AI (generates) → PyNEAT (marks) → Claude Code (fixes)
```

### 2. CI/CD Pipeline

```
GitHub Actions
  ↓
PyNEAT Security Scan
  ↓
SARIF Export
  ↓
GitHub Security Alerts
  ↓
Developer Reviews
  ↓
Claude Code Fixes
```

### 3. Code Review

```
PR Opened
  ↓
PyNEAT Scan
  ↓
PYNAGENT Markers Added
  ↓
Reviewer Sees Issues
  ↓
Reviewer / AI Fixes
  ↓
PR Merged
```

### 4. IDE Real-time

```
Developer Types Code
  ↓
IDE Sends to PyNEAT LSP
  ↓
PyNEAT Detects Issues
  ↓
PYNAGENT Markers Added
  ↓
AI Assistant Reads Markers
  ↓
AI Suggests Fixes
```

## Advanced Features

### Related Markers

Issues can be grouped together:

```python
# PYNAGENT: {"id":"PYN-001","type":"unused_import","related":["PYN-002","PYN-003"]}
import os

# PYNAGENT: {"id":"PYN-002","type":"unused_class","related":["PYN-001"]}
# PYNAGENT: {"id":"PYN-003","type":"dead_branch","related":["PYN-001"]}
```

### User Input Required

Some issues need human judgment:

```python
# PYNAGENT: {"id":"PYN-101","type":"race_condition",
#            "requires_user_input":true,
#            "hint":"Consider adding a lock",
#            "why":"Shared state modified without synchronization"}
shared_dict[key] = value
```

### Auto-fix Available

Markers show if PyNEAT can fix automatically:

```python
# PYNAGENT: {"id":"PYN-002","type":"magic_number",
#            "can_auto_fix":true,
#            "fix":"Replace with DISCOUNT_RATE constant",
#            "auto_fix_available":true}
price * 0.15  # Magic number
```

## Configuration

### Enable Marker Grafting

```bash
pyneat clean app.py --graft-markers
```

### Marker Format

```bash
# Default format
pyneat clean app.py --marker-format compact

# Expanded format with more details
pyneat clean app.py --marker-format expanded
```

### Related Markers

```bash
# Enable related marker detection
pyneat clean app.py --enable-related

# Set max related markers per issue
pyneat clean app.py --max-related 5
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ManifestExporter                          │
│                                                              │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐    │
│   │ AgentMarker │→ │ to_json()  │→ │ .pyneat.manifest│    │
│   │             │  │ to_sarif() │  │ .pyneat.sarif   │    │
│   │             │  │ to_md()    │  │ .pyneat.md      │    │
│   └─────────────┘  └─────────────┘  └─────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    MarkerParser                              │
│                                                              │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐    │
│   │ from_source │← │ PYNAGENT    │← │ # PYNAGENT: {...}│    │
│   │             │  │ regex       │  │                 │    │
│   │ from_manifest│← │            │← │ .pyneat.manifest│    │
│   └─────────────┘  └─────────────┘  └─────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Future Enhancements

- **LLM Integration**: Use markers to fine-tune AI models
- **Marker Analytics**: Track which issues AI fixes vs human fixes
- **Collaborative Markers**: Multiple AIs can add to the same marker set
- **Cross-Language Support**: Similar markers for JavaScript, TypeScript, etc.

## Related Documents

- [Unified Architecture](unified-architecture.md)
- [Security Rules](../pyneat/rules/security.py)
- [Quick Start](quickstart.md)
