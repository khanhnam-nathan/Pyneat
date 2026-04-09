# PyNEAT Unified Architecture

This document describes the unified architecture of PyNEAT, showing how all components connect and work together.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              User Layer                                      │
│                                                                             │
│   Human Developer                                                           │
│       │                                                                     │
│       ▼                                                                     │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                    IDE Layer (User Interface)                         │  │
│   │                                                                       │  │
│   │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │  │
│   │   │  VS Code     │  │   Neovim    │  │  JetBrains   │             │  │
│   │   │  Extension   │  │   (Lua)     │  │   Plugin     │             │  │
│   │   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘             │  │
│   │          │                 │                 │                       │  │
│   └──────────┼─────────────────┼─────────────────┼───────────────────────┘  │
│              │                 │                 │                          │
│              └─────────────────┼─────────────────┘                          │
│                                ▼                                           │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                Plugin Interface Layer                                  │  │
│   │                                                                       │  │
│   │   ┌──────────────────┐  ┌──────────────────┐  ┌───────────────────┐  │  │
│   │   │   LSP Server     │  │   CLI (Click)   │  │   REST API        │  │  │
│   │   │  (JSON-RPC)     │  │                 │  │   (FastAPI)       │  │  │
│   │   │                  │  │                  │  │                   │  │  │
│   │   │  - diagnostics   │  │  - clean        │  │  - analyze        │  │  │
│   │   │  - code_action  │  │  - check        │  │  - fix            │  │  │
│   │   │  - hover        │  │  - manifest     │  │  - export         │  │  │
│   │   │  - formatting   │  │  - verify       │  │                   │  │  │
│   │   └────────┬────────┘  └────────┬───────┘  └─────────┬─────────┘  │  │
│   │            │                   │                     │             │  │
│   └────────────┼───────────────────┼─────────────────────┼─────────────┘  │
│                │                   │                     │                 │
│                └───────────────────┼─────────────────────┘                 │
│                                    ▼                                        │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                    Core Engine Layer                                  │  │
│   │                                                                       │  │
│   │   ┌─────────────────────────────────────────────────────────────┐    │  │
│   │   │                    RuleEngine                                  │    │  │
│   │   │                                                               │    │  │
│   │   │   ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐     │    │  │
│   │   │   │  Security   │  │    AI Bug   │  │      Code       │     │    │  │
│   │   │   │   Rules     │  │   Patterns  │  │    Quality      │     │    │  │
│   │   │   │  SEC-001~   │  │   AI-*     │  │    QUAL-*      │     │    │  │
│   │   │   │   SEC-059   │  │             │  │                 │     │    │  │
│   │   │   └─────────────┘  └─────────────┘  └─────────────────┘     │    │  │
│   │   │                                                               │    │  │
│   │   └─────────────────────────────────────────────────────────────┘    │  │
│   │                                                                       │  │
│   │   ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐     │  │
│   │   │ AgentMarker │  │  Manifest   │  │    7-Layer Protection   │     │  │
│   │   │             │  │  Exporter   │  │                         │     │  │
│   │   │  - marker_id│  │             │  │  1. AST Validation      │     │  │
│   │   │  - issue_type│ │  - JSON     │  │  2. Semantic Guard     │     │  │
│   │   │  - severity │  │  - SARIF    │  │  3. Safe Transform    │     │  │
│   │   │  - hint     │  │  - GJSON    │  │  4. Backup & Rollback  │     │  │
│   │   │  - why      │  │  - Markdown │  │  5. Scope Guard       │     │  │
│   │   │  - fix      │  │             │  │  6. Type Shield       │     │  │
│   │   └─────────────┘  └─────────────┘  │  7. Final Verify      │     │  │
│   │                                      └─────────────────────────┘     │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                    Integration Layer                                   │  │
│   │                                                                       │  │
│   │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │  │
│   │   │   PyO3       │  │   LibCST     │  │    Rust     │             │  │
│   │   │  Bindings    │  │  Parser      │  │   Binary    │             │  │
│   │   └──────────────┘  └──────────────┘  └──────────────┘             │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Descriptions

### 1. User Layer

The human developer interacts with PyNEAT through their preferred IDE or command line.

### 2. IDE Layer

| IDE | Implementation | Features |
|-----|----------------|----------|
| **VS Code** | TypeScript Extension | Commands, Diagnostics, CodeLens, Problem Matchers |
| **Neovim** | Lua Plugin | Commands, LSP, ALE, Telescope, Quickfix |
| **JetBrains** | Kotlin Plugin | Actions, Tool Window, Quick Fixes |
| **CLI** | Click Commands | Full functionality via terminal |

### 3. Plugin Interface Layer

All IDEs connect through the same unified interface:

```python
# pyneat/plugin/__init__.py

class PyNEATCore:
    def analyze(self, source: str, path: str) -> List[PluginDiagnostic]:
        """Analyze source and return diagnostics."""
        ...

    def fix(self, source: str, path: str) -> str:
        """Fix issues and return cleaned code."""
        ...

    def export_manifest(self, path: Path, format: str) -> Path:
        """Export manifest for AI editors."""
        ...
```

### 4. Core Engine Layer

The heart of PyNEAT:

| Component | Description |
|-----------|-------------|
| **RuleEngine** | Orchestrates all rules and collects results |
| **AgentMarker** | Data model for issue markers |
| **ManifestExporter** | Exports issues in multiple formats |
| **7-Layer Protection** | Guards against accidental code damage |

### 5. Integration Layer

| Component | Purpose |
|-----------|---------|
| **PyO3 Bindings** | Rust-Python interop |
| **LibCST Parser** | Python AST parsing and transformation |
| **Rust Binary** | High-performance security scanning |

## Data Flow

### Analysis Flow

```
User opens Python file in IDE
        │
        ▼
LSP sends textDocument/didOpen
        │
        ▼
PyNEAT LSP Server receives content
        │
        ▼
RuleEngine.analyze_file()
        │
        ├──► Security Rules (SEC-001 ~ SEC-059)
        │
        ├──► AI Bug Patterns (AI-*)
        │
        └──► Code Quality Rules (QUAL-*)
        │
        ▼
AgentMarker objects created
        │
        ▼
LSP diagnostics published
        │
        ▼
IDE shows problems panel
```

### Fix Flow

```
User runs PyNEAT Clean command
        │
        ▼
CLI or IDE action triggered
        │
        ▼
RuleEngine.process_file()
        │
        ▼
7-Layer Protection activated
        │
        ├──► Layer 1: AST Validation
        │
        ├──► Layer 2: Semantic Guard
        │
        ├──► Layer 3: Safe Transform
        │
        ├──► Layer 4: Backup
        │
        ├──► Layer 5: Scope Guard
        │
        ├──► Layer 6: Type Shield
        │
        └──► Layer 7: Final Verify
        │
        ▼
Backup created (.pyneat.bak)
        │
        ▼
Code transformed
        │
        ▼
Result written to file
```

### Manifest Export Flow

```
PyNEAT scan completes
        │
        ▼
AgentMarkers collected
        │
        ▼
ManifestExporter.run()
        │
        ├──► JSON: .pyneat.manifest.json
        │
        ├──► SARIF: GitHub Code Scanning
        │
        ├──► CodeClimate: PR Reviews
        │
        └──► Markdown: Human-readable
        │
        ▼
AI editors read markers
        │
        ▼
PYNAGENT comments added to source
```

## File Structure

```
pyneat/
├── __init__.py              # Package entry
├── __main__.py              # python -m pyneat
├── cli.py                   # CLI commands (Click)
├── lsp.py                   # LSP server implementation
│
├── core/
│   ├── engine.py            # RuleEngine (main processor)
│   ├── types.py             # AgentMarker, CodeFile, etc.
│   ├── manifest.py          # ManifestExporter, MarkerParser
│   ├── marker_cleanup.py     # Marker cleanup logic
│   ├── semantic_guard.py    # Semantic diff protection
│   ├── type_shield.py       # Type checking
│   └── scope_guard.py       # Scope analysis
│
├── plugin/
│   └── __init__.py          # Unified plugin interface
│
├── rules/
│   ├── base.py              # Rule base class
│   ├── security.py           # Security rules
│   ├── ai_bugs.py           # AI bug patterns
│   ├── quality.py           # Code quality rules
│   ├── deadcode.py          # Dead code detection
│   ├── unused.py            # Unused imports
│   └── ... (more rules)
│
├── tools/
│   ├── github_fuzz/         # GitHub fuzzing tool
│   └── security/            # Security tools
│
└── scanner/
    └── rust_scanner.py      # Rust scanner wrapper

pyneat-rs/                   # Rust accelerator
├── src/
│   ├── lib.rs              # PyO3 bindings
│   ├── scanner.rs          # Security scanner
│   └── rules/              # Rust rules
└── Cargo.toml

vscode-extension/            # VS Code extension
├── src/
│   └── extension.ts
└── package.json

vim-plugin/                  # Neovim plugin
├── lua/
│   ├── pyneat.lua
│   └── pyneat-lsp.lua
└── README.md

jetbrains-plugin/           # JetBrains plugin
├── src/main/kotlin/
│   └── com/pyneat/
│       ├── PyneatPlugin.kt
│       ├── actions/
│       └── services/
└── build.gradle.kts
```

## Communication Protocols

### LSP Protocol

PyNEAT LSP server implements these methods:

| Method | Direction | Description |
|--------|-----------|-------------|
| `initialize` | Client→Server | Initialize server |
| `textDocument/didOpen` | Client→Server | File opened |
| `textDocument/didChange` | Client→Server | File modified |
| `textDocument/diagnostic` | Client→Server | Pull diagnostics |
| `textDocument/codeAction` | Client→Server | Request fixes |
| `textDocument/publishDiagnostics` | Server→Client | Push diagnostics |
| `workspace/executeCommand` | Bidirectional | Run commands |

### PYNAGENT Protocol

PYNAGENT markers are embedded in source code:

```python
# PYNAGENT: {"id":"PYN-001","type":"unused_import","severity":"medium",
#            "line":10,"hint":"Remove unused import",
#            "can_auto_fix":true,"fix":"Remove"}
import os

def main():
    pass
```

## Configuration

### Global Config

```python
# ~/.pyneat/config.toml
[pyneat]
enable_security = true
enable_ai_bugs = true
export_format = "json"

[pyneat.security]
min_severity = "medium"

[pyneat.ide]
auto_scan = true
show_on_save = false
```

### Per-Project Config

```toml
# pyproject.toml or .pyneat.toml
[tool.pyneat]
enable_security = true
enable_ai_bugs = false
export_format = "sarif"

[tool.pyneat.security]
min_severity = "high"

[tool.pyneat.ignore]
files = ["tests/*.py", "**/migrations/*.py"]
rules = ["SEC-001", "QUAL-005"]
```

## Performance

| Metric | Value |
|--------|-------|
| Cold Start | ~40ms |
| Warm Run | ~10ms |
| Memory | ~0.7MB per file |
| Cache Hit | 98%+ |

## Security

PyNEAT is designed with safety in mind:

1. **Backup First**: Always creates `.pyneat.bak` before modifying
2. **Semantic Guard**: Validates AST semantics before/after
3. **Scope Guard**: Only modifies declared scopes
4. **Type Shield**: Optional mypy verification
5. **Rollback**: Can restore from backup on failure

## Extending PyNEAT

### Adding a New Rule

```python
# pyneat/rules/my_rule.py
from pyneat.rules.base import Rule, RuleConfig, TransformationResult

class MyRule(Rule):
    name = "my-rule"
    description = "My custom rule"

    def check(self, node, context):
        # Check logic
        if issue_found:
            return TransformationResult(
                found_issue=True,
                message="Issue found",
                fix=lambda: fixed_code,
            )
        return None

    def fix(self, node, context):
        # Fix logic
        return fixed_code
```

### Adding a New IDE Plugin

```python
# In your plugin, use the unified interface:
from pyneat.plugin import PyNEATCore

core = PyNEATCore()
diagnostics = core.analyze(source_code, file_path)

for diag in diagnostics:
    display_in_ide(diag)
```

## Related Documents

- [Agent-to-Agent Protocol](agent-to-agent-protocol.md)
- [Security Rules](../pyneat/rules/security.py)
- [API Reference](api.md)
- [Quick Start](quickstart.md)
