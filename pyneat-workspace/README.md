# PyNEAT Workspace

This workspace contains two Rust crates:

1. **pyneat-core** (AGPL-3.0) - Open source core scanner
2. **pyneat-pro-engine** (PROPRIETARY) - Advanced proprietary features

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PyNEAT Workspace                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  pyneat-core (AGPL-3.0)                            │ │
│  │  ├── Basic linting rules                            │ │
│  │  ├── Tree-sitter AST parsing                        │ │
│  │  ├── Multi-language support                         │ │
│  │  ├── SARIF/JSON output                           │ │
│  │  └── LSP server                                   │ │
│  │                                                     │ │
│  │  ↕ JSON IPC (stdin/stdout)                       │ │
│  │                                                     │ │
│  └─────────────────────────────────────────────────────┘ │
│                           ▲                               │
│                           │                               │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  pyneat-pro-engine (PROPRIETARY)                   │ │
│  │  ├── Semantic analysis engine                      │ │
│  │  ├── Type validation (mypy/pyright)               │ │
│  │  ├── AI bug detection                             │ │
│  │  ├── Dependency vulnerability scanning             │ │
│  │  ├── CVE/GHSA integration                        │ │
│  │  └── Advanced security rules                       │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Building

### Build Core Only
```bash
cargo build -p pyneat-core --release
```

### Build Pro Engine (requires license)
```bash
cargo build -p pyneat-pro-engine --release
```

### Build Both
```bash
cargo build --release
```

## Usage

### Core Only (Open Source)
```bash
./target/release/pyneat-core scan ./src

# List available rules
./target/release/pyneat-core list-rules

# Check Pro Engine status
./target/release/pyneat-core pro-status
```

### With Pro Engine
If `pyneat-pro-engine` binary is installed, it will be automatically detected and used for advanced features.

## License

- **pyneat-core**: AGPL-3.0-or-later
- **pyneat-pro-engine**: PROPRIETARY (requires separate license)

## Directory Structure

```
pyneat-workspace/
├── Cargo.toml              # Workspace configuration
├── pyneat-core/            # Open source core
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs        # Library exports
│   │   ├── bin/main.rs    # CLI binary
│   │   ├── protocol.rs    # IPC protocol types
│   │   └── pro_engine.rs  # Pro Engine integration
│   └── ...
│
└── pyneat-pro-engine/     # Proprietary engine
    ├── Cargo.toml
    ├── src/
    │   ├── main.rs        # Binary entry point
    │   ├── protocol.rs     # IPC protocol types
    │   ├── handlers.rs     # Request handlers
    │   ├── semantic.rs     # Semantic analysis
    │   ├── type_checker.rs # Type validation
    │   ├── ai_security.rs # AI bug detection
    │   ├── security_engine.rs # Extended security
    │   └── dependency.rs   # CVE/GHSA scanning
    └── ...
```
