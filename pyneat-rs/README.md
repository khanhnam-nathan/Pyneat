# PyNeat-RS

**High-performance Rust reimplementation of PyNeat Python code cleaner.**

> ⚠️ **BETA VERSION** - This is a pre-release. Expect bugs and breaking changes.

## Features

- 🚀 **Fast** - Written in Rust for maximum performance
- 🔒 **Safe** - Memory-safe with no runtime overhead
- 📦 **Portable** - Single binary, no dependencies needed
- 🎯 **Focused** - 3 core rules to start, more coming

## Installation

### Pre-built binaries (coming soon)

```bash
# Download from GitHub releases
```

### Build from source

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/khanhnam-nathan/Pyneat.git
cd Pyneat/pyneat-rs
cargo build --release

# Run
./target/release/pyneat --help
```

## Usage

### Command Line

```bash
# List available rules
pyneat rules

# Clean a file (default: IsNotNoneRule)
pyneat clean file.py

# Enable f-string conversion
pyneat clean file.py --enable-fstring

# Enable dead code removal
pyneat clean file.py --enable-deadcode

# In-place edit
pyneat clean file.py --in-place

# Multiple rules
pyneat clean file.py --in-place --enable-fstring --enable-deadcode
```

### As a Library

```rust
use pyneat_rs::{RuleEngine, clean_code};
use pyneat_rs::rules::{IsNotNoneRule, FStringRule, DeadCodeRule};

// Simple API
let result = clean_code("if x != None: pass", None);
assert_eq!(result, "if x is not None: pass");

// Advanced API
let mut engine = RuleEngine::new();
engine.add_rule(std::sync::Arc::new(IsNotNoneRule::new()));
engine.add_rule(std::sync::Arc::new(FStringRule::new()));

// Process a file
let result = engine.process_file("path/to/file.py".into());
```

## Rules

### Always On

| Rule | Description |
|------|-------------|
| `IsNotNoneRule` | Fixes `x != None` → `x is not None` |

### Optional (--enable-* flags)

| Flag | Rule | Description |
|------|------|-------------|
| `--enable-fstring` | FStringRule | Converts `.format()` to f-strings |
| `--enable-deadcode` | DeadCodeRule | Removes unused functions/classes |

## Roadmap

- [x] Core engine with rule plugin system
- [x] IsNotNoneRule (always on)
- [x] FStringRule (optional)
- [x] DeadCodeRule (optional)
- [ ] SecurityScannerRule (SQL injection, hardcoded secrets)
- [ ] PerformanceRule (inefficient patterns)
- [ ] CodeQualityRule (magic numbers, empty except)
- [ ] Python bindings via PyO3
- [ ] Language server protocol (LSP) integration

## Performance

PyNeat-RS is designed to be 10-50x faster than the Python version.

Benchmarks (coming soon):
- Single file processing
- Directory batch processing
- Memory usage comparison

## Contributing

Issues and PRs welcome! Please see [CONTRIBUTING.md](../../CONTRIBUTING.md).

## License

MIT License - same as PyNeat Python version.
