# PyNEAT Core - Open Source (AGPL)

This is the open-source core of PyNEAT, licensed under AGPL-3.0.

## Features

- **Multi-language Support**: Python, JavaScript, TypeScript, Go, Java, Rust, C#, PHP, Ruby
- **Security Scanning**: 50+ built-in security rules
- **Quality Rules**: Code quality checks
- **Auto-fix**: Automatic code fixes for supported rules
- **Multiple Output Formats**: SARIF, JSON, Text, JUnit XML, CodeClimate
- **LSP Server**: Language Server Protocol for IDE integration
- **Python Bindings**: PyO3 integration for Python usage

## Building

```bash
cargo build --release
```

## Usage

### CLI
```bash
# Scan a file
./target/release/pyneat-core scan file.py

# List rules
./target/release/pyneat-core list-rules

# Check specific code
./target/release/pyneat-core check "import os; os.system('ls')"
```

### Python
```python
import pyneat_core

# Scan code
results = pyneat_core.scan_security("import os; os.system('ls')")
print(results)

# Parse LN-AST
ast = pyneat_core.parse_ln_ast("def foo(): pass", "python")
print(ast)
```

## License

This crate is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

See [LICENSE](../../LICENSE) for details.

## Advanced Features

For advanced features (semantic analysis, type validation, AI bug detection), see [pyneat-pro-engine](../pyneat-pro-engine/README.md).

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Copyright

Copyright (C) 2026 PyNEAT Authors.
