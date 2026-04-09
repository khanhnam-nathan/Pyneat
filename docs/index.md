# PyNEAT Documentation

Welcome to the PyNEAT documentation — AI Python Code Cleaner!

## Introduction

PyNEAT is a powerful Python code cleaning tool that uses AST to analyze and refactor code. PyNEAT automatically:

- Removes artifacts from AI-generated code
- Detects and fixes security vulnerabilities (50+ rules)
- Cleans up poor-quality code
- Improves code performance

## Key Features

### 7-Layer Protection

PyNEAT protects your code with 7 layers:

1. **AST Validation** - Syntax checking
2. **Semantic Diff Guard** - Compare semantics before/after
3. **Safe Transform API** - Safe LibCST usage
4. **Backup & Rollback** - Backup and restore
5. **Scope Guard** - Scope checking
6. **Type Shield** - Type checking
7. **Final Verification** - Final verification

### Security Scanner

50+ security rules from SEC-001 to SEC-059:

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 9 | Command injection, SQL injection, RCE |
| HIGH | 10 | Hardcoded secrets, weak crypto |
| MEDIUM | 20 | SSRF, XSS, open redirect |
| LOW | 10 | Information disclosure |
| INFO | 10 | Best practice hints |

## Quick Links

- [Quick Start](quickstart.md) - Get started quickly
- [Rules Catalog](rules.md) - Full list of 50+ rules
- [API Reference](api.md) - API documentation
- [Case Studies](case_studies.md) - Real-world examples and quantitative results
- [Benchmark Results](../benchmark_results.json) - Performance and benchmark data
- [GitHub Repository](https://github.com/pyneat/pyneat)

## Installation

```bash
pip install pyneat-cli
```

With all features:
```bash
pip install pyneat-cli[all]
```

## Ecosystem

| Tool | Status | Description |
|------|--------|-------------|
| GitHub Actions | ✅ | CI/CD integration |
| GitLab CI | ✅ | GitLab integration |
| VS Code | 🚧 | Extension (coming soon) |
| Neovim/Vim | 🚧 | Plugin (coming soon) |
| LSP | 🚧 | Language Server (coming soon) |

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to contribute.

## License

MIT License — see [LICENSE](../LICENSE).
