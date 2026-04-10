# Changelog

All notable project changes will be documented in this file.

The project follows [Semantic Versioning](https://semver.org/) and [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2.2.1] - 2026-04-10

### Added

#### Auto Manifest Export Integration
- **Config-driven Export**: `export_manifest = true` in `[tool.pyneat]` section
- **Pre-commit Hook**: Auto-generate `.pyneat.manifest.json` on commit
- **GitHub Actions**: CI/CD job for automated manifest export on push/PR

#### Enhanced CLI
- `--export-manifest` flag for both `clean` and `clean-dir` commands
- Auto-export based on `pyproject.toml` configuration

## [2.2.0-beta] - 2026-04-09

### Added

#### Agent-to-Agent Handoff System
- **PYNAGENT Markers**: Machine-readable markers for AI editor handoff
- **Manifest Export**: JSON, SARIF 2.1.0, CodeClimate, Markdown formats
- **LSP Integration**: VS Code, Neovim compatible code actions
- **Marker Cleanup**: Automatic cleanup of resolved markers
- **Export CLI**: `pyneat manifest <file> --format sarif|json|md|gjson`
- **Verify CLI**: `pyneat verify --cleanup`

#### 10 New AI Bug Detection Rules
- **AI-BOUND**: Boundary Check - Unsafe array indexing without guards
- **AI-RES**: Resource Leak - open() without context, HTTP without timeout
- **AI-NAME**: Naming Inconsistency - userId vs user_id detection
- **AI-PARAM**: Fake Parameter - Hallucinated function parameters
- **AI-PKG**: Phantom Package - Non-existent PyPI package detection
- **AI-IO**: Redundant I/O - Repeated API calls within same function
- **CodeDuplicationRule**: Cross-file duplicate detection using AST normalization

#### AgentMarker Enhancements
- `end_line`: End line for multi-line markers
- `requires_user_input`: Flag for issues needing user decision
- `related_markers`: IDs of related markers for grouping

#### Tests
- 35 new tests for Agent-to-Agent system
- 26 new tests for AI bug detection rules
- Total: 458 tests passing

### Changed

- Version bumped to 2.2.0-beta
- AgentMarker now imported from `pyneat.core.types`
- Manifest export consolidated in `pyneat.core.manifest`

### Fixed

- AgentMarker forward reference in `types.py`
- Missing Optional import in `quality.py`, `unused.py`, `redundant.py`
- Regex pattern error in REDUNDANT_IO_PATTERNS

## [2.0.0-beta.2] - 2026-04-09

### Added

#### Rust Security Rules (SEC-001 ~ SEC-059)
- SEC-001: Command Injection Detection
- SEC-002: SQL Injection Detection
- SEC-003: Eval/Exec Usage Detection
- SEC-004: Deserialization RCE Detection
- SEC-005: Path Traversal Detection
- SEC-010: Hardcoded Secrets Detection
- SEC-011: Weak Cryptography Detection
- SEC-012: Insecure SSL/TLS Usage
- SEC-013: XXE (XML External Entity) Detection
- SEC-014: YAML Unsafe Load (Auto-fix available)
- SEC-015: Assert in Production
- SEC-016: Debug Mode Enabled
- SEC-017: CORS Wildcard
- SEC-018: JWT None Algorithm
- SEC-019: Weak Random for Security
- SEC-020: LDAP Injection
- SEC-021: Cross-Site Scripting (XSS)
- SEC-022: Server-Side Request Forgery (SSRF)
- SEC-023: Open Redirect
- SEC-024~SEC-034: Medium severity rules
- SEC-040~SEC-049: Low severity rules
- SEC-050~SEC-059: Info severity rules

#### Rust Quality Rules
- QUAL-001: Unused Import Detection
- QUAL-002: Redundant Expression Detection
- QUAL-003: Magic Number Detection
- QUAL-004: Empty Except Block Detection
- QUAL-005: Complex Function Detection

#### Rust Architecture Improvements
- Tree-sitter Python grammar integration
- Auto-fix system with fixer module
- Diff generation for code changes
- PyO3 extension module (cdylib)

#### Ecosystem Components
- **GitHub Actions**: CI/CD workflows (.github/workflows/)
- **GitLab CI**: GitLab CI templates (.gitlab-ci/)
- **Pre-commit Hooks**: Local and remote pre-commit configurations
- **VS Code Extension**: Full IDE integration with commands and diagnostics
- **LSP Server**: Language Server Protocol implementation for real-time analysis
- **JetBrains Plugin**: Gradle configuration for IntelliJ-based IDEs
- **Vim/Neovim Plugin**: Lua-based plugin with LSP integration

### Changed

#### Performance Improvements
- Rust binary built with LTO and strip symbols
- Parallel scanning with Rayon
- Pre-compiled regex patterns with OnceLock
- No GIL contention

### Fixed

- Cargo.toml output filename collision (bin vs lib)
- Tree-sitter parser integration

## [2.0.0-beta.1] - 2026-04-08

### Added

#### Documentation
- Created CHANGELOG.md to track version changes
- Created CONTRIBUTING.md with development guidelines
- Created CODE_OF_CONDUCT.md with community conduct rules

#### Rust Architecture (pyneat-rs)
- Initialized Rust project with PyO3 bindings
- Implemented 5 basic security rules (SEC-001 ~ SEC-005):
  - SEC-001: Command Injection Detection
  - SEC-002: SQL Injection Detection
  - SEC-003: Eval/Exec Usage Detection
  - SEC-004: Deserialization RCE Detection
  - SEC-005: Path Traversal Detection
- Parallel scanning with Rayon
- Pre-compiled regex patterns with OnceLock
- Benchmark suite for Python vs Rust performance comparison

#### New Directory Structure
```
pyneat-rs/
├── Cargo.toml
├── src/
│   ├── lib.rs          # PyO3 bindings
│   ├── main.rs         # CLI entry point
│   ├── scanner.rs      # Regex-based scanner
│   ├── rules.rs         # Rule definitions
│   └── findings.rs      # Finding struct
├── benches/
│   └── benchmark.rs
└── tests/
    └── test_scanner.rs
```

### Changed

#### Performance Improvements
- Regex patterns pre-compiled once and reused
- Parallel pattern matching with Rayon
- No GIL contention

### Planned for 2.0.0 (Full Release)

- [x] Tree-sitter Python grammar integration
- [x] Full 50+ security rules (SEC-001 ~ SEC-059)
- [x] Auto-fix system for common vulnerabilities
- [x] Quality rules (imports, naming, dead code)
- [ ] CLI integration with `--rust` flag
- [ ] Binary wheels for pip install pyneat-cli[rust]
- [ ] Windows wheels with proper Python 3.10+ support

## [2.0.0] - 2026-03-XX

### Added

#### New Rules
- `IsNotNoneRule` - Convert `x is not None` patterns
- `MagicNumberRule` - Detect and flag magic numbers
- `RangeLenRule` - Fix `range(len())` anti-pattern
- `DeadCodeRule` - Remove unused functions and classes via AST analysis
- `FStringRule` - Convert `.format()` to f-strings
- `TypingRule` - Suggest type annotations for functions without typing
- `MatchCaseRule` - Suggest converting if-elif chains to match-case (Python 3.10+)
- `DataclassSuggestionRule` - Suggest `@dataclass` for simple classes

#### Rule System
- Refactored comprehensive rule system with priority ordering
- Cleaner CI/CD workflow with lint and stress tests
- Enhanced isolated block processing for nested code
- Fixed Unicode encoding issues in CLI output

### Changed

- Refactored comprehensive rule system with priority ordering
- Added comprehensive test samples for real-world scenarios
- Cleaner CI/CD workflow with lint and stress tests
- Enhanced isolated block processing for nested code
- Fixed Unicode encoding issues in CLI output
- Fixed CI configuration to use proper Linux Python paths
- Fixed compileall verification for package integrity

### Removed

- Removed redundant test files for leaner test suite
- Simplified CI pipeline (single pytest run instead of multiple jobs)

## [1.0.0] - 2026-01-XX

### Added

- Initial release with core cleaning rules:
  - ImportCleaningRule
  - NamingConventionRule
  - RefactoringRule
  - DebugCleaner
  - CommentCleaner
- Security scanning with SecurityScannerRule
- Security registry with 50+ security rules (SEC-001 ~ SEC-059)
- CLI with Click framework
- Pre-commit hooks integration
- GitHub Actions workflow
- 7-layer protection system
- AST and CST caching
- Semantic guards
- Type shields
