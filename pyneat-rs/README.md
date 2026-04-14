# PyNeat-RS

**High-performance Rust backend for PyNeat — AI-Generated Code Cleaner.**

> Production-ready scanner with tree-sitter AST parsing, 200+ rules, and auto-fix support across 9 languages.

**PyNeat-RS 3.0.0** — High-performance Rust backend for PyNeat.

## Features

- **9 Languages**: Python, JavaScript, TypeScript, Go, Java, Rust, C#, PHP, Ruby
- **200+ Rules**: 71 core + 120 language-specific + 18 AI security rules
- **AST-based**: Uses tree-sitter for precise code analysis
- **Auto-fix**: Safe, atomic code transformations with diff preview and conflict detection
- **Multi-language AST**: Unified LN-AST format enables universal rules
- **AI Security**: Dedicated scanner for AI-specific vulnerabilities
- **High performance**: Rust-powered with rayon parallel processing
- **Python bindings**: PyO3 integration for seamless Python usage
- **LSP Server**: Real-time IDE diagnostics via Language Server Protocol
- **SARIF 2.1.0**: Full compliance with GitHub Security Lab format

## Installation

### Build from source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/khanhnam-nathan/Pyneat.git
cd Pyneat/pyneat-rs
cargo build --release

# Run
./target/release/pyneat --help
```

### Python package

```bash
pip install pyneat[rust]
pyneat clean file.py --rust
```

## Usage

### Command Line

```bash
# Scan for security vulnerabilities
pyneat check file.py

# Clean AI-generated code patterns
pyneat clean file.py

# Dry-run with diff preview
pyneat clean file.py --dry-run --diff

# In-place edit with backup
pyneat clean file.py --in-place --backup

# Multi-language scan
pyneat check ./src

# Security scan with severity
pyneat check file.py --severity --cvss

# List all rules
pyneat rules

# Explain a specific rule
pyneat explain SEC-001

# Export SARIF report for GitHub Security
pyneat report ./src -f sarif -o security.sarif

# Fail CI on critical vulnerabilities
pyneat check ./src --fail-on critical
```

### As a Library

```rust
use pyneat_rs::{parse, all_security_rules, all_quality_rules};
use pyneat_rs::scanner::{JavaScriptScanner, PythonScanner};

// Parse code into AST
let tree = parse("const x = eval(userInput)").unwrap();

// Get all security rules
let rules = all_security_rules();
for rule in &rules {
    let findings = rule.detect(&tree, code);
    for finding in findings {
        println!("{}: {}", finding.rule_id, finding.problem);
    }
}

// Language-specific scanner
let scanner = JavaScriptScanner::new();
let ast = scanner.parse(code).unwrap();
let findings = scanner.detect(&ast, code);
```

## Rules

### Core Security Rules (SEC-001 to SEC-060)

| Rule | Severity | Description |
|------|----------|-------------|
| SEC-001 | Critical | Command Injection |
| SEC-002 | Critical | SQL Injection |
| SEC-003 | Critical | eval/exec Usage |
| SEC-004 | Critical | Unsafe Deserialization |
| SEC-005 | Critical | Path Traversal |
| SEC-006 | High | Hardcoded Secrets |
| SEC-007 | High | Weak Cryptography |
| SEC-008 | High | Insecure SSL/TLS |
| SEC-009 | High | XXE Vulnerability |
| SEC-010 | High | Unsafe YAML Loading |
| ... | ... | And 50 more |

### NEW Security Rules (SEC-061 to SEC-072)

| Rule | Severity | Description |
|------|----------|-------------|
| SEC-061 | Medium | Missing Subresource Integrity (SRI) |
| SEC-062 | High | Missing Content-Type Validation |
| SEC-063 | Medium | Missing Rate Limiting |
| SEC-064 | Critical | Weak JWT Secret Key |
| SEC-065 | Medium | Incomplete Session Destruction |
| SEC-066 | Medium | Timing Attack Vulnerability |
| SEC-067 | High | Weak Server-side Validation |
| SEC-068 | High | Client-side Price Calculation |
| SEC-069 | Medium | Dangerous Dependencies |
| SEC-070 | Medium | Missing Docker Vulnerability Scan |
| SEC-071 | High | Sensitive Data in JWT Payload |
| SEC-072 | Medium | Missing CSP Nonce for Inline Scripts |

### Extended Security Rules (SEC-073 to SEC-105+)

33 additional rules organized by OWASP Top 10 2021:

| Category | Rules | Description |
|----------|-------|-------------|
| A01: Broken Access Control | SEC-073 to SEC-075 | IDOR, horizontal/vertical privilege escalation |
| A02: Cryptographic Failures | SEC-076 to SEC-078 | Weak hash, ECB mode, hardcoded keys |
| A03: Injection | SEC-079 to SEC-082 | LDAP, XPath, SSTI, OS command injection |
| A05: Security Misconfiguration | SEC-083 to SEC-084 | Debug mode, CORS misconfiguration |
| A07: Authentication Failures | SEC-085 to SEC-086 | Weak password policy, brute force |
| A08: Software Integrity | SEC-087 to SEC-088 | Insecure deserialization, HTTP without TLS |
| A09: Security Logging | SEC-089 | Sensitive information in logs |
| A10: SSRF | SEC-090 | Server-side request forgery |
| Additional | SEC-091 to SEC-105 | XXE, race condition, ReDoS, unpredictable IDs, etc. |

### AI Security Rules (AI-010 to AI-070) — NEW

Dedicated scanner for AI-specific vulnerabilities:

| Rule | Severity | Description |
|------|----------|-------------|
| AI-010 | Critical | Prompt Injection — "ignore previous instructions" |
| AI-011 | Medium | Context Confusion — multi-turn conversation attacks |
| AI-012 | High | Proxy Injection — tool call injection in AI agents |
| AI-020 | Medium | Missing Confidence Threshold |
| AI-021 | High | Missing Fact Check for AI-generated content |
| AI-022 | High | Unguarded Sensitive Operations |
| AI-030 | Medium | Verbose Error Exposure |
| AI-031 | Medium | Missing API Rate Limit |
| AI-032 | Medium | Over-detailed System Information |
| AI-040 | Critical | Adversarial Input patterns |
| AI-041 | Medium | Unicode Homograph Attack |
| AI-050 | High | System Prompt Leakage |
| AI-051 | Medium | Tool Call Collision |
| AI-052 | High | Missing Output Guardrails |
| AI-053 | Medium | Toxic Output Risk |
| AI-060 | Low | Temperature Misuse |
| AI-061 | Medium | Context Window Mismanagement |
| AI-070 | High | Hallucinated API Calls |

### Core Quality Rules (7 rules)

| Rule | Description |
|------|-------------|
| QUAL-001 | Debug Code Detection |
| QUAL-002 | Redundant Expressions |
| QUAL-003 | TODO/FIXME Detection |
| QUAL-004 | Magic Numbers |
| QUAL-005 | Empty Except Blocks |

### Language-Specific Rules (120 rules)

| Language | Security | Quality | Total |
|----------|----------|---------|-------|
| JavaScript | 20 | 6 | 26 |
| Go | 17 | 2 | 19 |
| C# | 16 | 6 | 22 |
| PHP | 14 | 6 | 20 |
| Ruby | 6 | 6 | 12 |
| Rust | 3 | 8 | 11 |
| Java | 0 | 6 | 6 |
| TypeScript | (via JS) | 4 | 4 |

## Architecture

### 4-Layer Pipeline

```
┌─────────────────────────────────────────┐
│  Layer 1: Source Files                  │
└─────────────────┬───────────────────────┘
                  ▼
┌─────────────────────────────────────────┐
│  Layer 2: Language-Specific Parsers     │
│  (tree-sitter for each language)         │
└─────────────────┬───────────────────────┘
                  ▼
┌─────────────────────────────────────────┐
│  Layer 3: LN-AST (Language-Neutral AST) │
│  Unified JSON format for all languages   │
└─────────────────┬───────────────────────┘
                  ▼
┌─────────────────────────────────────────┐
│  Layer 4: Universal Rule Engine          │
│  Shared rules work on LN-AST patterns     │
└─────────────────────────────────────────┘
```

### Key Components

- **LN-AST**: Language-neutral AST that normalizes all 9 languages into a common representation
- **Fixer**: Atomic, conflict-aware code transformation engine with syntax validation
- **Diff**: Unified diff generation for dry-run previews
- **AI Security Scanner**: Dedicated module for AI-specific vulnerabilities
- **SARIF Writer**: Full SARIF 2.1.0 export for GitHub Security Lab
- **PyO3 bindings**: Seamless Python integration
- **LSP Server**: Real-time IDE diagnostics

### LN-AST Structure

```rust
pub struct LnAst {
    pub language: String,
    pub source_hash: String,
    pub functions: Vec<LnFunction>,
    pub classes: Vec<LnClass>,
    pub imports: Vec<LnImport>,
    pub assignments: Vec<LnAssignment>,
    pub calls: Vec<LnCall>,
    pub strings: Vec<LnString>,
    pub comments: Vec<LnComment>,
    pub catch_blocks: Vec<LnCatchBlock>,
    pub todos: Vec<LnTodo>,
    pub deep_nesting: Vec<LnDeepNesting>,
}
```

### Fix Engine

```rust
pub struct FixRange {
    pub start: Position,
    pub end: Position,
    pub replacement: String,
    pub rule_id: String,
}

pub struct FixResult {
    pub code: String,
    pub applied: Vec<String>,
    pub conflicts: Vec<FixConflict>,
    pub errors: Vec<String>,
}

// Key functions
pub fn apply_multiple_fixes(code: &str, fixes: Vec<FixRange>) -> FixResult
pub fn resolve_conflicts(fixes: &mut Vec<FixRange>)
pub fn check_fix_safety(code: &str, fix: &FixRange) -> bool
```

## CI/CD Integrations — NEW

### GitHub Security Lab

```bash
pyneat report ./src -f sarif -o security.sarif
```

Upload via GitHub Actions or `gh code scanning upload`:

```bash
gh code-scanning upload --sarif security.sarif --repo owner/repo
```

### GitLab SAST

```bash
pyneat report ./src -f gitlab-sast -o gl-sast.json
```

### SonarQube

```bash
pyneat report ./src -f sonarqube -o sonar-report.json
```

## SARIF 2.1.0 Export

Full SARIF 2.1.0 support with:

- CWE and OWASP mappings
- CVSS 3.1 scoring
- Fix suggestions in `fixes` array
- Supporting files and code flow
- Tool configuration export

```rust
pub struct SarifBuilder {
    pub tool_name: String,
    pub tool_version: String,
    pub rules: Vec<SarifRule>,
    pub results: Vec<SarifResult>,
}

impl SarifBuilder {
    pub fn new() -> Self { ... }
    pub fn add_result(&mut self, result: SarifResult) { ... }
    pub fn build(&self) -> String { ... }
}

pub struct SarifResult {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    pub location: SarifLocation,
    pub fix: Option<SarifFix>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub cvss: Option<f32>,
}
```

## LSP Server — NEW

Run PyNeat as a Language Server for real-time IDE diagnostics:

```bash
pyneat lsp --port 8765
```

Configuration:

```rust
pub struct LspConfig {
    pub severity_threshold: String,  // default: "warning"
    pub scan_on_save: bool,          // default: true
    pub debounce_ms: u64,             // default: 500
    pub enable_real_time: bool,       // default: false
    pub enabled_rules: Vec<String>,   // empty = all
}
```

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_parse_simple_code
```

## Contributing

Issues and PRs welcome! Please see [CONTRIBUTING.md](../../CONTRIBUTING.md).

## License

AGPL-3.0-or-later — same as PyNeat Python version.
