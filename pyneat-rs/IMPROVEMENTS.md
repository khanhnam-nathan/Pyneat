# Rust Accelerator Improvements

This document outlines planned improvements for the PyNeat Rust accelerator (`pyneat-rs`).

## Current Status

The Rust accelerator is in **BETA** version with:
- Tree-sitter parsing for 9 languages (Python, JavaScript, TypeScript, Go, Java, Rust, C#, PHP, Ruby)
- Rayon parallel processing
- PyO3 bindings for Python integration
- 3 core rules: IsNotNoneRule, FStringRule, DeadCodeRule

## Planned Improvements

### 1. Parallel Processing for Batch Operations

Currently batch processing uses Python's `ThreadPoolExecutor`. We can leverage Rayon for Rust-level parallelism.

```rust
// Before: Sequential in Python
def clean_dir(self, path: Path, pattern: str = "*.py"):
    files = list(path.rglob(pattern))
    for file in files:
        self.process_file(file)  # Sequential

// After: Parallel in Rust
// pyneat-rs/src/scanner/batch.rs
pub fn process_directory_parallel(
    &self,
    path: &Path,
    pattern: &str,
    workers: usize,
) -> Result<BatchResult> {
    // Use rayon for parallel file processing
    files.par_iter()
        .map(|f| self.process_file(f))
        .collect()
}
```

### 2. Rule Matching in Rust

Move performance-critical rule matching to Rust:

- SQL injection detection
- Command injection detection
- Hardcoded secrets detection (regex patterns)

```rust
// pyneat-rs/src/rules/security/
mod sql_injection;
mod command_injection;
mod secrets;

pub trait SecurityRule {
    fn scan(&self, content: &str) -> Vec<SecurityFinding>;
}

pub struct SQLInjectionRule;
impl SecurityRule for SQLInjectionRule {
    fn scan(&self, content: &str) -> Vec<SecurityFinding> {
        let pattern = Regex::new(r"(cursor|db)\.execute\s*\(.*?\+").unwrap();
        pattern.find_iter(content)
            .map(|m| SecurityFinding {
                rule_id: "SEC-002",
                severity: Severity::Critical,
                line: content[..m.start()].matches('\n').count() as u32,
                ..Default::default()
            })
            .collect()
    }
}
```

### 3. Caching Layer for Parsed AST

Implement a multi-level cache:

```rust
// pyneat-rs/src/cache/mod.rs

pub struct ASTCache {
    // Level 1: In-memory LRU cache
    lru: HashMap<ContentHash, CachedAST>,
    // Level 2: Disk cache for large files
    disk_cache: PathBuf,
    max_memory_entries: usize,
}

impl ASTCache {
    pub fn get(&self, hash: &ContentHash) -> Option<&CachedAST> {
        // Check L1 first
        if let Some(ast) = self.lru.get(hash) {
            return Some(ast);
        }
        // Check disk cache
        self.load_from_disk(hash)
    }

    pub fn insert(&mut self, hash: ContentHash, ast: CachedAST) {
        if self.lru.len() >= self.max_memory_entries {
            // Evict LRU entry
            self.lru.pop_lru();
        }
        self.lru.insert(hash, ast);
    }
}
```

### 4. Additional Security Rules

Complete the security rule set:

| Rule | Status | Description |
|------|--------|-------------|
| SEC-001 Command Injection | Planned | os.system, subprocess shell=True |
| SEC-002 SQL Injection | Planned | String concatenation in queries |
| SEC-004 Pickle RCE | Planned | pickle.loads detection |
| SEC-010 Hardcoded Secrets | Planned | API keys, passwords |
| SEC-011 Weak Crypto | Planned | MD5, SHA1 detection |
| SEC-014 YAML Unsafe | Planned | yaml.load without SafeLoader |

### 5. Language Server Protocol (LSP) Integration

Support IDE integration:

```rust
// pyneat-rs/src/lsp/mod.rs

pub struct PyNeatLanguageServer {
    client: Arc<dyn LanguageClient>,
    engine: RuleEngine,
    cache: ASTCache,
}

impl LanguageServer for PyNeatLanguageServer {
    fn text_document_did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let content = params.text_document.text;
        // Parse and cache AST
        self.engine.parse(&content);
    }

    fn text_document_did_change(&self, params: DidChangeTextDocumentParams) {
        // Incrementally update AST
        self.engine.update(params.content_changes);
    }
}
```

## Implementation Priority

1. **High Priority**:
   - Parallel batch processing
   - Caching layer
   - SQL injection rule

2. **Medium Priority**:
   - Command injection rule
   - Hardcoded secrets rule
   - Weak crypto rule

3. **Low Priority**:
   - LSP integration
   - Additional security rules

## Performance Targets

| Operation | Python | Rust Target | Speedup |
|-----------|--------|------------|---------|
| Parse 10K line file | 50ms | 5ms | 10x |
| Batch 1000 files | 5min | 30s | 10x |
| Security scan | 100ms | 10ms | 10x |

## Contributing

To contribute to the Rust accelerator:

1. Fork the repository
2. Create a branch for your feature
3. Write tests in `tests/`
4. Ensure `cargo test` passes
5. Submit a PR

## Build Instructions

```bash
cd pyneat-rs

# Development build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Benchmark
cargo bench
```

## References

- [PyO3 Documentation](https://pyo3.rs/)
- [Tree-sitter](https://tree-sitter.github.io/tree-sitter/)
- [Rayon](https://rayon-rs.github.io/)
