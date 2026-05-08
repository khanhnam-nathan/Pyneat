//! PyNeat Rust Security Scanner
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU Affero General Public License as published
//! by the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//! GNU Affero General Public License for more details.
//!
//! You should have received a copy of the GNU Affero General Public License
//! along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::collections::HashSet;

use regex::Regex;

use super::super::ln_ast::LnAst;
use super::super::base::{LangRule, LangFinding, LangFix};

/// Helper: get line byte offsets (0-indexed lines).
fn get_line_offsets(code: &str, line: usize) -> (usize, usize) {
    let mut current_line = 1;
    let mut line_start = 0;
    for (i, c) in code.char_indices() {
        if current_line == line {
            line_start = i;
            break;
        }
        if c == '\n' {
            current_line += 1;
        }
    }
    let mut line_end = line_start;
    for (i, c) in code[line_start..].char_indices() {
        if c == '\n' {
            line_end = line_start + i + 1;
            break;
        }
    }
    if line_end == line_start {
        line_end = code.len();
    }
    (line_start, line_end)
}

/// Helper: get full line text from line number (1-indexed)
fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|s| s.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-001: Command Injection via std::process::Command
// Severity: critical | CWE-78
// AI generates Command::new with user input without sanitization
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustCommandInjection;

impl LangRule for RustCommandInjection {
    fn id(&self) -> &str { "RUST-SEC-001" }
    fn name(&self) -> &str { "Command Injection (std::process::Command)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let cmd_targets: HashSet<&str> = [
            "Command::new", "std::process::Command",
        ].into_iter().collect();

        for call in &tree.calls {
            if cmd_targets.iter().any(|t| call.callee.contains(t)) {
                let has_user_input = !call.arguments.is_empty()
                    && call.arguments.iter().any(|a| {
                        a.contains("request")
                            || a.contains("input")
                            || a.contains("param")
                            || a.contains("user")
                            || a.contains("args")
                            || a.contains("_arg")
                    });

                if has_user_input {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = get_line_text(code, call.start_line)
                        .unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "Command execution '{}' with likely user-controlled argument. \
                            CWE-78: Command Injection — if the argument is unsanitized, \
                            attackers can execute arbitrary OS commands on the host.",
                            call.callee
                        ),
                        fix_hint: "Never pass unsanitized user input to Command. \
                            Validate and sanitize all arguments. Prefer passing args as a \
                            separated list: Command::new(\"ls\").arg(user_input) — avoid \
                            shell interpretation. Use an allowlist for permitted values.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        // Also check for .arg() with user input
        let arg_pattern = Regex::new(r#"(?i)\.arg\s*\([^)]*(?:request|input|param|user|args|arg)[^)]*\)"#).unwrap();
        if arg_pattern.is_match(code) {
            for m in arg_pattern.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                if !findings.iter().any(|f: &LangFinding| f.line == line) {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: "Command::arg() with potentially user-controlled input. \
                            CWE-78: Command injection risk.".to_string(),
                        fix_hint: "Sanitize and validate user input before passing to Command::arg(). \
                            Use an allowlist for permitted values.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-002: Hardcoded Secrets / Credentials
// Severity: critical | CWE-798
// AI generates code with hardcoded passwords, API keys, tokens
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustHardcodedSecret;

impl LangRule for RustHardcodedSecret {
    fn id(&self) -> &str { "RUST-SEC-002" }
    fn name(&self) -> &str { "Hardcoded Secrets / Credentials" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let secret_patterns = [
            (r#"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|bearer|jwt|private[_-]?key|aws[_-]?secret|slack[_-]?token|github[_-]?token)\s*[=:]\s*["'][^'"]{4,}["']"#, "hardcoded credential pattern"),
            (r#"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"#, "hardcoded JWT/bearer token"),
            (r#"(?i)(aws[_-]?(access[_-]?key[_-]?id|secret[_-]?access[_-]?key))\s*[=:]\s*["'][^'"]{10,}["']"#, "hardcoded AWS credentials"),
            (r#"conn_string\s*[=:]\s*["'][^'"]*password[^'"]*["']"#, "connection string with password"),
            (r#"encryption_key\s*[=:]\s*["'][^'"]{16,}["']"#, "encryption key hardcoded"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            for (pattern, desc) in &secret_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        for m in re.find_iter(line) {
                            let (start_byte, _) = get_line_offsets(code, line_num);
                            let abs_start = start_byte + line.len() - line.trim_start().len();
                            let abs_end = abs_start + line.len();

                            findings.push(LangFinding {
                                rule_id: self.id().to_string(),
                                severity: self.severity().to_string(),
                                line: line_num,
                                column: m.start(),
                                start_byte: abs_start,
                                end_byte: abs_end,
                                snippet: m.as_str().to_string(),
                                problem: format!(
                                    "Hardcoded secret detected: {}. CWE-798: Found credentials, \
                                    API keys, or tokens directly in source code. These can be \
                                    extracted from repositories, decompiled binaries, or logs.",
                                    desc
                                ),
                                fix_hint: "Move secrets to environment variables: std::env::var(\"API_KEY\"). \
                                    Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, \
                                    Docker secrets). Load at runtime from secure storage.".to_string(),
                                auto_fix_available: false,
                            });
                        }
                    }
                }
            }
        }

        // Check strings that look like API keys/tokens
        for string_lit in &tree.strings {
            let val = &string_lit.value;
            // Long alphanumeric strings that look like keys
            if val.len() >= 20
                && (val.starts_with("sk_") || val.starts_with("pk_")
                    || val.starts_with("ghp_") || val.starts_with("xoxb-")
                    || val.contains("-----BEGIN") || val.contains("AIza"))
                && !val.contains("example") && !val.contains("test")
            {
                let (start, end) = get_line_offsets(code, string_lit.start_line);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: string_lit.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: format!("\"{}...\"", &string_lit.value[..string_lit.value.len().min(30)]),
                    problem: "Potential hardcoded API key or token detected. \
                        CWE-798: Secrets in source code are a critical security risk.".to_string(),
                    fix_hint: "Move this value to an environment variable: \
                        std::env::var(\"KEY_NAME\"). Store secrets in secure vaults, \
                        not in source code.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-003: Path Traversal / Arbitrary File Access
// Severity: high | CWE-22
// AI generates file operations without checking for ../ sequences
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustPathTraversal;

impl LangRule for RustPathTraversal {
    fn id(&self) -> &str { "RUST-SEC-003" }
    fn name(&self) -> &str { "Path Traversal / Arbitrary File Read" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let fs_imports = [
            "std::fs", "std::io", "fs::", "File::",
        ];

        let dangerous_calls: HashSet<&str> = [
            "read", "read_to_string", "read_to_end",
            "File::open", "File::create", "fs::read",
            "fs::read_to_string", "fs::read_dir",
        ].into_iter().collect();

        let has_fs = tree.imports.iter().any(|imp| {
            fs_imports.iter().any(|fs| imp.module.contains(fs))
        });

        if !has_fs {
            return findings;
        }

        let sanitization_patterns = [
            "canonicalize", "components().collect", "strip_prefix",
            "ends_with", "starts_with", "normalize",
        ];

        for call in &tree.calls {
            if dangerous_calls.iter().any(|dc| call.callee.contains(dc)) {
                let has_user_input = !call.arguments.is_empty()
                    && call.arguments.iter().any(|a| {
                        a.contains("request") || a.contains("input")
                            || a.contains("param") || a.contains("filename")
                            || a.contains("path") || a.contains("user")
                    });

                let has_sanitization = sanitization_patterns.iter().any(|sp| {
                    tree.calls.iter().any(|c| c.callee.contains(sp))
                });

                if has_user_input && !has_sanitization {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = get_line_text(code, call.start_line)
                        .unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "File operation '{}' with likely user-controlled path and no sanitization. \
                            CWE-22: Path Traversal — attackers can use '../' sequences to read \
                            arbitrary files like /etc/passwd, application config, or source code.",
                            call.callee
                        ),
                        fix_hint: "Use canonicalize() to resolve symlinks and verify the path stays \
                            within an allowed directory. Example: \
                            let path = path.canonicalize()?; \
                            if !path.starts_with(ALLOWED_DIR) { return Err(...); }".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-004: Sensitive Data Logging
// Severity: high | CWE-532
// AI logs sensitive data like passwords, tokens, credit cards
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustSensitiveDataLogging;

impl LangRule for RustSensitiveDataLogging {
    fn id(&self) -> &str { "RUST-SEC-004" }
    fn name(&self) -> &str { "Sensitive Data in Logs" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let sensitive_patterns = [
            (r#"(?i)(?:password|passwd|pwd|secret|token|bearer|jwt|api[_-]?key|auth|credential)[^;]*\."#, "sensitive field logged"),
            (r#"(?i)\.log\s*\([^)]*(?:password|token|bearer|secret|key)[^)]*\)"#, "sensitive data in log call"),
            (r#"println!\s*\([^)]*(?:password|token|bearer|secret)[^)]*\)"#, "sensitive data in println!"),
            (r#"(?i)(?:credit[_-]?card|cvv|ssn|social[_-]?security)\s*[=:]"#, "PII/financial data defined"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            for (pattern, desc) in &sensitive_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start_byte, _) = get_line_offsets(code, line_num);
                        let abs_start = start_byte + line.len() - line.trim_start().len();
                        let abs_end = abs_start + line.len();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: abs_start,
                            end_byte: abs_end,
                            snippet: line.trim().to_string(),
                            problem: format!(
                                "Sensitive data logged: {}. CWE-532: Information Disclosure — \
                                passwords, tokens, and PII in logs can be read by anyone with \
                                access to log files, monitoring systems, or log aggregation tools.",
                                desc
                            ),
                            fix_hint: "Never log sensitive fields. Use structured logging and \
                                explicitly exclude sensitive fields from output. Example: \
                                logger.info(\"User logged in: {}\", username) — never log password.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = get_line_text(code, finding.line)?;
        let trimmed = line_text.trim();

        // Comment out the line
        if trimmed.contains("println!") || trimmed.contains(".log")
            || trimmed.contains("eprintln!")
        {
            let indent = &line_text[..line_text.len() - line_text.trim_start().len()];
            let commented = format!("{}// FIXME: [RUST-SEC-004] Remove sensitive data from log: {}", indent, trimmed);
            Some(LangFix {
                rule_id: self.id().to_string(),
                original: line_text,
                replacement: commented,
                start_byte: finding.start_byte,
                end_byte: finding.end_byte,
                description: "Comment out log with sensitive data".to_string(),
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-005: Integer Overflow
// Severity: medium | CWE-190
// AI performs arithmetic without checking for overflow
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustIntegerOverflow;

impl LangRule for RustIntegerOverflow {
    fn id(&self) -> &str { "RUST-SEC-005" }
    fn name(&self) -> &str { "Potential Integer Overflow" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check if debug mode overflow checking is disabled
        let has_overflow_check_disabled = code.contains("#[overflow_checks")
            && code.contains("= false");

        if has_overflow_check_disabled {
            for (line_idx, line) in code.lines().enumerate() {
                let line_num = line_idx + 1;
                if line.contains("overflow_checks") && line.contains("false") {
                    let (start, end) = get_line_offsets(code, line_num);

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: line_num,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.trim().to_string(),
                        problem: "Integer overflow checks disabled in release mode. \
                            CWE-190: Arithmetic operations can overflow silently.".to_string(),
                        fix_hint: "Keep overflow checks enabled in release mode. If you need \
                            wrapping arithmetic, use explicit wrapping methods: \
                            a.wrapping_add(b), a.saturating_add(b), or a.checked_add(b).".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        // Check for potential overflow in array/index operations
        let _overflow_patterns = [
            (r"\[.*usize\]", "array access with usize"),
            (r"\.len\(\)\s*[><=]", "length comparison for bounds"),
            (r"\.index\s*\(", "index access pattern"),
        ];

        for call in &tree.calls {
            // Check for unchecked indexing
            if call.callee.contains("unwrap")
                && (call.callee.contains("index") || call.callee.contains("get_")) {
                let (start, end) = get_line_offsets(code, call.start_line);
                let line_text = get_line_text(code, call.start_line)
                    .unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: "Index access with unwrap(). CWE-190: This can panic if index is out of bounds.".to_string(),
                    fix_hint: "Use checked indexing: vec.get(index) instead of vec[index].unwrap(). \
                        Or ensure index is validated before access.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-006: Insecure Random Number Generation
// Severity: medium | CWE-338
// AI uses thread_rng for security-sensitive random numbers
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustInsecureRandom;

impl LangRule for RustInsecureRandom {
    fn id(&self) -> &str { "RUST-SEC-006" }
    fn name(&self) -> &str { "Insecure Random for Security-Sensitive Use" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let _insecure_random_imports = [
            "rand::thread_rng", "rand::random", "rand::distributions",
        ];

        let security_sensitive_patterns = [
            "password", "token", "key", "salt", "nonce", "session_id",
            "verification", "captcha", "otp", "crypt",
        ];

        let has_rand = tree.imports.iter().any(|imp| {
            imp.module.contains("rand")
        });

        if !has_rand {
            return findings;
        }

        // Look for security-sensitive code blocks
        let code_upper = code.to_uppercase();
        let has_security_context = security_sensitive_patterns.iter()
            .any(|pattern| code_upper.contains(&pattern.to_uppercase()));

        if has_security_context {
            for call in &tree.calls {
                if call.callee.contains("thread_rng") || call.callee.contains("random") {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = get_line_text(code, call.start_line)
                        .unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "Random number generation '{}' in security-sensitive context. \
                            CWE-338: thread_rng() is not cryptographically secure. \
                            For security purposes (passwords, tokens, keys), use a CSPRNG.",
                            call.callee
                        ),
                        fix_hint: "Use a cryptographically secure random number generator: \
                            getrandom::getrandom() or rand::prng::chacha::ChaChaRng. \
                            For passwords: use rand::distributions::Alphanumeric \
                            with a secure RNG.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-007: Unbounded Collection (DoS Risk)
// Severity: medium | CWE-400
// AI creates Vec/HashMap without size limits (memory exhaustion)
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustUnboundedCollection;

impl LangRule for RustUnboundedCollection {
    fn id(&self) -> &str { "RUST-SEC-007" }
    fn name(&self) -> &str { "Unbounded Collection (Memory Exhaustion DoS)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let collection_imports = [
            "Vec", "HashMap", "HashSet", "BTreeMap", "BTreeSet",
            "vec!", "HashMap::new", "Vec::new",
        ];

        let has_user_input = tree.calls.iter().any(|call| {
            call.arguments.iter().any(|a| {
                a.contains("request") || a.contains("input")
                    || a.contains("body") || a.contains("data")
                    || a.contains("param")
            })
        });

        let has_collections = tree.imports.iter().any(|imp| {
            collection_imports.iter().any(|c| imp.module.contains(c) || imp.name.contains(c))
        }) || tree.calls.iter().any(|call| {
            collection_imports.iter().any(|c| call.callee.contains(c))
        });

        // Check for Vec::with_capacity - good practice
        let has_capacity_limit = tree.calls.iter()
            .any(|call| call.callee.contains("with_capacity")
                || call.callee.contains("with_capacity_and_trait"));

        if has_collections && has_user_input && !has_capacity_limit {
            // Look at lines with collection creation
            let collect_pattern = Regex::new(r"(?i)(?:vec!|hashmap!|hashset!|Vec::new|HashMap::new)\s*\(\s*\)").unwrap();

            for m in collect_pattern.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;

                // Check if there's any capacity limit nearby
                let line_text = get_line_text(code, line).unwrap_or_default();
                if !line_text.contains("with_capacity") && !line_text.contains("reserve") {
                    let (start, end) = get_line_offsets(code, line);

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: "Unbounded collection created without size limit. \
                            CWE-400: Attackers can send large payloads to exhaust memory.".to_string(),
                        fix_hint: "Set maximum capacity: vec.reserve(capacity) or use bounded \
                            collections. Validate input size before adding to collection. \
                            Example: if items.len() > MAX_SIZE { return Err(...); }".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-008: Weak Cryptography
// Severity: high | CWE-327
// AI uses MD5, SHA1, DES, etc. for security purposes
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustWeakCrypto;

impl LangRule for RustWeakCrypto {
    fn id(&self) -> &str { "RUST-SEC-008" }
    fn name(&self) -> &str { "Weak / Broken Cryptography" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let weak_algo_imports = [
            ("md5", "MD5 is broken for security purposes. Use SHA-256 or SHA-3."),
            ("sha1", "SHA-1 is deprecated for signatures. Use SHA-256 or SHA-3."),
            ("des", "DES is broken (56-bit key). Use AES-256."),
            ("rc4", "RC4 is broken. Use AES."),
            ("blowfish", "Blowfish is weakened. Use AES."),
        ];

        for imp in &tree.imports {
            for (algo, msg) in &weak_algo_imports {
                if imp.module.to_lowercase().contains(algo)
                    || imp.name.to_lowercase().contains(algo)
                {
                    let (start, end) = get_line_offsets(code, imp.start_line);

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: imp.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: imp.module.clone(),
                        problem: format!(
                            "Weak cryptography algorithm '{}' detected. CWE-327: {}",
                            algo, msg
                        ),
                        fix_hint: "Use cryptographically secure algorithms: AES-256-GCM for \
                            encryption, SHA-256 or SHA-3 for hashing. For passwords, use \
                            bcrypt, argon2, or scrypt.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        // Check for weak encryption patterns in code
        let weak_patterns = [
            (r#"Md5Hash\.new\(\)"#, "MD5 hash creation"),
            (r#"Sha1\.new\(\)"#, "SHA-1 hash creation"),
            (r#"des::\w+"#, "DES encryption"),
            (r#"Rc4\.new\(\)"#, "RC4 encryption"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            for (pattern, name) in &weak_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, line_num);

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line.trim().to_string(),
                            problem: format!(
                                "Weak cryptography detected: {}. CWE-327: This algorithm is \
                                cryptographically weak and should not be used for security.",
                                name
                            ),
                            fix_hint: "Replace with a modern, secure algorithm: AES-256-GCM, \
                                SHA-256, or ChaCha20-Poly1305.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-009: Use After Free (Unsafe Rust)
// Severity: high | CWE-416
// AI may create use-after-free patterns in unsafe code
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustUseAfterFree;

impl LangRule for RustUseAfterFree {
    fn id(&self) -> &str { "RUST-SEC-009" }
    fn name(&self) -> &str { "Potential Use-After-Free Pattern" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Look for Box::into_raw, raw pointers, and manual drop patterns
        let dangerous_patterns = [
            (r"Box::into_raw\s*\(", "Box::into_raw without corresponding Box::from_raw"),
            (r"std::ptr::read\s*\(", "std::ptr::read on potentially invalid memory"),
            (r"std::ptr::drop_in_place\s*\(", "Manual memory deallocation"),
            (r"\bas\s+as\s+as\b", "Double cast on raw pointers"),
            (r"\*const\s+\w+\s+as\s+\*const", "Pointer casting pattern"),
        ];

        let has_unsafe = code.contains("unsafe");

        if !has_unsafe {
            return findings;
        }

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            // Skip comments and safety documentation
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            for (pattern, desc) in &dangerous_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, line_num);

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: trimmed.to_string(),
                            problem: format!(
                                "Potentially unsafe memory operation: {}. CWE-416: This pattern \
                                can lead to use-after-free vulnerabilities if pointers are not \
                                properly managed.",
                                desc
                            ),
                            fix_hint: "Ensure all raw pointer operations are safe. Use Box<T> \
                                for owned heap allocations. If you must use raw pointers, \
                                follow Rust's unsafe guidelines strictly. Document all invariants.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-010: Regex DoS (ReDoS)
// Severity: medium | CWE-1333
// AI creates regex patterns that can cause catastrophic backtracking
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustRegexDos;

impl LangRule for RustRegexDos {
    fn id(&self) -> &str { "RUST-SEC-010" }
    fn name(&self) -> &str { "Regex DoS (ReDoS) Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Look for potentially catastrophic regex patterns
        let redos_patterns = [
            (r#"\(\.\*\+\)\{"#, "nested quantifiers: (.*+){"),
            (r#"\(\.\+\)\{"#, "nested quantifiers: (.+){"),
            (r#"\(\.\*\)\{"#, "nested quantifiers: (.*){"),
            (r#"\([^)]*\*[^)]*\)\{"#, "quantifier inside group with quantifier"),
            (r#"\([^)]+\+\)[^?]"#, "greedy quantifier with alternation"),
            (r#"\|.*\|.*\|.*\|"#, "complex alternation"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;

            // Check if this line creates a regex
            let is_regex_line = line.contains("Regex::new")
                || line.contains("regex!")
                || line.contains("from_str")
                || line.contains("is_match")
                || line.contains("find");

            if is_regex_line {
                for (pattern, desc) in &redos_patterns {
                    if let Ok(re) = Regex::new(pattern) {
                        if re.is_match(line) {
                            let (start, end) = get_line_offsets(code, line_num);

                            findings.push(LangFinding {
                                rule_id: self.id().to_string(),
                                severity: self.severity().to_string(),
                                line: line_num,
                                column: 0,
                                start_byte: start,
                                end_byte: end,
                                snippet: line.trim().to_string(),
                                problem: format!(
                                    "Potentially catastrophic regex pattern: {}. CWE-1333: \
                                    This regex can cause exponential backtracking on malicious input, \
                                    leading to denial of service.",
                                    desc
                                ),
                                fix_hint: "Rewrite the regex to avoid nested quantifiers. Use atomic \
                                    groups (not in standard Rust regex) or possessive quantifiers. \
                                    Simplify alternation patterns. Consider using regex crate with \
                                   公園 (use_nth) to limit complexity.".to_string(),
                                auto_fix_available: false,
                            });
                        }
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry function
// ─────────────────────────────────────────────────────────────────────────────

/// All Rust security rules.
pub fn rust_security_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(RustCommandInjection),
        Box::new(RustHardcodedSecret),
        Box::new(RustPathTraversal),
        Box::new(RustSensitiveDataLogging),
        Box::new(RustIntegerOverflow),
        Box::new(RustInsecureRandom),
        Box::new(RustUnboundedCollection),
        Box::new(RustWeakCrypto),
        Box::new(RustUseAfterFree),
        Box::new(RustRegexDos),
    ]
}
