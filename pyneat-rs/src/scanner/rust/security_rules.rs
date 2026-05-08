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

use once_cell::sync::Lazy;
use regex::Regex;

use super::super::ln_ast::LnAst;
use super::super::base::{LangRule, LangFinding, LangFix};

// ─────────────────────────────────────────────────────────────────────────────
// Pre-compiled Regex Patterns
// ─────────────────────────────────────────────────────────────────────────────

// RUST-SEC-001
static COMMAND_INJECTION_ARG_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\.arg\s*\([^)]*(?:request|input|param|user|args|arg)[^)]*\)").unwrap()
});

// RUST-SEC-002
static SECRET_GENERIC: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|bearer|jwt|private[_-]?key|aws[_-]?secret|slack[_-]?token|github[_-]?token)\s*[=:]\s*["'][^'"]{4,}["']"#).unwrap());
static SECRET_BEARER: Lazy<Regex> = Lazy::new(|| Regex::new(r#"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"#).unwrap());
static SECRET_AWS: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)(aws[_-]?(access[_-]?key[_-]?id|secret[_-]?access[_-]?key))\s*[=:]\s*["'][^'"]{10,}["']"#).unwrap());
static SECRET_CONN_STRING: Lazy<Regex> = Lazy::new(|| Regex::new(r#"conn_string\s*[=:]\s*["'][^'"]*password[^'"]*["']"#).unwrap());
static SECRET_ENCRYPTION_KEY: Lazy<Regex> = Lazy::new(|| Regex::new(r#"encryption_key\s*[=:]\s*["'][^'"]{16,}["']"#).unwrap());

// RUST-SEC-004
static SENSITIVE_LOG_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)(?:password|passwd|pwd|secret|token|bearer|jwt|api[_-]?key|auth|credential)[^;]*\."#).unwrap());
static LOG_CALL_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)\.log\s*\([^)]*(?:password|token|bearer|secret|key)[^)]*\)"#).unwrap());
static PRINTLN_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r#"println!\s*\([^)]*(?:password|token|bearer|secret)[^)]*\)"#).unwrap());
static PII_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)(?:credit[_-]?card|cvv|ssn|social[_-]?security)\s*[=:]"#).unwrap());

// RUST-SEC-007
static COLLECTION_INIT_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(?:vec!|hashmap!|hashset!|Vec::new|HashMap::new)\s*\(\s*\)").unwrap());

// RUST-SEC-008
static WEAK_CRYPTO_MD5: Lazy<Regex> = Lazy::new(|| Regex::new(r#"Md5Hash\.new\(\)"#).unwrap());
static WEAK_CRYPTO_SHA1: Lazy<Regex> = Lazy::new(|| Regex::new(r#"Sha1\.new\(\)"#).unwrap());
static WEAK_CRYPTO_DES: Lazy<Regex> = Lazy::new(|| Regex::new(r#"des::\w+"#).unwrap());
static WEAK_CRYPTO_RC4: Lazy<Regex> = Lazy::new(|| Regex::new(r#"Rc4\.new\(\)"#).unwrap());

// RUST-SEC-009
static USE_AFTER_FREE_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"Box::into_raw\s*\(", "Box::into_raw without corresponding Box::from_raw"),
    (r"std::ptr::read\s*\(", "std::ptr::read on potentially invalid memory"),
    (r"std::ptr::drop_in_place\s*\(", "Manual memory deallocation"),
    (r"\bas\s+as\s+as\b", "Double cast on raw pointers"),
    (r"\*const\s+\w+\s+as\s+\*const", "Pointer casting pattern"),
]);

// RUST-SEC-010
static REDOS_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"\(\.\*\+\)\{"#, "nested quantifiers: (.*+){"),
    (r#"\(\.\+\)\{"#, "nested quantifiers: (.+){"),
    (r#"\(\.\*\)\{"#, "nested quantifiers: (.*){"),
    (r#"\([^)]*\*[^)]*\)\{"#, "quantifier inside group with quantifier"),
    (r#"\([^)]+\+\)[^?]"#, "greedy quantifier with alternation"),
    (r#"\|.*\|.*\|.*\|"#, "complex alternation"),
]);

// RUST-SEC-011
static UNSAFE_BLOCK_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bunsafe\s*\{").unwrap());
static SAFETY_DOC_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)#\s*Safety\s*:").unwrap());

// RUST-SEC-012
static RC_REFCELL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"Rc\s*<\s*RefCell\s*<").unwrap());
static RAW_PTR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\*\s*(?:const|mut)\s+\w+\s*(?:\w+\s*)?;").unwrap());

// RUST-SEC-013
static WRAPAROUND_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"(?i)\.wrapping_(add|sub|mul|div)", "Integer wraparound method - silently wraps on overflow"),
    (r"(?i)\.overflowing_(add|sub|mul|div)", "Overflowing integer operation - does not panic"),
    (r"(?i)\.saturating_(add|sub|mul|div)", "Saturating arithmetic - clamps instead of wrapping"),
    (r"(?i)(usize|USIZE)::MAX\s+(?:as\s+)?i\d", "Casting usize::MAX to signed integer - can cause overflow"),
    (r"(?i)(i\d)::MAX\s+(?:as\s+)?(?:u\d|usize)", "Casting large signed value to unsigned - unexpected truncation"),
]);

// RUST-SEC-014
static INSECURE_TLS_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"(?i)\.danger_accept_invalid_certs\s*\(\s*true\s*\)", "TLS certificate verification disabled - allows MITM attacks"),
    (r"(?i)danger_accept_invalid_certs\s*=\s*(?:true|1)", "TLS verification disabled in config"),
    (r"(?i)\.use_preconfigured_certs\s*\(\s*\)", "Preconfigured certs without proper validation"),
    (r"(?i)rustls.*verify\s*=\s*(?:false|0)", "rustls TLS verification disabled"),
    (r"(?i)reqwest.*ssl.*verify.*false", "reqwest SSL verification disabled"),
]);

// RUST-SEC-016
static DBG_MACRO_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bdbg!\s*\(").unwrap());

// RUST-SEC-017
static OVERFLOW_ARITH_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"\b\d+\s*[\+\-]\s*\d+", "Addition/subtraction without overflow check"),
    (r"\b\d+\s*\*\s*\d+", "Multiplication without overflow check"),
    (r"\bu(?:size|8|16|32|64)\s*::\s*MAX", "MAX constant usage without bounds check"),
    (r"\bi(?:8|16|32|64)\s*::\s*MAX", "Signed MAX constant without bounds check"),
]);

// RUST-SEC-018
static UAF_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"std::ptr::read\s*\(", "std::ptr::read on potentially freed memory"),
    (r"std::ptr::drop_in_place\s*\(", "std::ptr::drop_in_place followed by read"),
    (r"::from_raw_parts\s*\(", "Creating reference from raw parts without validation"),
    (r"ManuallyDrop::into_inner\s*\(", "ManuallyDrop into_inner after potential drop"),
]);

// RUST-SEC-019
static INSECURE_RAND_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"rand::thread_rng\s*\(", "rand::thread_rng - not cryptographically secure"),
    (r"rand::(\w+::)?Rng::new\s*\(", "rand Rng::new - not cryptographically secure"),
    (r"use\s+rand\s*;", "rand crate import for non-crypto use"),
    (r"rand::seq::SliceRandom::shuffle\s*\(", "rand shuffle for security-sensitive purposes"),
]);

// RUST-SEC-020
static UNSAFE_BLOCK_RE2: Lazy<Regex> = Lazy::new(|| Regex::new(r"unsafe\s*\{").unwrap());

// RUST-SEC-021
static HARDCODED_SECRETS_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:api[_-]?key|secret|password|passwd|token|auth|credential)\s*[=:]\s*["'][^'"]{4,}["']"##, "Hardcoded secret value"),
    (r##"(?i)password\s*=\s*["'][^'"]{4,}["']"##, "Hardcoded password"),
    (r##"(?i)api[_-]?key\s*[=:]\s*["'][A-Za-z0-9_\-]{10,}["']"##, "Hardcoded API key"),
    (r##"AKIA[0-9A-Z]{16}"##, "AWS Access Key ID"),
    (r##"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"##, "Private key embedded in code"),
    (r##"(?i)bearer\s+[A-Za-z0-9_\-\.]+"##, "Hardcoded Bearer token"),
]);

// RUST-SEC-022
static WRONG_CAST_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"std::mem::transmute\s*<[^>]+>\s*\([^)]+\)", "mem::transmute usage - unsafe type conversion"),
    (r"\bas\s+\w+\s*as\s+", "Chained type casts - potential precision loss"),
    (r"\bu?int(?::\d+)?\s*::\s*(?:try_from|from)\s*\([^)]*f(?:32|64)\s*\)", "Integer from float conversion - may lose precision"),
]);

// RUST-CRYPT-001
static CRYPT_WEAK_HASH_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"ring::digest::digest\s*\([^)]*md5"#, "ring::digest with MD5 - insecure for cryptographic purposes"),
    (r#"digest::digest\s*\([^)]*::md5"#, "digest::md5 usage - MD5 is broken for security"),
    (r#"sha1::digest::Digest"#, "SHA1 digest usage - deprecated for signatures"),
    (r#"::sha1::"#, "SHA1 crate usage - use SHA-256 or SHA-3"),
    (r#"::md5::"#, "MD5 crate usage - MD5 is cryptographically broken"),
]);

static CRYPT_SMALL_RSA_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"RSA\s*\{[^}]*bits\s*:\s*(?:256|512)"#, "RSA with 256 or 512 bits - trivially breakable"),
    (r#"rsa::\w+\s*\(\s*(?:256|512)\s*\)"#, "RSA key generation with 256/512 bits"),
    (r#"RsaKeyPair::\w+\s*\(\s*(?:256|512)\s*\)"#, "RsaKeyPair with small key size"),
]);

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
                        replacement: String::new(),
                    });
                }
            }
        }

        // Also check for .arg() with user input
        if COMMAND_INJECTION_ARG_PATTERN.is_match(code) {
            for m in COMMAND_INJECTION_ARG_PATTERN.find_iter(code) {
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
                        replacement: String::new(),
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

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed_line = line.trim();

            // Check each pre-compiled pattern
            if SECRET_GENERIC.is_match(trimmed_line) {
                for m in SECRET_GENERIC.find_iter(trimmed_line) {
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
                        problem: "Hardcoded secret detected: hardcoded credential pattern. CWE-798: Found credentials, \
                                    API keys, or tokens directly in source code. These can be \
                                    extracted from repositories, decompiled binaries, or logs.".to_string(),
                        fix_hint: "Move secrets to environment variables: std::env::var(\"API_KEY\"). \
                                    Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, \
                                    Docker secrets). Load at runtime from secure storage.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
            if SECRET_BEARER.is_match(trimmed_line) {
                for m in SECRET_BEARER.find_iter(trimmed_line) {
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
                        problem: "Hardcoded secret detected: hardcoded JWT/bearer token. CWE-798: Found credentials, \
                                    API keys, or tokens directly in source code. These can be \
                                    extracted from repositories, decompiled binaries, or logs.".to_string(),
                        fix_hint: "Move secrets to environment variables: std::env::var(\"API_KEY\"). \
                                    Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, \
                                    Docker secrets). Load at runtime from secure storage.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
            if SECRET_AWS.is_match(trimmed_line) {
                for m in SECRET_AWS.find_iter(trimmed_line) {
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
                        problem: "Hardcoded secret detected: hardcoded AWS credentials. CWE-798: Found credentials, \
                                    API keys, or tokens directly in source code. These can be \
                                    extracted from repositories, decompiled binaries, or logs.".to_string(),
                        fix_hint: "Move secrets to environment variables: std::env::var(\"API_KEY\"). \
                                    Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, \
                                    Docker secrets). Load at runtime from secure storage.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
            if SECRET_CONN_STRING.is_match(trimmed_line) {
                for m in SECRET_CONN_STRING.find_iter(trimmed_line) {
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
                        problem: "Hardcoded secret detected: connection string with password. CWE-798: Found credentials, \
                                    API keys, or tokens directly in source code. These can be \
                                    extracted from repositories, decompiled binaries, or logs.".to_string(),
                        fix_hint: "Move secrets to environment variables: std::env::var(\"API_KEY\"). \
                                    Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, \
                                    Docker secrets). Load at runtime from secure storage.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
            if SECRET_ENCRYPTION_KEY.is_match(trimmed_line) {
                for m in SECRET_ENCRYPTION_KEY.find_iter(trimmed_line) {
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
                        problem: "Hardcoded secret detected: encryption key hardcoded. CWE-798: Found credentials, \
                                    API keys, or tokens directly in source code. These can be \
                                    extracted from repositories, decompiled binaries, or logs.".to_string(),
                        fix_hint: "Move secrets to environment variables: std::env::var(\"API_KEY\"). \
                                    Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, \
                                    Docker secrets). Load at runtime from secure storage.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
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
                        replacement: String::new(),
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
                        replacement: String::new(),
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

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed_line = line.trim();

            if SENSITIVE_LOG_PATTERN.is_match(trimmed_line) {
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
                    problem: "Sensitive data logged: sensitive field logged. CWE-532: Information Disclosure — \
                                passwords, tokens, and PII in logs can be read by anyone with \
                                access to log files, monitoring systems, or log aggregation tools.".to_string(),
                    fix_hint: "Never log sensitive fields. Use structured logging and \
                                explicitly exclude sensitive fields from output. Example: \
                                logger.info(\"User logged in: {}\", username) — never log password.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
            if LOG_CALL_PATTERN.is_match(trimmed_line) {
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
                    problem: "Sensitive data logged: sensitive data in log call. CWE-532: Information Disclosure — \
                                passwords, tokens, and PII in logs can be read by anyone with \
                                access to log files, monitoring systems, or log aggregation tools.".to_string(),
                    fix_hint: "Never log sensitive fields. Use structured logging and \
                                explicitly exclude sensitive fields from output. Example: \
                                logger.info(\"User logged in: {}\", username) — never log password.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
            if PRINTLN_PATTERN.is_match(trimmed_line) {
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
                    problem: "Sensitive data logged: sensitive data in println!. CWE-532: Information Disclosure — \
                                passwords, tokens, and PII in logs can be read by anyone with \
                                access to log files, monitoring systems, or log aggregation tools.".to_string(),
                    fix_hint: "Never log sensitive fields. Use structured logging and \
                                explicitly exclude sensitive fields from output. Example: \
                                logger.info(\"User logged in: {}\", username) — never log password.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
            if PII_PATTERN.is_match(trimmed_line) {
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
                    problem: "Sensitive data logged: PII/financial data defined. CWE-532: Information Disclosure — \
                                passwords, tokens, and PII in logs can be read by anyone with \
                                access to log files, monitoring systems, or log aggregation tools.".to_string(),
                    fix_hint: "Never log sensitive fields. Use structured logging and \
                                explicitly exclude sensitive fields from output. Example: \
                                logger.info(\"User logged in: {}\", username) — never log password.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
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
// RUST-SEC-005: Integer Overflow — Debug/Cargo Overflow Checks Disabled
// Severity: medium | CWE-190
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustOverflowChecksDisabled;

impl LangRule for RustOverflowChecksDisabled {
    fn id(&self) -> &str { "RUST-SEC-005" }
    fn name(&self) -> &str { "Integer Overflow Checks Disabled in Release" }
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
                        replacement: String::new(),
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
                        replacement: String::new(),
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
                        replacement: String::new(),
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
            for m in COLLECTION_INIT_PATTERN.find_iter(code) {
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
                        replacement: String::new(),
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
                        replacement: String::new(),
                    });
                }
            }
        }

        // Check for weak encryption patterns in code
        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;

            if WEAK_CRYPTO_MD5.is_match(line) || WEAK_CRYPTO_SHA1.is_match(line)
                || WEAK_CRYPTO_DES.is_match(line) || WEAK_CRYPTO_RC4.is_match(line)
            {
                let name = if WEAK_CRYPTO_MD5.is_match(line) {
                    "MD5 hash creation"
                } else if WEAK_CRYPTO_SHA1.is_match(line) {
                    "SHA-1 hash creation"
                } else if WEAK_CRYPTO_DES.is_match(line) {
                    "DES encryption"
                } else {
                    "RC4 encryption"
                };

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
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// RUST-SEC-009: Use After Free — Unsafe Dereference
// Severity: high | CWE-416
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustUnsafeDeref;

impl LangRule for RustUnsafeDeref {
    fn id(&self) -> &str { "RUST-SEC-009" }
    fn name(&self) -> &str { "Unsafe Block with Pointer Dereference" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

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

            for (pattern, desc) in &*USE_AFTER_FREE_PATTERNS {
                let re = Regex::new(pattern).unwrap();
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
                        replacement: String::new(),
                    });
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

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;

            // Check if this line creates a regex
            let is_regex_line = line.contains("Regex::new")
                || line.contains("regex!")
                || line.contains("from_str")
                || line.contains("is_match")
                || line.contains("find");

            if is_regex_line {
                for (pattern, desc) in &*REDOS_PATTERNS {
                    let re = Regex::new(pattern).unwrap();
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
                               Consider using regex-debug or static analysis tools to limit complexity.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
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
// RUST-SEC-011: Missing Safety Documentation (CWE-682)
// Severity: medium
// unsafe blocks without # Safety: doc comment
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustUnsafeDocs;

impl LangRule for RustUnsafeDocs {
    fn id(&self) -> &str { "RUST-SEC-011" }
    fn name(&self) -> &str { "Missing Safety Documentation for Unsafe Block" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (i, line) in code.lines().enumerate() {
            if UNSAFE_BLOCK_RE.is_match(line) {
                // Look at the next few lines for a safety doc comment
                let remaining: String = code.lines().skip(i).take(5).collect::<Vec<_>>().join("\n");
                if !SAFETY_DOC_RE.is_match(&remaining) {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: "RUST-SEC-011".to_string(),
                        severity: "medium".to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.to_string(),
                        problem: "unsafe block without safety documentation comment. Unsafe code must document invariants that must be upheld to maintain memory safety.".to_string(),
                        fix_hint: "Add a # Safety: doc comment before the unsafe block explaining: 1) What invariants the caller must uphold, 2) What behavior is undefined if violated, 3) Why this unsafe block is necessary.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-012: Data Race / Send+Sync Violation (CWE-362)
// Severity: high
// Rc<RefCell<T>> pattern, shared mutable state without Mutex
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustDataRace;

impl LangRule for RustDataRace {
    fn id(&self) -> &str { "RUST-SEC-012" }
    fn name(&self) -> &str { "Potential Data Race / Missing Sync Primitives" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (i, line) in code.lines().enumerate() {
            if RC_REFCELL_RE.is_match(line) && !line.trim().starts_with("//") {
                findings.push(LangFinding {
                    rule_id: "RUST-SEC-012".to_string(),
                    severity: "high".to_string(),
                    line: i + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line.to_string(),
                    problem: "Rc<RefCell<T>> is not Send or Sync. This pattern is not thread-safe and can cause data races when shared across threads. RefCell provides runtime borrow checking which is not atomic.".to_string(),
                    fix_hint: "Use Arc<Mutex<T>> or Arc<RwLock<T>> instead for thread-safe shared mutable state. If you need multiple owners, Arc is the thread-safe reference counter.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        // Also check for raw pointer dereferences
        for (i, line) in code.lines().enumerate() {
            if RAW_PTR_RE.is_match(line) && !line.trim().starts_with("//") {
                findings.push(LangFinding {
                    rule_id: "RUST-SEC-012".to_string(),
                    severity: "high".to_string(),
                    line: i + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line.to_string(),
                    problem: "Raw pointer dereference detected. Raw pointers are unsafe and bypass Rust's memory safety guarantees.".to_string(),
                    fix_hint: "Prefer safe Rust abstractions. If raw pointers are necessary, wrap them in a safe API with clear safety invariants documented.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-013: Integer Wraparound (CWE-190)
// Severity: high
// wrapping_add, overflow_add without check, usize::MAX as i32
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustIntegerWraparound;

impl LangRule for RustIntegerWraparound {
    fn id(&self) -> &str { "RUST-SEC-013" }
    fn name(&self) -> &str { "Integer Overflow / Wraparound Risk" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (i, line) in code.lines().enumerate() {
            if line.trim().starts_with("//") || line.trim().starts_with("/*") {
                continue;
            }
            for (pat, label) in &*WRAPAROUND_PATTERNS {
                let re = Regex::new(pat).unwrap();
                if re.is_match(line) {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: "RUST-SEC-013".to_string(),
                        severity: "high".to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.to_string(),
                        problem: format!("Integer wraparound risk: {}. This can lead to unexpected behavior in security-critical calculations.", label),
                        fix_hint: "Use checked arithmetic (checked_add, checked_sub) that returns None on overflow. For performance-critical code where wraparound is intentional, document it clearly and use wrapping_* explicitly. Never cast usize::MAX to signed types.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                    break;
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-014: Insecure TLS Configuration (CWE-295)
// Severity: high | OWASP A02:2021
// reqwest with verify(false), rustls without proper config
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustInsecureTls;

impl LangRule for RustInsecureTls {
    fn id(&self) -> &str { "RUST-SEC-014" }
    fn name(&self) -> &str { "Insecure TLS Configuration" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (i, line) in code.lines().enumerate() {
            if line.trim().starts_with("//") || line.trim().starts_with("/*") {
                continue;
            }
            for (pat, problem) in &*INSECURE_TLS_PATTERNS {
                let re = Regex::new(pat).unwrap();
                if re.is_match(line) {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: "RUST-SEC-014".to_string(),
                        severity: "high".to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.to_string(),
                        problem: problem.to_string(),
                        fix_hint: "Always verify TLS certificates in production. Use the system's certificate store via native_tls or rustls with default configuration. If you must disable verification (e.g., for testing), guard it behind a feature flag and never use in production.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                    break;
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-015: Panic in Public API (CWE-248)
// Severity: medium
// pub fn with unwrap/expect without #[track_caller]
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustPanicPublicApi;

impl LangRule for RustPanicPublicApi {
    fn id(&self) -> &str { "RUST-SEC-015" }
    fn name(&self) -> &str { "Panic Risk in Public API" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let panic_methods = ["unwrap", "expect", "unwrap_err", "expect_err", "unwrap_unchecked"];

        for func in &tree.functions {
            let is_public = func.name.starts_with("pub ") || func.name.contains("pub fn") || func.name.contains("pub const");
            if !is_public { continue; }

            // Get function body lines
            if func.end_line > func.start_line {
                let lines: Vec<_> = code.lines().skip(func.start_line - 1).take(func.end_line - func.start_line + 1).collect();
                let func_code = lines.join("\n");

                for method in &panic_methods {
                    let re = Regex::new(&format!(r"\b{}\s*\(", method)).unwrap();
                    let has_track_caller = func_code.contains("#[track_caller]");

                    for m in re.find_iter(&func_code) {
                        if !has_track_caller {
                            let line_offset = code[..m.start()].matches('\n').count() + 1;
                            let line_text = code.lines().nth(line_offset - 1).unwrap_or("");
                            findings.push(LangFinding {
                                rule_id: "RUST-SEC-015".to_string(),
                                severity: "medium".to_string(),
                                line: line_offset,
                                column: 0,
                                start_byte: 0,
                                end_byte: 0,
                                snippet: line_text.to_string(),
                                problem: format!("Public API uses {}(), which panics on None/Err. This creates a denial-of-service risk for callers.", method),
                                fix_hint: "Return a Result or Option instead of panicking. If panicking is acceptable, add #[track_caller] for better stack traces. Consider using unwrap_or, unwrap_or_else, or ? operator.".to_string(),
                                auto_fix_available: false,
                        replacement: String::new(),
                            });
                        }
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-016: Format String via dbg! Macro (CWE-134)
// Severity: low
// dbg! with user-controlled input
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustDbgFormatString;

impl LangRule for RustDbgFormatString {
    fn id(&self) -> &str { "RUST-SEC-016" }
    fn name(&self) -> &str { "Debug Macro with Potentially Sensitive Data" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let sensitive_keywords = ["password", "secret", "token", "key", "auth", "credential", "ssn", "credit"];

        for (i, line) in code.lines().enumerate() {
            if DBG_MACRO_RE.is_match(line) {
                let line_lower = line.to_lowercase();
                if sensitive_keywords.iter().any(|k| line_lower.contains(k)) {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: "RUST-SEC-016".to_string(),
                        severity: "low".to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.to_string(),
                        problem: "dbg! macro used with potentially sensitive data. dbg! prints to stderr and can leak sensitive information in logs.".to_string(),
                        fix_hint: "Remove dbg! calls before production. Use proper logging at info/warn level for debugging. Sensitive values should be redacted in logs.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// RUST-SEC-026: Integer Overflow — Unchecked Arithmetic Operations
// Severity: high | CWE-190
// AI generates arithmetic without checked operations
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustIntegerOverflowArith;

impl LangRule for RustIntegerOverflowArith {
    fn id(&self) -> &str { "RUST-SEC-026" }
    fn name(&self) -> &str { "Unchecked Integer Overflow in Arithmetic" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (pat, desc) in &*OVERFLOW_ARITH_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                if line_text.trim().starts_with("//") || line_text.trim().starts_with("/*") {
                    continue;
                }

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Integer overflow risk: {} on line {}. Default Rust integer arithmetic panics on overflow in debug mode.", desc, line),
                    fix_hint: "Use checked arithmetic (checked_add, checked_sub, checked_mul), wrapping arithmetic (wrapping_add, etc.), or saturating arithmetic (saturating_add, etc.) depending on your needs.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// RUST-SEC-018: Use After Free — Freed Memory Access Pattern
// Severity: high | CWE-416
// AI generates code that may access freed memory via pointers
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustUseAfterFreePattern;

impl LangRule for RustUseAfterFreePattern {
    fn id(&self) -> &str { "RUST-SEC-018" }
    fn name(&self) -> &str { "Memory Freed Then Accessed Pattern" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (pat, desc) in &*UAF_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Use-after-free risk: {} on line {}. Direct pointer manipulation can lead to use-after-free vulnerabilities.", desc, line),
                    fix_hint: "Prefer safe Rust abstractions. Use Box<T>, Rc<T>, Arc<T>, or std::mem::replace/std::mem::take instead of raw pointer operations.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-019: Insecure Random Number Generation
// Severity: medium | CWE-338
// AI generates code using math::rand instead of crypto::rand
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustInsecureRandomGen;

impl LangRule for RustInsecureRandomGen {
    fn id(&self) -> &str { "RUST-SEC-019" }
    fn name(&self) -> &str { "Insecure Random Number Generation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (pat, desc) in &*INSECURE_RAND_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Insecure randomness: {} on line {}. The 'rand' crate is not cryptographically secure.", desc, line),
                    fix_hint: "Use the 'rand' crate with a cryptographic random number generator: rand::rngs::StdRng seeded from rand::SeedableRng::from_entropy(), or use the 'getrandom' crate for OS-level randomness.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-020: Incorrect unsafe Block Scope
// Severity: medium | CWE-682
// AI generates unsafe blocks that are too broad
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustUnsafeTooBroad;

impl LangRule for RustUnsafeTooBroad {
    fn id(&self) -> &str { "RUST-SEC-020" }
    fn name(&self) -> &str { "Unsafe Block Scope Too Broad" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let lines: Vec<&str> = code.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if UNSAFE_BLOCK_RE2.is_match(line) {
                let line_num = i + 1;
                let trimmed = line.trim();
                let indent = line.len() - line.trim_start().len();

                let mut brace_count = 0;
                let mut found_open = false;
                let mut unsafe_end = i;
                let unsafe_lines = 0;

                for j in i..lines.len() {
                    let _unsafe_lines = lines[j].matches('{').count();
                    brace_count += lines[j].matches('{').count() - lines[j].matches('}').count();

                    if lines[j].contains("unsafe") && lines[j].contains("{") && !found_open {
                        found_open = true;
                    }

                    if brace_count == 0 && found_open {
                        unsafe_end = j;
                        break;
                    }
                }

                let total_unsafe_lines = unsafe_end - i + 1;

                if total_unsafe_lines > 20 {
                    let (start, end) = get_line_offsets(code, line_num);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: line_num,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: trimmed.to_string(),
                        problem: format!("Unsafe block spans {} lines (lines {}-{}). Large unsafe blocks are hard to audit and increase the attack surface.", total_unsafe_lines, line_num, unsafe_end + 1),
                        fix_hint: "Minimize unsafe scope: extract each unsafe operation into a separate, small, well-documented unsafe function. Each unsafe block should do one thing with documented safety invariants.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-021: Hardcoded Secrets
// Severity: high | CWE-798
// AI generates code with hardcoded API keys, passwords, tokens
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustHardcodedSecrets;

impl LangRule for RustHardcodedSecrets {
    fn id(&self) -> &str { "RUST-SEC-021" }
    fn name(&self) -> &str { "Hardcoded Secrets in Code" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (pat, desc) in &*HARDCODED_SECRETS_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Hardcoded secret detected: {} on line {}. Credentials should never be stored in source code.", desc, line),
                    fix_hint: "Use environment variables: let key = env::var(\"API_KEY\").expect(\"API_KEY must be set\"); or use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler).".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-022: Wrong Type Cast
// Severity: medium | CWE-704
// AI generates incorrect transmute or type casting operations
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustWrongTypeCast;

impl LangRule for RustWrongTypeCast {
    fn id(&self) -> &str { "RUST-SEC-022" }
    fn name(&self) -> &str { "Incorrect Type Cast" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (pat, desc) in &*WRONG_CAST_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Type casting issue: {} on line {}. Incorrect casting can cause undefined behavior, data corruption, or panics.", desc, line),
                    fix_hint: "mem::transmute requires source and destination to have the same size. For type conversions, prefer TryFrom/TryInto or explicit checked conversions. Ensure the target type can represent the source value.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-CRYPT-001: Insecure Cryptography in Rust
// Severity: critical | CWE-327, CWE-295
// Detects insecure cryptographic practices in Rust code
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustInsecureCrypto;

impl LangRule for RustInsecureCrypto {
    fn id(&self) -> &str { "RUST-CRYPT-001" }
    fn name(&self) -> &str { "Insecure Cryptographic Practices" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check for md5/sha1 crate imports
        for imp in &tree.imports {
            if imp.module.contains("md5") || imp.name.contains("md5") {
                let (start, end) = get_line_offsets(code, imp.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: imp.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: imp.module.clone(),
                    problem: "MD5 crate usage detected. CWE-327: MD5 is cryptographically broken \
                        for security purposes (collision attacks, chosen prefix attacks).".to_string(),
                    fix_hint: "Use SHA-256 or SHA-3 for hashing. Example: use sha2::{Sha256, Digest}; \
                        let mut hasher = Sha256::new(); hasher.update(data); let result = hasher.finalize();".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
            if imp.module.contains("sha1") || imp.name.contains("sha1") {
                let (start, end) = get_line_offsets(code, imp.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: imp.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: imp.module.clone(),
                    problem: "SHA1 crate usage detected. CWE-327: SHA-1 is deprecated for \
                        digital signatures and security certificates.".to_string(),
                    fix_hint: "Use SHA-256 or SHA-3 for hashing. Example: use sha2::{Sha256, Digest}; \
                        let mut hasher = Sha256::new(); hasher.update(data);".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        // Check for ECB mode AES
        for call in &tree.calls {
            if call.callee.contains("Ecb") || call.callee.contains("ecb") {
                let (start, end) = get_line_offsets(code, call.start_line);
                let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: "AES ECB mode detected. CWE-327: ECB mode encrypts identical blocks \
                        identically, revealing patterns in the plaintext.".to_string(),
                    fix_hint: "Use AES-GCM or ChaCha20-Poly1305 for authenticated encryption. \
                        Example: use aes_gcm::{Aes256Gcm, Nonce}; or use chacha20poly1305::ChaCha20Poly1305.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        // Check for RSA with small key sizes
        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            for (pattern, _) in &*CRYPT_SMALL_RSA_PATTERNS {
                let re = Regex::new(pattern).unwrap();
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
                        problem: "RSA with small key size (< 2048 bits). CWE-327: Small RSA keys \
                                can be factored in minutes to hours.".to_string(),
                        fix_hint: "Use RSA keys of at least 2048 bits. For security, prefer 4096 bits. \
                                Alternatively, use elliptic curve cryptography (P-256, P-384, or X25519).".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        // Check for ring::digest with weak algorithms
        for (pattern, desc) in &*CRYPT_WEAK_HASH_PATTERNS {
            let re = Regex::new(pattern).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                if !findings.iter().any(|f: &LangFinding| f.line == line) {
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("Weak cryptography: {}", desc),
                        fix_hint: "Use SHA-256 or SHA-3 for cryptographic hashing. \
                                For the 'ring' crate: use Sha256::digest() instead of md5.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-023: XSS via HTML Template Rendering
// Severity: high | CWE-79
// AI generates HTML templates with unsanitized user input
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustXssRule;

impl LangRule for RustXssRule {
    fn id(&self) -> &str { "RUST-SEC-023" }
    fn name(&self) -> &str { "Potential XSS via HTML Template Rendering" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let template_imports = ["askama", "ttera", "horrorshow", "markup", "maud"];

        let has_template = tree.imports.iter().any(|imp| {
            template_imports.iter().any(|t| imp.module.contains(t))
        });

        if !has_template {
            return findings;
        }

        let dangerous_calls: Vec<&str> = vec![
            "render_str", "render", "to_string", "html", "write",
        ];

        let user_input_patterns = ["request", "input", "param", "user", "args", "body", "query", "form"];

        for call in &tree.calls {
            if dangerous_calls.iter().any(|dc| call.callee.contains(dc)) {
                let has_user_input = !call.arguments.is_empty()
                    && call.arguments.iter().any(|a| {
                        user_input_patterns.iter().any(|p| a.contains(p))
                    });

                if has_user_input {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = get_line_text(code, call.start_line)
                        .unwrap_or_default();

                    if !line_text.contains("escape") && !line_text.contains("sanitize")
                        && !line_text.contains("Html::") && !line_text.contains("Text::") {
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.trim().to_string(),
                            problem: format!(
                                "Template rendering '{}' with user-controlled input. \
                                CWE-79: Cross-Site Scripting — if unescaped, attackers can inject \
                                malicious scripts via template parameters.",
                                call.callee
                            ),
                            fix_hint: "Always escape user input in templates. Use framework-provided \
                                escaping (askama auto-escapes by default for expressions). Avoid \
                                raw() or SafeString unless absolutely necessary.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                    }
                }
            }
        }

        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-024: Server-Side Request Forgery (SSRF)
// Severity: high | CWE-918
// AI generates HTTP requests to user-controlled URLs
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustSsrfRule;

impl LangRule for RustSsrfRule {
    fn id(&self) -> &str { "RUST-SEC-024" }
    fn name(&self) -> &str { "Server-Side Request Forgery (SSRF)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let http_clients = ["reqwest", "isahc", "ureq", "surf", "hyper", "actix-web"];

        let has_http = tree.imports.iter().any(|imp| {
            http_clients.iter().any(|c| imp.module.contains(c))
        });

        if !has_http {
            return findings;
        }

        let user_input_patterns = ["request", "input", "param", "user", "args", "body", "query", "url", "endpoint"];

        for call in &tree.calls {
            let is_http_call = http_clients.iter().any(|c| call.callee.contains(c));
            if is_http_call {
                let has_user_url = !call.arguments.is_empty()
                    && call.arguments.iter().any(|a| {
                        user_input_patterns.iter().any(|p| a.contains(p))
                    });

                if has_user_url {
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
                            "HTTP client call '{}' with user-controlled URL. \
                            CWE-918: SSRF — attackers can make the server request \
                            internal services, cloud metadata, or external systems.",
                            call.callee
                        ),
                        fix_hint: "Validate and allowlist URLs before making requests. \
                            Reject URLs containing private IP ranges (10.x, 172.16.x, 192.168.x, 127.x), \
                            localhost, or cloud metadata endpoints (169.254.169.254). \
                            Use a URL parser to check the scheme (only http/https).".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
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
// RUST-SEC-025: Insecure Deserialization
// Severity: critical | CWE-502
// AI deserializes untrusted data with unsafe formats
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustInsecureDeserRule;

impl LangRule for RustInsecureDeserRule {
    fn id(&self) -> &str { "RUST-SEC-025" }
    fn name(&self) -> &str { "Insecure Deserialization" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_imports = ["bincode", "rmp_serde", "serde_derive::deserialize"];

        let has_dangerous = tree.imports.iter().any(|imp| {
            dangerous_imports.iter().any(|d| imp.module.contains(d) || imp.name.contains(d))
        });

        if !has_dangerous {
            return findings;
        }

        let dangerous_calls = vec![
            ("bincode::decode_from_slice", "bincode decode — vulnerable to malformed input"),
            ("bincode::deserialize", "bincode deserialize — unsafe without size limits"),
            ("rmp_serde::from_read", "MessagePack deserialize from reader"),
            ("rmp_serde::from_slice", "MessagePack deserialize from bytes"),
            ("serde_json::from_str", "JSON deserialize with user input"),
        ];

        let user_input_patterns = ["request", "input", "param", "user", "args", "body", "query", "data"];

        for call in &tree.calls {
            let is_dangerous = dangerous_calls.iter().any(|(pattern, _)| call.callee.contains(pattern));
            if is_dangerous {
                let has_user_input = !call.arguments.is_empty()
                    && call.arguments.iter().any(|a| {
                        user_input_patterns.iter().any(|p| a.contains(p))
                    });

                if has_user_input {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = get_line_text(code, call.start_line)
                        .unwrap_or_default();

                    let desc = dangerous_calls.iter()
                        .find(|(pattern, _)| call.callee.contains(pattern))
                        .map(|(_, d)| d)
                        .unwrap_or(&"deserialization call");

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "Insecure deserialization: {}. CWE-502: Deserializing untrusted data \
                            can lead to remote code execution, type confusion, or denial of service.",
                            desc
                        ),
                        fix_hint: "Never deserialize untrusted data without validation. \
                            For JSON: use serde with explicit type bounds. \
                            For binary formats: use bincode with SizeLimit. \
                            Consider using a safe replacement like postcard for serialization. \
                            Validate schema and data bounds before deserialization.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
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
// RUST-SEC-027: Timing Side-Channel AES (CWE-208)
// Severity: high
// Non-constant-time AES operations that leak timing information
// ─────────────────────────────────────────────────────────────────────────────
static AES_NON_CONST_TIME_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"aes::\w+::(?:Aes|Aes256|Aes128)::(?:new|encrypt|decrypt)"#, "AES block cipher without CTR/GCM mode — vulnerable to timing side-channel"),
    (r#"Aes::(?:new|encrypt_block|decrypt_block)"#, "AES encrypt/decrypt without authenticated encryption mode"),
    (r#"aes_gcm::(?:AesGcm|Gcm)::new\s*\(\s*(?!.*(?:ccm|gcm|ctr))"#, "AES-GCM constructor without proper nonce"),
    (r#"cbc::Encryptor|cbc::Decryptor"#, "AES-CBC mode without HMAC — vulnerable to padding oracle attacks"),
]);

pub struct RustTimingSideChannelAes;

impl LangRule for RustTimingSideChannelAes {
    fn id(&self) -> &str { "RUST-SEC-027" }
    fn name(&self) -> &str { "Timing Side-Channel in AES Operations" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let has_aes = tree.imports.iter().any(|imp| {
            imp.module.contains("aes") || imp.name.contains("aes")
        });

        if !has_aes {
            return findings;
        }

        for (pat, desc) in &*AES_NON_CONST_TIME_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Timing side-channel vulnerability: {}. CWE-208: Non-constant-time cryptographic operations can leak key material through timing differences.", desc),
                    fix_hint: "Use authenticated encryption modes like AES-GCM or ChaCha20-Poly1305. These provide both confidentiality and integrity, and are designed to be constant-time.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-028: TLS Verification Disabled (CWE-295)
// Severity: critical
// rustls dangerous_configuration() or reqwest with disabled verification
// ─────────────────────────────────────────────────────────────────────────────
static TLS_DANGEROUS_CONFIG_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"dangerous_configuration\s*\(\s*\)\s*\."#, "rustls dangerous_configuration() — allows disabling TLS verification"),
    (r#"rustls::ConfigBuilder::dangerous\s*\(\s*\)"#, "rustls ConfigBuilder::dangerous() — disables certificate verification"),
    (r#"dangerously_disable_backtrace\s*\(\s*\)"#, "reqwest dangerously_disable_backtrace — disables security features"),
    (r#"DangerousClientSessionBuilder"#, "DangerousClientSessionBuilder — rustls session without verification"),
]);

pub struct RustTlsVerifyDisabled;

impl LangRule for RustTlsVerifyDisabled {
    fn id(&self) -> &str { "RUST-SEC-028" }
    fn name(&self) -> &str { "TLS Certificate Verification Disabled" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (pat, desc) in &*TLS_DANGEROUS_CONFIG_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("TLS verification disabled: {}. CWE-295: Disabling certificate verification allows man-in-the-middle attacks.", desc),
                    fix_hint: "Never disable TLS verification in production. Use the default TLS configuration which validates certificates properly. Only disable for local development/testing with explicit comments.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-029: Regex Catastrophic Backtracking (CWE-1333)
// Severity: medium
// Nested quantifiers like (a+)+, (a*)* that cause exponential complexity
// ─────────────────────────────────────────────────────────────────────────────
static REGEX_CATASTROPHIC_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"\([^)]*\+[^)]*\)\+"#, "nested quantifier: (x+)+ — catastrophic backtracking"),
    (r#"\([^)]*\*[^)]*\)\*"#, "nested quantifier: (x*)* — catastrophic backtracking"),
    (r#"\([^)]*\+[^)]*\)\*"#, "nested quantifier: (x+)* — catastrophic backtracking"),
    (r#"\([^)]*\?[^)]*\)\*"#, "nested quantifier: (x?)* — catastrophic backtracking"),
    (r#"\([^)]*\+[^)]*\)\?"#, "nested quantifier: (x+)? — catastrophic backtracking"),
    (r#"\([^+*?]*\+\)[+*?]"#, "possessive quantifier followed by quantifier"),
]);

pub struct RustRegexCatastrophicBacktracking;

impl LangRule for RustRegexCatastrophicBacktracking {
    fn id(&self) -> &str { "RUST-SEC-029" }
    fn name(&self) -> &str { "Regex Catastrophic Backtracking" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;

            let is_regex_line = line.contains("Regex::new")
                || line.contains("regex!")
                || line.contains("is_match")
                || line.contains("find")
                || line.contains("captures");

            if !is_regex_line { continue; }

            for (pat, desc) in &*REGEX_CATASTROPHIC_PATTERNS {
                let re = Regex::new(pat).unwrap();
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
                        problem: format!("Regex catastrophic backtracking: {}. CWE-1333: Nested quantifiers can cause exponential time complexity on certain inputs.", desc),
                        fix_hint: "Rewrite the regex to avoid nested quantifiers. Use atomic groups (not available in Rust regex) or possessive quantifiers. Simplify the pattern. Consider limiting input length.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                    break;
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-030: Unbounded Vec Allocation (CWE-400)
// Severity: high
// vec![x; user_input] or Vec::from_elem with large count
// ─────────────────────────────────────────────────────────────────────────────
static VEC_UNBOUNDED_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"vec!\s*\[[^\]]*;\s*(?:request|input|param|user|len|count|size)"#, "vec! macro with user-controlled count — can exhaust memory"),
    (r#"Vec::from_elem\s*\([^,]+,\s*(?:request|input|param|user|len|count|size)"#, "Vec::from_elem with user-controlled count"),
    (r#"std::iter::repeat\s*\([^)]*\)\.take\s*\([^)]*(?:request|input|param|user|len)"#, "Iterator repeat().take() with user-controlled count"),
    (r#"vec!\s*\[[^\]]*;\s*\d{5,}\]"#, "vec! macro with very large count (5+ digits)"),
]);

pub struct RustUnboundedVecAllocation;

impl LangRule for RustUnboundedVecAllocation {
    fn id(&self) -> &str { "RUST-SEC-030" }
    fn name(&self) -> &str { "Unbounded Vec Allocation (Memory Exhaustion)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (pat, desc) in &*VEC_UNBOUNDED_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Unbounded allocation: {}. CWE-400: Allocating memory based on untrusted input can cause denial of service.", desc),
                    fix_hint: "Always validate and bound the allocation size. Example: let count = std::cmp::min(user_count, MAX_SIZE); let vec = vec![value; count];".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-031: HashDoS Vulnerability (CWE-682)
// Severity: medium
// HashMap/HashSet with default hasher vulnerable to collision attacks
// ─────────────────────────────────────────────────────────────────────────────
static HASH_DOS_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"HashMap::<[^>]+>::\s*new\s*\(\s*(?:\)|$)"#, "HashMap::new() with default hasher — vulnerable to HashDoS"),
    (r#"HashSet::<[^>]+>::\s*new\s*\(\s*(?:\)|$)"#, "HashSet::new() with default hasher — vulnerable to HashDoS"),
    (r#"std::collections::HashMap::new\s*\("#, "std::collections::HashMap with default hasher"),
    (r#"FxHashMap|FxHashSet"#, "FxHashMap/FxHashSet — not DoS-resistant, faster but insecure"),
    (r#"AHashMap|AHashSet"#, "AHashMap/AHashSet — faster but may not be DoS-resistant"),
]);

pub struct RustHashDosVulnerability;

impl LangRule for RustHashDosVulnerability {
    fn id(&self) -> &str { "RUST-SEC-031" }
    fn name(&self) -> &str { "HashDoS Vulnerability (DefaultHasher)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let has_hashmap = tree.imports.iter().any(|imp| {
            imp.module.contains("HashMap") || imp.module.contains("HashSet") || imp.module.contains("collections")
        }) || code.contains("HashMap") || code.contains("HashSet");

        if !has_hashmap {
            return findings;
        }

        let has_user_input = tree.calls.iter().any(|call| {
            call.arguments.iter().any(|a| {
                a.contains("request") || a.contains("input") || a.contains("body") || a.contains("param")
            })
        });

        for (pat, desc) in &*HASH_DOS_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("HashDoS risk: {}. CWE-682: DefaultHasher is vulnerable to collision attacks where attackers craft inputs with identical hash values.", desc),
                    fix_hint: "Use a DoS-resistant hasher: BuildMap, HashMap with FxHasher in no_std, or implement custom Hash trait. Consider using IndexMap for ordered maps with better defaults.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        if has_user_input && has_hashmap {
            for call in &tree.calls {
                if (call.callee.contains("HashMap::new") || call.callee.contains("HashSet::new"))
                    && !call.callee.contains("with_hasher")
                    && !call.callee.contains("default") {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: "HashMap/HashSet with default hasher in code that processes user input. CWE-682: Vulnerable to HashDoS attacks.".to_string(),
                        fix_hint: "Use a DoS-resistant hasher like BuildMap (fnv crate) or consider using IndexMap.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-032: Format String Injection (CWE-134)
// Severity: high
// format!("{}", user_input) or println!(user_input) — direct user input as format
// ─────────────────────────────────────────────────────────────────────────────
static FORMAT_STRING_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"format!\s*\(\s*(?:request|input|param|user|args|arg)[^)]*\)"#, "format!() with user input as format string — CWE-134"),
    (r#"format!\s*\(\s*\"[^\"]*\"[^\)]*(?:request|input|param|user)"#, "format!() using user variable in format args"),
    (r#"println!\s*\(\s*(?:request|input|param|user|args|arg)\s*\)"#, "println!() with user input as sole argument — CWE-134"),
    (r#"eprintln!\s*\(\s*(?:request|input|param|user|args|arg)\s*\)"#, "eprintln!() with user input — potential format string injection"),
    (r#"write!\s*\([^,]+,\s*(?:request|input|param|user|args|arg)\s*\)"#, "write!() with user input as format string"),
    (r#"panic!\s*\(\s*(?:request|input|param|user)[^)]*\)"#, "panic!() with user input as message"),
]);

pub struct RustFormatStringInjection;

impl LangRule for RustFormatStringInjection {
    fn id(&self) -> &str { "RUST-SEC-032" }
    fn name(&self) -> &str { "Format String Injection" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (pat, desc) in &*FORMAT_STRING_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Format string vulnerability: {}. CWE-134: Passing user input directly as a format string can cause crashes or information disclosure.", desc),
                    fix_hint: "Never use user input as the format string. Always use positional arguments: format!(\"{{}}\", user_input) instead of format!(user_input).".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-033: YAML Unsafe Deserialization (CWE-502)
// Severity: critical
// serde_yaml::from_str with user input without safe deserializer
// ─────────────────────────────────────────────────────────────────────────────
static YAML_UNSAFE_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"serde_yaml::from_str\s*\([^)]*(?:request|input|param|user|body|args)"#, "serde_yaml::from_str with user input — CWE-502"),
    (r#"Yaml::load\s*\([^)]*(?:request|input|param|user|body)"#, "Yaml::load with user input — unsafe deserialization"),
    (r#"serde_yaml::from_reader\s*\([^)]*(?:request|input|param|user)"#, "serde_yaml::from_reader with user input"),
    (r#"serde_yaml::Deserializer::from"#, "serde_yaml Deserializer — ensure input is validated"),
]);

pub struct RustYamlUnsafeDeserialization;

impl LangRule for RustYamlUnsafeDeserialization {
    fn id(&self) -> &str { "RUST-SEC-033" }
    fn name(&self) -> &str { "YAML Unsafe Deserialization" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let has_yaml = tree.imports.iter().any(|imp| {
            imp.module.contains("serde_yaml") || imp.module.contains("yaml")
        });

        if !has_yaml {
            return findings;
        }

        for (pat, desc) in &*YAML_UNSAFE_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("YAML deserialization vulnerability: {}. CWE-502: Deserializing untrusted YAML can lead to code execution in some configurations.", desc),
                    fix_hint: "Always validate YAML input before deserialization. Use explicit type deserialization with serde. Consider using a strict YAML parser that avoids arbitrary code execution.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-034: Environment Variable Injection (CWE-78)
// Severity: medium
// std::env::var() used in command paths or database connections
// ─────────────────────────────────────────────────────────────────────────────
static ENV_INJECTION_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"Command::new\s*\(\s*(?:request|input|param|user|path).*\)|Command::new\s*\(\s*std::env::var"#, "Command::new with env var that could be user-controlled"),
    (r#"std::env::var\s*\([^)]*\)\s*\.(?:unwrap|expect)"#, "env::var with unwrap in command context"),
    (r#"File::open\s*\(\s*std::env::var"#, "File::open with env var in path — potential path traversal"),
    (r#"std::fs::read\s*\(\s*std::env::var"#, "std::fs::read with env var in path"),
    (r#"std::env::var\s*\([^)]*\)\s*\+\s*(?:request|input|param|user)"#, "Env var concatenated with user input"),
]);

pub struct RustEnvVariableInjection;

impl LangRule for RustEnvVariableInjection {
    fn id(&self) -> &str { "RUST-SEC-034" }
    fn name(&self) -> &str { "Environment Variable Injection" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let has_env = code.contains("std::env::var") || code.contains("env::var") || code.contains("std::env!");

        if !has_env {
            return findings;
        }

        for (pat, desc) in &*ENV_INJECTION_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Environment variable injection risk: {}. CWE-78: Using environment variables in security-sensitive operations can be manipulated by attackers.", desc),
                    fix_hint: "Avoid using environment variables in security-sensitive paths. If necessary, validate env var contents and use allowlists. Prefer compile-time constants for critical paths.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-035: Cleartext Transmission (CWE-319)
// Severity: high
// HTTP (not HTTPS) for sensitive data transmission
// ─────────────────────────────────────────────────────────────────────────────
static CLEARTEXT_TRANSMISSION_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"http://(?:?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\"'\s]*"#, "HTTP URL without HTTPS — sensitive data may be transmitted in cleartext"),
    (r#"Client::new\s*\(\s*\)\s*\.\s*get\s*\(\s*\"http://"#, "reqwest client making HTTP request"),
    (r#"Request::new\s*\(\s*Method::[Gg]et\s*,\s*\"http://"#, "HTTP request to non-HTTPS URL"),
    (r#"surf::Client::new\s*\(\s*\)\s*\.\s*get\s*\(\s*\"http://"#, "surf HTTP request"),
    (r#"isahc::get\s*\(\s*\"http://"#, "isahc HTTP GET request"),
]);

pub struct RustCleartextTransmission;

impl LangRule for RustCleartextTransmission {
    fn id(&self) -> &str { "RUST-SEC-035" }
    fn name(&self) -> &str { "Cleartext Transmission of Sensitive Data" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let http_clients = ["reqwest", "isahc", "ureq", "surf", "hyper", "actix-web"];
        let has_http = tree.imports.iter().any(|imp| {
            http_clients.iter().any(|c| imp.module.contains(c))
        }) || code.contains("http::");

        if !has_http {
            return findings;
        }

        let sensitive_keywords = ["auth", "token", "password", "secret", "key", "credential", "session", "api", "private", "sensitive"];

        for (pat, desc) in &*CLEARTEXT_TRANSMISSION_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                let line_lower = line_text.to_lowercase();
                let has_sensitive = sensitive_keywords.iter().any(|k| line_lower.contains(&k.to_lowercase()));

                if has_sensitive {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("Cleartext transmission: {}. CWE-319: Sensitive data sent over HTTP can be intercepted by attackers via network sniffing.", desc),
                        fix_hint: "Always use HTTPS for transmitting sensitive data. Configure TLS certificates properly. Example: https://api.example.com instead of http://.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-036: JWT HS256 Weak Secret (CWE-347)
// Severity: high
// jsonwebtoken with HS256 and short secret (< 32 chars)
// ─────────────────────────────────────────────────────────────────────────────
#[allow(dead_code)]
static JWT_WEAK_SECRET_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"EncodingKey::from_rsa_pem|EncodingKey::from_ec_pem"#, "RSA/EC key used with HS256 — algorithm confusion vulnerability"),
    (r#"jsonwebtoken::EncodingKey"#, "JWT encoding key detected"),
    (r#"HS256|HS384|HS512"#, "HMAC-SHA JWT algorithm"),
]);

pub struct RustJwtWeakSecret;

impl LangRule for RustJwtWeakSecret {
    fn id(&self) -> &str { "RUST-SEC-036" }
    fn name(&self) -> &str { "JWT with Weak or Misconfigured Secret" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let has_jwt = tree.imports.iter().any(|imp| {
            imp.module.contains("jsonwebtoken") || imp.module.contains("jwt")
        });

        if !has_jwt {
            return findings;
        }

        let has_hs256 = code.contains("HS256") || code.contains("HS384") || code.contains("HS512");
        let has_short_secret = Regex::new(r#"secret\s*=\s*["'][^'"]{1,31}["']"#).unwrap().is_match(code);
        let has_rsa_with_hs = Regex::new(r#"rsa_pem|ec_pem|RS256|RS384|RS512"#).unwrap().is_match(code);

        if has_hs256 && has_short_secret {
            for m in Regex::new(r#"secret\s*=\s*["'][^'"]{1,31}["']"#).unwrap().find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: "JWT with short secret (< 32 characters). CWE-347: Short HMAC secrets can be brute-forced, allowing attackers to forge valid tokens.".to_string(),
                    fix_hint: "Use a cryptographically random secret of at least 32 characters. Prefer RS256 (RSA) or ES256 (ECDSA) algorithms for better security. Store secrets securely.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        if has_hs256 && has_rsa_with_hs {
            for line_idx in 0..code.lines().count() {
                let line = code.lines().nth(line_idx).unwrap_or("");
                if line.contains("HS256") && (line.contains("rsa_pem") || line.contains("ec_pem") || line.contains("RS256")) {
                    let line_num = line_idx + 1;
                    let (start, end) = get_line_offsets(code, line_num);

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: line_num,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.trim().to_string(),
                        problem: "Algorithm confusion: RSA/EC key used with HMAC algorithm. CWE-347: Attacker can switch algorithm and sign with public key.".to_string(),
                        fix_hint: "Always verify the 'alg' header matches your expected algorithm. Use RS256 for RSA keys, ES256 for ECDSA keys. Never accept 'none' algorithm.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-037: Predictable Random for Security (CWE-338)
// Severity: high
// rand::thread_rng() or rand::random() used for tokens/passwords
// ─────────────────────────────────────────────────────────────────────────────
#[allow(dead_code)]
static PREDICTABLE_RANDOM_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"rand::thread_rng\s*\(\s*\)"#, "rand::thread_rng — not cryptographically secure"),
    (r#"rand::random::<(?:String|Token|Secret|Password)"#, "rand::random for security-sensitive type"),
    (r#"rand::Rng::gen::<(?:String|Token|Secret)"#, "Rng::gen for security-sensitive type"),
    (r#"rand::seq::SliceRandom::choose\s*\([^)]*\)"#, "rand::choose for security-sensitive selection"),
    (r#"use\s+rand\s*;[\s\S]{0,100}(?:password|token|secret|key)"#, "rand crate used near security-sensitive code"),
]);

pub struct RustPredictableRandom;

impl LangRule for RustPredictableRandom {
    fn id(&self) -> &str { "RUST-SEC-037" }
    fn name(&self) -> &str { "Predictable Random for Security-Sensitive Use" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let has_rand = tree.imports.iter().any(|imp| {
            imp.module.contains("rand")
        }) || code.contains("rand::");

        if !has_rand {
            return findings;
        }

        let security_sensitive = ["password", "token", "secret", "key", "salt", "nonce", "session_id", "otp", "captcha"];

        for call in &tree.calls {
            let uses_thread_rng = call.callee.contains("thread_rng");
            let uses_random = call.callee.contains("rand::random");
            let uses_gen = call.callee.contains("gen::<");

            let is_security_sensitive = security_sensitive.iter().any(|s| {
                call.callee.to_lowercase().contains(s)
            });

            if (uses_thread_rng || uses_random || uses_gen) && is_security_sensitive {
                let (start, end) = get_line_offsets(code, call.start_line);
                let line_text = get_line_text(code, call.start_line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Predictable random for security use: '{}' used for {}. CWE-338: rand::thread_rng() is not cryptographically secure.", call.callee, "security-sensitive purpose"),
                    fix_hint: "Use a CSPRNG: rand::rngs::StdRng from rand::SeedableRng::from_entropy() or the getrandom crate. Example: let mut rng = StdRng::from_entropy(); rng.gen::<u32>()".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-038: Cookie Missing Secure Flag (CWE-614)
// Severity: medium
// Cookie::new() without .secure(true)
// ─────────────────────────────────────────────────────────────────────────────
#[allow(dead_code)]
static COOKIE_INSECURE_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"Cookie::new\s*\([^)]*\)(?!\s*\.\s*secure\s*\(\s*true)"#, "Cookie::new without .secure(true) — missing secure flag"),
    (r#"cookie::Cookie::new\s*\([^)]*\)(?!\s*\.secure\s*\(\s*true)"#, "cookie crate Cookie::new without secure flag"),
    (r#"Set-Cookie:\s*[^;]*;(?!\s*Secure)"#, "Set-Cookie header without Secure attribute"),
    (r#"Cookie::build\s*\([^)]*\)(?!\s*\.secure\s*\(\s*true)"#, "Cookie::build without secure flag"),
]);

pub struct RustCookieMissingSecure;

impl LangRule for RustCookieMissingSecure {
    fn id(&self) -> &str { "RUST-SEC-038" }
    fn name(&self) -> &str { "Cookie Missing Secure Flag" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let has_cookie = tree.imports.iter().any(|imp| {
            imp.module.contains("cookie")
        }) || code.contains("Cookie::");

        if !has_cookie {
            return findings;
        }

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;

            if line.contains("Cookie::new") || line.contains("Cookie::build") {
                let has_secure = Regex::new(r"\.secure\s*\(\s*true\s*\)").unwrap().is_match(line);

                if !has_secure {
                    let (start, end) = get_line_offsets(code, line_num);
                    let sensitive_cookie = Regex::new(r"(?i)(?:session|auth|token|jwt|account|user)").unwrap().is_match(line);

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: if sensitive_cookie { "high" } else { "medium" }.to_string(),
                        line: line_num,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.trim().to_string(),
                        problem: format!("Cookie without Secure flag{}. CWE-614: Cookies without Secure flag can be transmitted over HTTP, allowing attackers to intercept sensitive session data.", if sensitive_cookie { " (sensitive cookie)" } else { "" }),
                        fix_hint: "Always add .secure(true) when creating cookies: Cookie::build(name, value).secure(true). Example: Cookie::build(\"session\", token).secure(true).path(\"/\").".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-039: CORS Wildcard with Credentials (CWE-346)
// Severity: high
// Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true
// ─────────────────────────────────────────────────────────────────────────────
static CORS_WILDCARD_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#""Access-Control-Allow-Origin"\s*:\s*"\*""#, "CORS wildcard origin *"),
    (r#"header!\s*\([^)]*"Access-Control-Allow-Origin"\s*,\s*"\*""#, "CORS header with wildcard origin"),
    (r#"\.with_credentials\s*\(\s*(?:true|1)\s*\).*(?:\*|wildcard|any)"#, "Credentials enabled with potential wildcard"),
    (r#"(?s)Access-Control-Allow-Credentials.*?Access-Control-Allow-Origin.*?\*"#, "Credentials true followed by wildcard origin"),
]);

pub struct RustCorsWildcard;

impl LangRule for RustCorsWildcard {
    fn id(&self) -> &str { "RUST-SEC-039" }
    fn name(&self) -> &str { "CORS Wildcard Origin with Credentials" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let has_cors = code.contains("Access-Control") || code.contains("CORS") || code.contains("cors");

        if !has_cors {
            return findings;
        }

        let has_wildcard = code.contains("\"*\"") || code.contains("'*'");
        let has_credentials = code.contains("Access-Control-Allow-Credentials")
            && (code.contains("true") || code.contains("1"));

        if has_wildcard && has_credentials {
            for (line_idx, line) in code.lines().enumerate() {
                let line_num = line_idx + 1;

                if line.contains("Access-Control-Allow-Origin") && line.contains("*") {
                    let (start, end) = get_line_offsets(code, line_num);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: line_num,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.trim().to_string(),
                        problem: "CORS wildcard origin with credentials. CWE-346: Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true allows any website to steal user data.".to_string(),
                        fix_hint: "Never use '*' with credentials. Specify explicit origins: Access-Control-Allow-Origin: https://your-domain.com. Use a whitelist of allowed origins.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                    break;
                }
            }
        }

        for (pat, desc) in &*CORS_WILDCARD_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
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
                        problem: format!("CORS configuration issue: {}. CWE-346: Insecure CORS setup can allow unauthorized cross-origin access.", desc),
                        fix_hint: "Use explicit origin whitelist instead of wildcard. Validate origins against a list of allowed domains. Never allow credentials with wildcard origins.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-040: Path Traversal Extended (CWE-22)
// Severity: high
// Additional path traversal patterns for Rust file operations
// ─────────────────────────────────────────────────────────────────────────────
static PATH_TRAVERSAL_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"std::fs::read\s*\(\s*(?:request|input|param|user|path|filename)"#, "std::fs::read with user-controlled path"),
    (r#"std::fs::read_to_string\s*\(\s*(?:request|input|param|user|path|filename)"#, "std::fs::read_to_string with user-controlled path"),
    (r#"std::fs::write\s*\(\s*(?:request|input|param|user|path|filename)"#, "std::fs::write with user-controlled path"),
    (r#"std::fs::File::open\s*\(\s*(?:request|input|param|user|path|filename)"#, "File::open with user-controlled path"),
    (r#"std::fs::create_dir_all\s*\(\s*(?:request|input|param|user|path)"#, "create_dir_all with user-controlled path"),
    (r#"std::path::Path::new\s*\([^)]*(?:request|input|param|user)"#, "Path construction with user input"),
    (r#"PathBuf::from\s*\([^)]*(?:request|input|param|user)"#, "PathBuf::from with user input"),
    (r#"\.join\s*\([^)]*(?:request|input|param|user|path)"#, "Path join with user-controlled component"),
]);

pub struct RustPathTraversalExtended;

impl LangRule for RustPathTraversalExtended {
    fn id(&self) -> &str { "RUST-SEC-040" }
    fn name(&self) -> &str { "Path Traversal Vulnerability" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let fs_imports = ["std::fs", "std::path", "fs::", "File::"];
        let has_fs = tree.imports.iter().any(|imp| {
            fs_imports.iter().any(|fs| imp.module.contains(fs))
        });

        if !has_fs && !code.contains("fs::") && !code.contains("std::fs") {
            return findings;
        }

        let sanitization_funcs = ["canonicalize", "components().collect", "strip_prefix", "normalize", "absolute"];
        let has_sanitization = tree.calls.iter().any(|call| {
            sanitization_funcs.iter().any(|sf| call.callee.contains(sf))
        });

        for (pat, desc) in &*PATH_TRAVERSAL_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Path traversal: {}. CWE-22: User-controlled path components can include '../' to access files outside the intended directory.", desc),
                    fix_hint: "Use canonicalize() and validate the resolved path stays within allowed directory: let path = path.canonicalize()?; if !path.starts_with(ALLOWED_DIR) { return Err(...); }".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        if !has_sanitization && !findings.is_empty() {
            for finding in &mut findings {
                finding.problem = format!("{} No path sanitization detected.", finding.problem);
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-SEC-041: Integer Wraparound Unsigned (CWE-190)
// Severity: high
// u32::MAX, usize::MAX arithmetic without checked/wrapping operations
// ─────────────────────────────────────────────────────────────────────────────
static UNSIGNED_WRAPAROUND_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"(?:u(?:size|8|16|32|64))::MAX\s*[+\-]"#, "unsigned MAX constant used in arithmetic — silent wraparound"),
    (r#"(?:u(?:size|8|16|32|64))::MAX\s*"#, "unsigned MAX constant without checked operation"),
    (r#"(?:usize|u32)::MAX\s+(?:as\s+)?i\d+"#, "Casting usize::MAX to signed — can cause unexpected overflow"),
    (r#"(?:u(?:size|8|16|32|64))::MAX\s*/\s*(?:n|divisor|count)"#, "Division using MAX constant — potential logic error"),
    (r#"(?:u(?:size|8|16|32|64))::MAX\s*%\s*(?:n|mod|divisor)"#, "Modulo with MAX constant — potential logic error"),
]);

pub struct RustUnsignedWraparound;

impl LangRule for RustUnsignedWraparound {
    fn id(&self) -> &str { "RUST-SEC-041" }
    fn name(&self) -> &str { "Unsigned Integer Wraparound Risk" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (pat, desc) in &*UNSIGNED_WRAPAROUND_PATTERNS {
            let re = Regex::new(pat).unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let line_text = code.lines().nth(line.saturating_sub(1)).unwrap_or("");

                if line_text.trim().starts_with("//") || line_text.trim().starts_with("/*") {
                    continue;
                }

                let (start, end) = get_line_offsets(code, line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Unsigned integer wraparound: {}. CWE-190: Unsigned integers silently wrap on overflow in release mode.", desc),
                    fix_hint: "Use checked arithmetic (checked_add, checked_sub) or ensure operations stay within bounds. Be explicit about wraparound intent with wrapping_* methods.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

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
        Box::new(RustOverflowChecksDisabled),
        Box::new(RustInsecureRandom),
        Box::new(RustUnboundedCollection),
        Box::new(RustWeakCrypto),
        Box::new(RustUnsafeDeref),
        Box::new(RustRegexDos),
        Box::new(RustUnsafeDocs),
        Box::new(RustDataRace),
        Box::new(RustIntegerWraparound),
        Box::new(RustInsecureTls),
        Box::new(RustPanicPublicApi),
        Box::new(RustDbgFormatString),
        Box::new(RustIntegerOverflowArith),
        Box::new(RustUseAfterFreePattern),
        Box::new(RustInsecureRandomGen),
        Box::new(RustUnsafeTooBroad),
        Box::new(RustHardcodedSecrets),
        Box::new(RustWrongTypeCast),
        // RUST-CRYPT-001: Insecure Cryptography
        Box::new(RustInsecureCrypto),
        // RUST-SEC-023 to SEC-025: XSS, SSRF, Insecure Deserialization
        Box::new(RustXssRule),
        Box::new(RustSsrfRule),
        Box::new(RustInsecureDeserRule),
        // RUST-SEC-027 to SEC-041: New security rules
        Box::new(RustTimingSideChannelAes),           // CWE-208: Timing Side-Channel AES
        Box::new(RustTlsVerifyDisabled),              // CWE-295: TLS Verify Disabled
        Box::new(RustRegexCatastrophicBacktracking), // CWE-1333: Regex Catastrophic Backtracking
        Box::new(RustUnboundedVecAllocation),         // CWE-400: Unbounded Vec Allocation
        Box::new(RustHashDosVulnerability),           // CWE-682: HashDoS
        Box::new(RustFormatStringInjection),          // CWE-134: Format String Injection
        Box::new(RustYamlUnsafeDeserialization),     // CWE-502: YAML Deserialize Unsafe
        Box::new(RustEnvVariableInjection),          // CWE-78: Env Variable Injection
        Box::new(RustCleartextTransmission),         // CWE-319: Cleartext Transmission
        Box::new(RustJwtWeakSecret),                  // CWE-347: JWT HS256 Weak Secret
        Box::new(RustPredictableRandom),             // CWE-338: Predictable Random
        Box::new(RustCookieMissingSecure),           // CWE-614: Cookie Missing Secure
        Box::new(RustCorsWildcard),                   // CWE-346: CORS Wildcard
        Box::new(RustPathTraversalExtended),         // CWE-22: Path Traversal Extended
        Box::new(RustUnsignedWraparound),             // CWE-190: Integer Wraparound Unsigned
    ]
}
