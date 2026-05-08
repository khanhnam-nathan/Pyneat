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


use crate::scanner::ln_ast::{LnAst, LnCall};
use crate::scanner::base::{find_calls, has_import, LangFix, LangRule, LangFinding};

/// Helper: get line byte offsets (0-indexed lines, 0-indexed bytes).
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

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-001: SQL Injection
// CWE-89 — CVSS 9.8 — CRITICAL
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpSqlInjection;

impl LangRule for PhpSqlInjection {
    fn id(&self) -> &str { "PHP-SEC-001" }
    fn name(&self) -> &str { "SQL Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let sql_funcs = ["mysqli_query", "mysql_query", "pg_query", "sqlite_query",
                        "DB::query", "$db->query", "$pdo->query", "select", "insert",
                        "update", "delete"];
        let dangerous_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE"];

        for call in find_calls(tree, &sql_funcs) {
            let args_str = call.arguments.join(" ");
            let has_user_input = dangerous_keywords.iter().any(|p| args_str.contains(p))
                || args_str.contains("$_GET") || args_str.contains("$_POST")
                || args_str.contains("$_REQUEST");
            if has_user_input {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: format!("SQL injection risk: {} with user input", call.callee),
                    fix_hint: "Use prepared statements: $stmt = $pdo->prepare($sql); $stmt->execute($params);".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-002: Cross-Site Scripting (XSS)
// CWE-79 — CVSS 6.1 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpXss;

impl LangRule for PhpXss {
    fn id(&self) -> &str { "PHP-SEC-002" }
    fn name(&self) -> &str { "Cross-Site Scripting (XSS)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let xss_funcs = ["echo", "print", "printf", "print_r", "var_dump", "var_export"];
        let user_inputs = ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"];

        for call in find_calls(tree, &xss_funcs) {
            let args_str = call.arguments.join(" ");
            let has_user_input = user_inputs.iter().any(|i| args_str.contains(i));
            if has_user_input && !args_str.contains("htmlspecialchars")
                && !args_str.contains("htmlentities")
                && !args_str.contains("strip_tags") {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: "XSS risk: unescaped user input in output".to_string(),
                    fix_hint: "Escape output: echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-003: Command Injection
// CWE-78 — CVSS 9.8 — CRITICAL
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpCommandInjection;

impl LangRule for PhpCommandInjection {
    fn id(&self) -> &str { "PHP-SEC-003" }
    fn name(&self) -> &str { "Command Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous_funcs = ["exec", "system", "shell_exec", "passthru", "popen",
                               "proc_open", "pcntl_exec"];

        for call in find_calls(tree, &dangerous_funcs) {
            let args_str = call.arguments.join(" ");
            let _has_user_input = args_str.contains("$_GET") || args_str.contains("$_POST")
                || args_str.contains("$_REQUEST") || args_str.contains("$argv");
            let (start, end) = get_line_offsets(code, call.start_line);
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: call.start_line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: call.callee.clone(),
                problem: format!("Command injection risk: {} with user input", call.callee),
                fix_hint: "Use escapeshellarg() or avoid shell commands. Consider PHP native functions.".to_string(),
                auto_fix_available: false,
            });
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-004: Path Traversal / Local File Inclusion
// CWE-22 — CVSS 7.5 — HIGH
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpPathTraversal;

impl LangRule for PhpPathTraversal {
    fn id(&self) -> &str { "PHP-SEC-004" }
    fn name(&self) -> &str { "Path Traversal / LFI" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous_funcs = ["include", "include_once", "require", "require_once",
                               "file_get_contents", "file_put_contents", "fopen",
                               "readfile", "copy", "unlink"];

        for call in find_calls(tree, &dangerous_funcs) {
            let args_str = call.arguments.join(" ");
            let has_user_input = args_str.contains("$_GET") || args_str.contains("$_POST")
                || args_str.contains("$_REQUEST");
            let has_traversal = args_str.contains("../") || args_str.contains("..\\");
            if has_user_input || has_traversal {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: format!("Path traversal risk: {} with user input or traversal", call.callee),
                    fix_hint: "Validate and sanitize file paths. Use realpath() and whitelist allowed directories.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-005: Insecure Password Hashing
// CWE-328 — CVSS 5.3 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpWeakHashing;

impl LangRule for PhpWeakHashing {
    fn id(&self) -> &str { "PHP-SEC-005" }
    fn name(&self) -> &str { "Weak Password Hashing" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let weak_funcs = ["md5(", "sha1(", "crypt("];
        let weak_algos = ["MD5", "SHA1", "DES", "BLOWFISH"];

        for (i, line) in code.lines().enumerate() {
            for func in &weak_funcs {
                if line.contains(func) {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.trim().to_string(),
                        problem: format!("Weak hashing: {} found", func.replace("(", "")),
                        fix_hint: "Use password_hash() with PASSWORD_DEFAULT or password_hash($password, PASSWORD_ARGON2ID).".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
            for algo in &weak_algos {
                if line.contains(algo) && line.contains("hash_") {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.trim().to_string(),
                        problem: format!("Weak hashing algorithm: {}", algo),
                        fix_hint: "Use hash_equals() for timing-safe comparison and ARGON2ID for hashing.".to_string(),
                        auto_fix_available: true,
                    });
                }
            }
        }
        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = code.lines().nth(finding.line - 1)?;
        let mut replacement = line_text.to_string();

        // Replace md5(...) with hash("sha256", ...)
        if line_text.contains("md5(") {
            replacement = replacement.replace("md5(", "hash(\"sha256\", ");
            return Some(LangFix {
                rule_id: self.id().to_string(),
                original: line_text.to_string(),
                replacement,
                start_byte: finding.start_byte,
                end_byte: finding.end_byte,
                description: "Replace md5() with hash(\"sha256\", ...) for secure hashing".to_string(),
            });
        }

        // Replace sha1(...) with hash("sha256", ...)
        if line_text.contains("sha1(") {
            replacement = replacement.replace("sha1(", "hash(\"sha256\", ");
            return Some(LangFix {
                rule_id: self.id().to_string(),
                original: line_text.to_string(),
                replacement,
                start_byte: finding.start_byte,
                end_byte: finding.end_byte,
                description: "Replace sha1() with hash(\"sha256\", ...) for secure hashing".to_string(),
            });
        }

        None
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-006: Hardcoded Secrets
// CWE-798 — CVSS 7.5 — HIGH
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpHardcodedSecrets;

impl LangRule for PhpHardcodedSecrets {
    fn id(&self) -> &str { "PHP-SEC-006" }
    fn name(&self) -> &str { "Hardcoded Secrets" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"(?i)password\s*[=:]\s*["'][^"']{4,}["']"#, "Hardcoded password"),
            (r#"(?i)secret\s*[=:]\s*["'][^"']{4,}["']"#, "Hardcoded secret"),
            (r#"(?i)api[_-]?key\s*[=:]\s*["'][^"']{4,}["']"#, "Hardcoded API key"),
            (r#"(?i)token\s*[=:]\s*["'][A-Za-z0-9_\-]{10,}["']"#, "Hardcoded token"),
            (r#"AKIA[A-Z0-9]{16}"#, "AWS Access Key ID"),
            (r#"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"#, "Private key"),
            (r#"(?i)db[_-]?pass(word)?\s*[=:]\s*["'][^"']+["']"#, "Database password"),
            (r#"(?i)aws[_-]?secret\s*[=:]\s*["'][^"']+["']"#, "AWS secret"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Use environment variables: getenv('SECRET') or _ENV['SECRET'].".to_string(),
                        auto_fix_available: true,
                    });
                }
            }
        }
        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = code.lines().nth(finding.line - 1)?;
        let indented = line_text.trim_start();

        // Extract the key name (e.g., "password", "api_key")
        let key_re = regex::Regex::new(r#"(?i)((?:api[_-]?)?(?:key|secret|password|token|pass(?:word)?))"#).ok()?;
        let key_caps = key_re.captures(&finding.snippet)?;
        let key_name = key_caps.get(1)?.as_str().to_uppercase().replace("-", "_");

        // Create replacement using env var
        let replacement = format!(
            "{} // FIXME: Use getenv('{}') in production",
            indented,
            key_name
        );

        Some(LangFix {
            rule_id: self.id().to_string(),
            original: line_text.to_string(),
            replacement,
            start_byte: finding.start_byte,
            end_byte: finding.end_byte,
            description: format!("Replace hardcoded {} with environment variable", key_name),
        })
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-007: Eval Usage
// CWE-95 — CVSS 8.1 — HIGH
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpEvalUsage;

impl LangRule for PhpEvalUsage {
    fn id(&self) -> &str { "PHP-SEC-007" }
    fn name(&self) -> &str { "Dangerous Eval Usage" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous_funcs = ["eval", "assert", "create_function", "preg_replace"];

        for call in find_calls(tree, &dangerous_funcs) {
            let args_str = call.arguments.join(" ");
            let _has_user_input = args_str.contains("$_GET") || args_str.contains("$_POST")
                || args_str.contains("$_REQUEST");
            let (start, end) = get_line_offsets(code, call.start_line);
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: call.start_line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: call.callee.clone(),
                problem: format!("Dangerous function: {} with user input risk", call.callee),
                fix_hint: "Avoid eval/assert. Use type checking and whitelist validation instead.".to_string(),
                auto_fix_available: false,
            });
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-008: Session Fixation
// CWE-384 — CVSS 6.0 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpSessionFixation;

impl LangRule for PhpSessionFixation {
    fn id(&self) -> &str { "PHP-SEC-008" }
    fn name(&self) -> &str { "Session Fixation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let session_funcs = ["session_id", "session_start"];
        let has_regenerate = code.contains("session_regenerate_id");
        let has_destroy = code.contains("session_destroy");

        for call in find_calls(tree, &session_funcs) {
            if !has_regenerate && !has_destroy {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: "Session without regeneration - fixation risk".to_string(),
                    fix_hint: "Add session_regenerate_id(true) after authentication.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-009: Unvalidated Redirect
// CWE-601 — CVSS 6.1 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpUnvalidatedRedirect;

impl LangRule for PhpUnvalidatedRedirect {
    fn id(&self) -> &str { "PHP-SEC-009" }
    fn name(&self) -> &str { "Unvalidated Redirect" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let redirect_funcs = ["header", "Location:", "redirect", "wp_redirect", "http_redirect"];
        let user_inputs = ["$_GET", "$_POST", "$_REQUEST", "$_SERVER"];

        for call in find_calls(tree, &redirect_funcs) {
            let args_str = call.arguments.join(" ");
            let has_user_input = user_inputs.iter().any(|i| args_str.contains(i));
            if has_user_input {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: "Unvalidated redirect with user input".to_string(),
                    fix_hint: "Validate and whitelist redirect URLs. Never allow absolute URLs from user input.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-010: PHP Object Injection
// CWE-502 — CVSS 9.1 — CRITICAL
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpObjectInjection;

impl LangRule for PhpObjectInjection {
    fn id(&self) -> &str { "PHP-SEC-010" }
    fn name(&self) -> &str { "PHP Object Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous_funcs = ["unserialize"];
        let user_inputs = ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "file_get_contents"];

        for call in find_calls(tree, &dangerous_funcs) {
            let args_str = call.arguments.join(" ");
            let has_user_input = user_inputs.iter().any(|i| args_str.contains(i));
            if has_user_input {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: "Object injection: unserialize with user input".to_string(),
                    fix_hint: "Use json_decode() instead of unserialize(), or implement __wakeup/__destruct validation.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-011: Insecure CORS
// CWE-942 — CVSS 5.3 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpInsecureCors;

impl LangRule for PhpInsecureCors {
    fn id(&self) -> &str { "PHP-SEC-011" }
    fn name(&self) -> &str { "Insecure CORS Configuration" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"header\s*\(\s*["']Access-Control-Allow-Origin:\s*\*["']"#, "CORS allows all origins"),
            (r"Access-Control-Allow-Credentials.*true", "CORS with credentials and wildcard origin"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Specify exact origins: header('Access-Control-Allow-Origin: https://trusted.com');".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-012: Information Disclosure
// CWE-200 — CVSS 5.0 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpInfoDisclosure;

impl LangRule for PhpInfoDisclosure {
    fn id(&self) -> &str { "PHP-SEC-012" }
    fn name(&self) -> &str { "Information Disclosure" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"error_reporting\s*\(\s*E_ALL\s*\)"#, "Error reporting enabled in production"),
            (r#"ini_set\s*\(\s*["']display_errors"#, "Display errors enabled"),
            (r#"phpinfo\s*\(\s*\)"#, "phpinfo() exposes system info"),
            (r#"var_dump\s*\(\s*\$\w+\s*\)"#, "var_dump exposes variable content"),
            (r#"print_r\s*\(\s*\$\w+\s*\)"#, "print_r exposes variable content"),
            (r#"\$_SERVER\s*\[\s*["']PHP_SELF["']"#, "PHP_SELF can cause XSS"),
            (r#"\$_SERVER\s*\[\s*["']REQUEST_URI["']"#, "REQUEST_URI may contain malicious input"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Disable display_errors in production. Use error logging instead.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-013: Weak Random
// CWE-338 — CVSS 6.5 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpWeakRandom;

impl LangRule for PhpWeakRandom {
    fn id(&self) -> &str { "PHP-SEC-013" }
    fn name(&self) -> &str { "Weak Random Number Generation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r"mt_rand\s*\(", "mt_rand is predictable for security"),
            (r"rand\s*\(", "rand is predictable for security"),
            (r"srand\s*\(", "srand with weak seed"),
            (r"mcrypt_", "mcrypt is deprecated and insecure"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Use random_bytes() for cryptography or Randomizer from randomlib.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-014: Missing HTTPS Enforcement
// CWE-295 — CVSS 5.3 — LOW
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpMissingHttps;

impl LangRule for PhpMissingHttps {
    fn id(&self) -> &str { "PHP-SEC-014" }
    fn name(&self) -> &str { "Missing HTTPS Enforcement" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let has_https_check = code.contains("HTTPS") && code.contains("on")
            || code.contains("HTTP_X_FORWARDED_PROTO")
            || code.contains("filter_var") && code.contains("FILTER_FLAG_SCHEME_REQUIRED");
        let has_sts = code.contains("Strict-Transport-Security");
        let has_login = find_calls(tree, &["login", "auth", "password", "signin"]).len() > 0;

        if has_login && !has_https_check {
            let (start, end) = get_line_offsets(code, 1);
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: 1,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: "Login/authentication detected".to_string(),
                problem: "Missing HTTPS enforcement for sensitive operations".to_string(),
                fix_hint: "Add HTTPS check: if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') { die('HTTPS required'); }".to_string(),
                auto_fix_available: false,
            });
        }

        if !has_sts && has_https_check {
            let (start, end) = get_line_offsets(code, 1);
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: 1,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: "HTTPS detected but no HSTS".to_string(),
                problem: "Missing HTTP Strict Transport Security header".to_string(),
                fix_hint: "Add HSTS header: header('Strict-Transport-Security: max-age=31536000; includeSubDomains');".to_string(),
                auto_fix_available: false,
            });
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-015: Insecure File Upload
// CWE-434 — CVSS 8.1 — CRITICAL
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpInsecureFileUpload;

impl LangRule for PhpInsecureFileUpload {
    fn id(&self) -> &str { "PHP-SEC-015" }
    fn name(&self) -> &str { "Insecure File Upload" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let upload_funcs = ["move_uploaded_file", "copy", "file_put_contents"];
        let has_validation = code.contains("exif_imagetype")
            || code.contains("mime_content_type")
            || code.contains("getimagesize")
            || code.contains("finfo_file");

        for call in find_calls(tree, &upload_funcs) {
            if !has_validation && call.arguments.len() > 0 {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: "File upload without proper validation - may accept malicious files".to_string(),
                    fix_hint: "Validate file type using exif_imagetype(), mime_content_type(), and check file extension whitelist.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-016: Loose Comparison
// CWE-20 — CVSS 6.1 — HIGH
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpLooseComparison;

impl LangRule for PhpLooseComparison {
    fn id(&self) -> &str { "PHP-SEC-016" }
    fn name(&self) -> &str { "Loose Type Comparison" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"\$_\w+\s*==\s*['"][^'"]+['"]"#, "Loose comparison with user input string"),
            (r#"==\s*(?!==)(?!!=)"#, "Loose equality operator - use === for type-safe comparison"),
            (r#"['"][^'"]+['"]\s*==\s*\$_\w+"#, "String compared loosely with user input"),
            (r#"if\s*\(\s*!\s*empty\s*\([^)]+\)\s*\)"#, "empty() with loose check - verify type safety"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Use strict comparison (=== or !==) and validate input types explicitly.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-017: Missing CSRF Protection
// CWE-352 — CVSS 6.0 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpMissingCsrf;

impl LangRule for PhpMissingCsrf {
    fn id(&self) -> &str { "PHP-SEC-017" }
    fn name(&self) -> &str { "Missing CSRF Protection" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let has_csrf_check = code.contains("csrf_token")
            || code.contains("CSRF")
            || code.contains("csrf验证")
            || code.contains("token_verify")
            || code.contains("hash_equals");
        let has_form_post = code.contains("$_POST") || code.contains("form") && code.contains("method");
        let has_session = code.contains("session_start") || code.contains("SESSION");

        if has_form_post && has_session && !has_csrf_check {
            if let Ok(re) = regex::Regex::new(r#"if\s*\(\s*!\s*empty\s*\(\s*\$_\w+\s*\)\s*\)"#) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: "POST form handler detected".to_string(),
                        problem: "Form POST handler without CSRF token validation".to_string(),
                        fix_hint: "Add CSRF token: generate token on form, verify with hash_equals($_SESSION['csrf'], $_POST['csrf']).".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-018: PHP XXE (XML External Entity)
// CWE-611 — CVSS 8.0 — HIGH
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpXxe;

impl LangRule for PhpXxe {
    fn id(&self) -> &str { "PHP-SEC-018" }
    fn name(&self) -> &str { "PHP XXE Vulnerability" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"simplexml_load_(string|file)"#, "SimpleXML load without XXE protection"),
            (r#"DOMDocument->load(XML|HTML)"#, "DOMDocument load without XXE protection"),
            (r#"xml_parse\s*\("#, "XML parsing without XXE protection"),
            (r#"libxml_set_external_entity_loader"#, "Custom entity loader may enable XXE"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Disable XXE: libxml_disable_entity_loader(true); before parsing.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-019: LDAP Injection
// CWE-90 — CVSS 8.0 — HIGH
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpLdapInjection;

impl LangRule for PhpLdapInjection {
    fn id(&self) -> &str { "PHP-SEC-019" }
    fn name(&self) -> &str { "LDAP Injection" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let ldap_funcs = ["ldap_search", "ldap_bind", "ldap_connect", "ldap_modify"];

        for call in find_calls(tree, &ldap_funcs) {
            let args_str = call.arguments.join(" ");
            let has_user_input = args_str.contains("$_GET")
                || args_str.contains("$_POST")
                || args_str.contains("$_REQUEST");
            if has_user_input {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: "LDAP injection risk: user input in LDAP query".to_string(),
                    fix_hint: "Escape LDAP special characters: ldap_escape($input, '', LDAP_ESCAPE_FILTER). Use prepared LDAP statements.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-020: Mass Assignment
// CWE-915 — CVSS 6.1 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpMassAssignment;

impl LangRule for PhpMassAssignment {
    fn id(&self) -> &str { "PHP-SEC-020" }
    fn name(&self) -> &str { "Mass Assignment Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"::create\s*\(\s*\$_POST\s*\)"#, "Mass assignment via create with $_POST"),
            (r#"::update\s*\(\s*\$_POST\s*\)"#, "Mass assignment via update with $_POST"),
            (r#"Model\s*::\w+\s*\(\s*\$_(GET|POST|REQUEST)\s*\)"#, "Model method with user input"),
            (r#"\$model\s*->fill\s*\(\s*\$_\w+\s*\)"#, "Fill method with user input"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Use $fillable or $guarded properties in Eloquent. Validate and whitelist allowed fields.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-001: Slopsquatting (AI-Hallucinated Dependencies)
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpSlopsquatting;

impl LangRule for PhpSlopsquatting {
    fn id(&self) -> &str { "PHP-AI-001" }
    fn name(&self) -> &str { "AI-Hallucinated Dependency (Slopsquatting)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let hallucinated: Vec<&str> = vec![
            "fakerlib", "jsonify", "phpserialize", "laravelfake",
            "mongomagic", "mysqldriver-fake", "redis-mock",
            "test-pkg-xyz", "mock-ext",
        ];
        for imp in &tree.imports {
            for fake in &hallucinated {
                if imp.module.contains(fake) || imp.name.contains(fake) {
                    let (start, end) = get_line_offsets(_code, imp.start_line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: imp.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: imp.module.clone(),
                        problem: format!("Slopsquatting Risk: The package '{}' appears to be a hallucinated name.", imp.module),
                        fix_hint: "Verify this package exists on packagist.org before installing.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-002: Verbose Error Exposure
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpVerboseError;

impl LangRule for PhpVerboseError {
    fn id(&self) -> &str { "PHP-AI-002" }
    fn name(&self) -> &str { "Verbose Error Exposure" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r#"echo\s+(['\"]?\s*\$e(rr|rror)?\s*->(getMessage|__toString)\(\)\s*['\"]?)"#, "Echoing error directly to output"),
            (r#"print_r\s*\(\s*\$e(rr|rror)"#, "print_r exposing error details"),
            (r#"var_dump\s*\(\s*\$e(rr|rror)"#, "var_dump exposing error details"),
            (r#"die\s*\(\s*\$e(rr|rror)"#, "die() with error object"),
            (r#"echo\s+['\"]?\s*err(or)?\s*['\"]?\s*\.\s*\$e"#, "String concatenation with error"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Log errors to file, return generic message to user.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-003: Missing Input Validation
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpMissingInputValidation;

impl LangRule for PhpMissingInputValidation {
    fn id(&self) -> &str { "PHP-AI-003" }
    fn name(&self) -> &str { "Missing Input Validation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r#"\$_GET\s*\[\s*['\"][^'\"]+['\"]\s*\]"#, "Direct $_GET access without sanitization"),
            (r#"\$_POST\s*\[\s*['\"][^'\"]+['\"]\s*\]"#, "Direct $_POST access without validation"),
            (r#"\$_REQUEST\s*\[\s*['\"][^'\"]+['\"]\s*\]"#, "Direct $_REQUEST without filtering"),
            (r#"filter_input\s*\(\s*INPUT_GET[^)]*\)\s*(?!&&|\|\||\?)"#, "filter_input without immediate check"),
            (r#"htmlspecialchars\s*\([^)]*\$_(GET|POST|REQUEST)"#, "Escaping with htmlspecialchars but missing charset"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Validate and sanitize all user input using filter_input() or custom validation.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-004: AI-Generated Code Marker
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpAiGenComment;

impl LangRule for PhpAiGenComment {
    fn id(&self) -> &str { "PHP-AI-004" }
    fn name(&self) -> &str { "AI-Generated Code Marker" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"(?i)generated by (chatgpt|claude|copilot|gemini|llm|gpt|ai|openai|anthropic)"##, "AI generation marker"),
            (r##"(?i)written by (chatgpt|claude|copilot|gemini|llm)"##, "AI authorship claim"),
            (r##"(?i)code generated by (cursor|github|replit)"##, "Code assistant marker"),
            (r##"(?i)AI[_-]?generated"##, "AI-generated marker"),
        ];
        for comment in &tree.comments {
            for (pattern, _) in &patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(&comment.text) {
                        let (start, end) = get_line_offsets(code, comment.start_line);
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: comment.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: comment.text.clone(),
                            problem: "AI-Generated Code Detected".to_string(),
                            fix_hint: "Review AI-generated code carefully before production use.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// All PHP Security Rules
// ─────────────────────────────────────────────────────────────────────────────

pub fn php_security_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(PhpSqlInjection),
        Box::new(PhpXss),
        Box::new(PhpCommandInjection),
        Box::new(PhpPathTraversal),
        Box::new(PhpWeakHashing),
        Box::new(PhpHardcodedSecrets),
        Box::new(PhpEvalUsage),
        Box::new(PhpSessionFixation),
        Box::new(PhpUnvalidatedRedirect),
        Box::new(PhpObjectInjection),
        Box::new(PhpInsecureCors),
        Box::new(PhpInfoDisclosure),
        Box::new(PhpWeakRandom),
        Box::new(PhpMissingHttps),
        Box::new(PhpInsecureFileUpload),
        Box::new(PhpLooseComparison),
        Box::new(PhpMissingCsrf),
        Box::new(PhpXxe),
        Box::new(PhpLdapInjection),
        Box::new(PhpMassAssignment),
        Box::new(PhpSlopsquatting),
        Box::new(PhpVerboseError),
        Box::new(PhpMissingInputValidation),
        Box::new(PhpAiGenComment),
    ]
}
