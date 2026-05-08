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

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LangRule, LangFinding, LangFix};

/// Helper to get line byte offsets
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

// ---------------------------------------------------------------------------
// Existing rules
// ---------------------------------------------------------------------------

pub struct CSharpConsoleWrite;

impl LangRule for CSharpConsoleWrite {
    fn id(&self) -> &str { "CSHARP-001" }
    fn name(&self) -> &str { "Console Write Statement" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for (i, line) in code.lines().enumerate() {
            if line.contains("Console.Write") {
                let (start, end) = get_line_offsets(code, i + 1);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: i + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.to_string(),
                    problem: "Console.Write found. Remove or replace with proper logging.".to_string(),
                    fix_hint: "Use ILogger or a logging framework for production.".to_string(),
                    auto_fix_available: true,
                        replacement: String::new(),
                });
            }
        }
        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = code.lines().nth(finding.line - 1)?;
        let indented = line_text.trim_start();
        let indent_len = line_text.len() - indented.len();
        let indent = &line_text[..indent_len];
        let commented = format!("{}// {} // FIXME: use ILogger", indent, indented);
        Some(LangFix {
            rule_id: self.id().to_string(),
            original: line_text.to_string(),
            replacement: commented,
            start_byte: finding.start_byte,
            end_byte: finding.end_byte,
            description: "Comment out Console.Write".to_string(),
        })
    }

    fn supports_auto_fix(&self) -> bool { true }
}

pub struct CSharpTodoComments;

impl LangRule for CSharpTodoComments {
    fn id(&self) -> &str { "CSHARP-002" }
    fn name(&self) -> &str { "TODO/FIXME Comments" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for todo in &tree.todos {
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: todo.start_line,
                column: 0,
                start_byte: 0,
                end_byte: 0,
                snippet: todo.text.clone(),
                problem: format!("Unresolved {} marker: {}", todo.marker, todo.description),
                fix_hint: "Address the TODO or provide a timeline for resolution.".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }
        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-003 — SQL Injection
// CWE-89 | OWASP A03:2021 | High severity
// Detects: string concatenation in SQL queries, raw SQL commands with + or string interpolation
// ---------------------------------------------------------------------------

pub struct CSharpSqlInjection;

impl LangRule for CSharpSqlInjection {
    fn id(&self) -> &str { "CSHARP-003" }
    fn name(&self) -> &str { "SQL Injection Vulnerability" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // SQL keywords + string ops that suggest raw SQL construction
        let sql_re = Regex::new(r#"(?i)(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|EXEC|EXECUTE)\s*\(?\s*["\+]"#).unwrap();

        // Dangerous patterns: "SELECT * FROM " + var
        // or $"SELECT * FROM Users WHERE Id = {id}"
        let patterns = [
            (r#"(?i)\bSELECT\b[^;]*\+[^;]*"#, "SQL query with string concatenation"),
            (r#"(?i)\bINSERT\b[^;]*\+[^;]*"#, "SQL query with string concatenation"),
            (r#"(?i)\bUPDATE\b[^;]*\+[^;]*"#, "SQL query with string concatenation"),
            (r#"(?i)\bDELETE\b[^;]*\+[^;]*"#, "SQL query with string concatenation"),
            (r#"(?i)\bEXEC(UTE)?\s*\([^)]*\+"#, "EXEC/EXECUTE with string concatenation"),
            (r#"\.Execute(Raw)?\s*\(\s*"[^"]*\+[^"]*""#, "Execute* with interpolated SQL string"),
            (r#"\.Execute(Raw)?\s*\(\s*\$"[^"]*\{[^}]+\}[^"]*""#, "Execute* with string interpolation"),
            (r#"\.FromSql(Raw)?\s*\([^)]*\+"#, "FromSqlRaw with string concatenation"),
        ];

        for (i, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            // Skip comments and strings that aren't real SQL
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                continue;
            }

            // Pattern-based detection
            for (pattern, desc) in &patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, i + 1);
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: i + 1,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line.to_string(),
                            problem: format!(
                                "Potential SQL injection: {} in SQL query. \
                                User input may be concatenated directly into SQL.",
                                desc
                            ),
                            fix_hint: "Use parameterized queries or an ORM (Entity Framework) instead of string concatenation.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                    }
                }
            }

            // Regex-based detection for SQL + string ops
            if sql_re.is_match(line) {
                let (start, end) = get_line_offsets(code, i + 1);
                // Avoid duplicates
                if !findings.iter().any(|f: &LangFinding| f.line == i + 1 && f.rule_id == self.id()) {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.to_string(),
                        problem: "Potential SQL injection: SQL keyword found with string operation. \
                                  User input may be concatenated directly into SQL.".to_string(),
                        fix_hint: "Use parameterized queries (SqlParameter) or Entity Framework for database access.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-004 — Insecure Deserialization
// CWE-502 | Critical severity
// Detects: BinaryFormatter, LosFormatter, SoapFormatter, NetDataContractSerializer usage
// ---------------------------------------------------------------------------

pub struct CSharpInsecureDeserialization;

impl LangRule for CSharpInsecureDeserialization {
    fn id(&self) -> &str { "CSHARP-004" }
    fn name(&self) -> &str { "Insecure Deserialization" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Dangerous serializers (function call names)
        let dangerous_calls: HashSet<&str> = [
            "BinaryFormatter.Deserialize",
            "LosFormatter.Deserialize",
            "SoapFormatter.Deserialize",
            "NetDataContractSerializer.ReadObject",
            "NetDataContractSerializer.Deserialize",
            "JavaScriptSerializer.Deserialize",
            "DataContractSerializer.ReadObject",
            "XmlSerializer.Deserialize",
            "ObjectBinder.Deserialize",
            "pickle.load",
            "FsPickler.Deserialize",
            "JsonSerializer.Deserialize",
            "DeserializeObject",
        ].into_iter().collect();

        for call in &tree.calls {
            let callee_lower = call.callee.to_lowercase();
            for dangerous in &dangerous_calls {
                if callee_lower.contains(&dangerous.to_lowercase()) {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let snippet = code.lines().nth(call.start_line - 1).unwrap_or("").to_string();

                    let problem = if callee_lower.contains("binaryformatter") {
                        "BinaryFormatter is deprecated and unsafe for deserializing untrusted data. \
                        It can lead to remote code execution (RCE). CVE-2025-21171, CVE-2025-53690."
                    } else if callee_lower.contains("xmlserializer") || callee_lower.contains("datacontract") {
                        "Deserializing untrusted XML/data can lead to XXE or RCE attacks."
                    } else {
                        "Deserializing untrusted data is dangerous and can lead to RCE attacks."
                    };

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet,
                        problem: problem.to_string(),
                        fix_hint: "Use System.Text.Json or Newtonsoft.Json with TypeNameHandling.None. \
                                   Never deserialize untrusted input. If BinaryFormatter is required, \
                                   implement a custom SerializationBinder.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                    break;
                }
            }
        }

        // Also detect via regex for patterns in declarations/fields
        let deserialize_re = Regex::new(
            r"(?i)(BinaryFormatter|LosFormatter|SoapFormatter|NetDataContractSerializer|DataContractSerializer)\s*"
        ).unwrap();

        for (i, line) in code.lines().enumerate() {
            if deserialize_re.is_match(line) {
                let (start, end) = get_line_offsets(code, i + 1);
                if !findings.iter().any(|f: &LangFinding| f.line == i + 1 && f.rule_id == self.id()) {
                    let snippet = line.to_string();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet,
                        problem: "Insecure deserialization type detected. \
                                  These serializers can be exploited when processing untrusted data.".to_string(),
                        fix_hint: "Replace with safe serializers like System.Text.Json. \
                                   Set TypeNameHandling = None in Newtonsoft.Json.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-005 — Hardcoded Secrets / Credentials
// CWE-798 | OWASP A02:2021 | Critical severity
// Detects: hardcoded API keys, passwords, connection strings, tokens
// ---------------------------------------------------------------------------

pub struct CSharpHardcodedSecrets;

impl LangRule for CSharpHardcodedSecrets {
    fn id(&self) -> &str { "CSHARP-005" }
    fn name(&self) -> &str { "Hardcoded Secret / Credential" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Patterns for hardcoded secrets
        let patterns = [
            // Hardcoded strings that look like secrets
            (r#"(?i)(password|pwd|passwd|secret|apikey|api_key|api-key)\s*[=:]\s*["'][^"']{4,}["']"#,
             "Hardcoded secret value (password/API key/secret) found in source code"),
            (r#"(?i)(bearer|token|auth|jwt|accesstoken|access_token)\s*[=:]\s*["'][^"']{8,}["']"#,
             "Hardcoded authentication token found in source code"),
            (r#"(?i)(connectionstring|connection_string)\s*[=:]\s*["'][^"']+;[^"']*(password|pwd)\s*="#,
             "Connection string with embedded password"),
            (r#"(?i)(aws_access_key|aws_secret|access_key_id|secret_access_key)\s*[=:]\s*["']"#,
             "Hardcoded AWS credentials"),
            // String literals longer than 30 chars that look like base64 keys
            (r#"=\s*["'][A-Za-z0-9+/=]{32,}["']"#, "Potential hardcoded key or token"),
            // Connection strings with passwords
            (r#"Password\s*=\s*[^;]{4,}"#, "Potential hardcoded database password"),
            (r#"pwd\s*=\s*[^;]{4,}"#, "Potential hardcoded password"),
            // Private keys
            (r#"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"#, "Hardcoded private key"),
            (r#"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----"#, "Hardcoded SSH private key"),
            // Generic credential patterns
            (r#"(?i)(username|userid|user_id)\s*[=:]\s*["'][^"']{2,}["']"#, "Hardcoded username or user ID"),
        ];

        for (i, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            // Skip comments (but not string literals inside code)
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            for (pattern, desc) in &patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, i + 1);
                        // Mask the secret value for the snippet
                        let snippet = re.replace_all(line, |caps: &regex::Captures| {
                            let m = caps.get(0).unwrap().as_str();
                            let sep_idx = m.find('=').unwrap_or(m.len());
                            let (before, _after) = m.split_at(sep_idx + 1);
                            format!("{}********", before)
                        }).to_string();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: i + 1,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet,
                            problem: desc.to_string(),
                            fix_hint: "Store secrets in environment variables, Azure Key Vault, \
                                       AWS Secrets Manager, or .NET User Secrets. \
                                       Never hardcode sensitive values in source code.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                        break;
                    }
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-006 — Command Injection
// CWE-78 | OWASP A03:2021 | Critical severity
// Detects: Process.Start with string concatenation, shell command execution
// ---------------------------------------------------------------------------

pub struct CSharpCommandInjection;

impl LangRule for CSharpCommandInjection {
    fn id(&self) -> &str { "CSHARP-006" }
    fn name(&self) -> &str { "Command Injection Vulnerability" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_calls: HashSet<&str> = [
            "Process.Start",
            "System.Diagnostics.Process.Start",
            "Runtime.exec",
            "Shell.Execute",
            "bash",
            "cmd.exe",
            "powershell.exe",
        ].into_iter().collect();

        for call in &tree.calls {
            if dangerous_calls.contains(call.callee.as_str()) {
                let (start, end) = get_line_offsets(code, call.start_line);
                let snippet = code.lines().nth(call.start_line - 1).unwrap_or("").to_string();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: snippet.clone(),
                    problem: "Potential command injection: external command execution with untrusted input. \
                              Attackers can execute arbitrary system commands if user input reaches this call.".to_string(),
                    fix_hint: "Avoid shell commands entirely. Use parameterised APIs. \
                               If unavoidable, validate input against a strict whitelist of allowed values.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        // Also detect via regex for patterns like: new ProcessStartInfo("cmd", "/c " + userInput)
        let cmd_patterns = [
            (r#"(?i)new\s+ProcessStartInfo\s*\([^)]*\+"#, "ProcessStartInfo constructed with string concatenation"),
            (r#"(?i)ProcessStartInfo\s*\.\s*(Arguments|FileName)\s*=[^;]*\+"#, "Process argument built with string concatenation"),
            (r#"(?i)(bash|sh|cmd|powershell)\s+["'].*\+.*["']"#, "Shell command with string concatenation"),
            (r#"(?i)\.Execute\s*\([^)]*\+"#, "Shell.Execute or similar with string concatenation"),
        ];

        for (i, line) in code.lines().enumerate() {
            if line.trim().starts_with("//") || line.trim().starts_with("/*") {
                continue;
            }

            for (pattern, desc) in &cmd_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, i + 1);
                        if !findings.iter().any(|f: &LangFinding| f.line == i + 1 && f.rule_id == self.id()) {
                            findings.push(LangFinding {
                                rule_id: self.id().to_string(),
                                severity: self.severity().to_string(),
                                line: i + 1,
                                column: 0,
                                start_byte: start,
                                end_byte: end,
                                snippet: line.to_string(),
                                problem: format!(
                                    "Potential command injection: {}. \
                                    Untrusted input may be passed to a shell command.",
                                    desc
                                ),
                                fix_hint: "Use ProcessStartInfo with explicit arguments (not shell). \
                                           Validate all input against a whitelist. \
                                           Consider using a safe API instead of shell commands.".to_string(),
                                auto_fix_available: false,
                        replacement: String::new(),
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-007 — Weak Cryptography
// CWE-327 | OWASP A02:2021 | High severity
// Detects: MD5, SHA1, DES, RC2 usage; weak crypto random; hardcoded IVs
// ---------------------------------------------------------------------------

pub struct CSharpWeakCryptography;

impl LangRule for CSharpWeakCryptography {
    fn id(&self) -> &str { "CSHARP-007" }
    fn name(&self) -> &str { "Weak Cryptographic Algorithm" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // Weak hash algorithms
            (r"(?i)\bMD5(Create)?\b", "MD5 hash algorithm — broken and unsuitable for security"),
            (r"(?i)\bSHA1(Create)?\b", "SHA1 hash algorithm — deprecated and unsuitable for security"),
            (r"(?i)\bRIPEMD160\b", "RIPEMD160 — weak hash algorithm"),
            // Weak encryption
            (r"(?i)\bDESCryptoServiceProvider\b", "DES encryption — broken (56-bit key)"),
            (r"(?i)\bRC2CryptoServiceProvider\b", "RC2 encryption — weak and broken"),
            (r"(?i)\bTripleDESCryptoServiceProvider\b", "3DES — slow and deprecated (112-bit effective)"),
            (r"(?i)\bAes\.Create\(\)\s*\.\s*Mode\s*=\s*CipherMode\.ECB", "ECB mode encryption — deterministic and weak"),
            // Weak random
            (r"(?i)\bnew\s+Random\s*\(\s*\)", "Random class — not cryptographically secure"),
            // Hardcoded IV/salt
            (r"(?i)(IV|InitializationVector|IVector)\s*[=:]\s*new\s+byte\[\s*\]", "Hardcoded initialization vector — undermines encryption"),
            (r"(?i)(salt|Salt)\s*[=:]\s*[^;]{1,30}\b", "Potential hardcoded salt value"),
            // Insecure password derivation
            (r"(?i)\bRfc2898DeriveBytes\b[^;]*(?<!iterations:\s*[0-9]{4,})", "Rfc2898DeriveBytes without sufficient iterations (min 100,000)"),
            // Plaintext storage
            (r"(?i)(password|secret)\s*[=:]\s*[^;]*(text|string)\b(?!.*encrypt)", "Potential plaintext password or secret"),
        ];

        for (i, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("///") {
                continue;
            }

            for (pattern, desc) in &patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, i + 1);
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: i + 1,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line.to_string(),
                            problem: format!("Weak cryptography: {}", desc),
                            fix_hint: "Use SHA-256 or SHA-3 for hashing, AES-256-GCM for encryption, \
                                       RNGCryptoServiceProvider for random values, \
                                       and Argon2id or PBKDF2 with high iterations for password derivation.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                        break;
                    }
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-008 — Path Traversal
// CWE-22 | OWASP A01:2021 | High severity
// Detects: File.ReadAllText, FileStream, Path.Combine with user input without validation
// ---------------------------------------------------------------------------

pub struct CSharpPathTraversal;

impl LangRule for CSharpPathTraversal {
    fn id(&self) -> &str { "CSHARP-008" }
    fn name(&self) -> &str { "Path Traversal Vulnerability" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_calls: HashSet<&str> = [
            "File.ReadAllText",
            "File.ReadAllLines",
            "File.ReadAllBytes",
            "File.WriteAllText",
            "File.WriteAllLines",
            "File.Copy",
            "File.Move",
            "File.Delete",
            "File.Exists",
            "FileStream",
            "StreamReader",
            "StreamWriter",
            "Directory.GetFiles",
            "Directory.GetDirectories",
            "Path.Combine",
            "Path.GetFullPath",
            "Path.GetFileName",
            "DirectoryInfo",
            "FileInfo",
        ].into_iter().collect();

        for call in &tree.calls {
            if dangerous_calls.contains(call.callee.as_str()) {
                let (start, end) = get_line_offsets(code, call.start_line);
                let snippet = code.lines().nth(call.start_line - 1).unwrap_or("").to_string();

                // Path traversal indicators
                let context_line = &snippet.to_lowercase();
                let has_user_input = context_line.contains("request")
                    || context_line.contains("query")
                    || context_line.contains("params")
                    || context_line.contains("form")
                    || context_line.contains("input")
                    || context_line.contains("posted")
                    || context_line.contains("session")
                    || context_line.contains("header")
                    || context_line.contains("cookie");

                let problem = if has_user_input {
                    "Path traversal: file operation on potentially untrusted input. \
                     Attackers can use paths like ../../../etc/passwd to access files outside the intended directory."
                } else {
                    "Potential path traversal: file operation without apparent input validation. \
                     Ensure the path is validated and restricted to an allowed directory."
                };

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet,
                    problem: problem.to_string(),
                    fix_hint: "Validate paths with Path.GetFullPath() and verify the result starts with \
                               the allowed base directory. Use Path.GetFileName() to strip directory components. \
                               Implement allowlisting of file extensions.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        // Regex fallback for file patterns
        let file_re = Regex::new(
            r"(?i)(File\.|Directory\.|Path\.|FileStream|StreamReader|StreamWriter|FileInfo|DirectoryInfo)"
        ).unwrap();

        for (i, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            if file_re.is_match(line) {
                if !findings.iter().any(|f: &LangFinding| f.line == i + 1 && f.rule_id == self.id()) {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.to_string(),
                        problem: "File system operation detected. Ensure the file path is validated \
                                  and does not allow traversal outside the intended directory.".to_string(),
                        fix_hint: "Use Path.GetFullPath() and check it stays within a whitelisted base directory. \
                                   Validate and sanitize all user-supplied path components.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-009 — Insecure Randomness
// CWE-338 | Medium severity
// Detects: new Random() used for security-sensitive purposes
// ---------------------------------------------------------------------------

pub struct CSharpInsecureRandomness;

impl LangRule for CSharpInsecureRandomness {
    fn id(&self) -> &str { "CSHARP-009" }
    fn name(&self) -> &str { "Insecure Random Number Generator" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r"(?i)\bnew\s+Random\s*\(\s*\)", "new Random() — seeded from system clock, predictable"),
            (r"(?i)\bnew\s+Random\s*\(\s*DateTime\.Now", "Random seeded with DateTime.Now — easily predictable"),
            (r"(?i)\bnew\s+Random\s*\(\s*\d{5,}", "Random seeded with a fixed or low-entropy value"),
        ];

        for (i, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            for (pattern, desc) in &patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, i + 1);
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: i + 1,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line.to_string(),
                            problem: format!(
                                "Insecure RNG: {}. \
                                The Random class produces predictable numbers \
                                and must not be used for security, cryptography, or token generation.",
                                desc
                            ),
                            fix_hint: "Use System.Security.Cryptography.RandomNumberGenerator, \
                                       or in .NET 6+: Random.Shared (thread-safe but still not for crypto). \
                                       For security-sensitive values, use cryptographic random.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                        break;
                    }
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-010 — Cross-Site Scripting (XSS) in ASP.NET
// CWE-79 | OWASP A03:2021 | High severity
// Detects: Raw HTML rendering, unencoded output, dangerous innerHTML usage
// ---------------------------------------------------------------------------

pub struct CSharpXssVulnerability;

impl LangRule for CSharpXssVulnerability {
    fn id(&self) -> &str { "CSHARP-010" }
    fn name(&self) -> &str { "Cross-Site Scripting (XSS) Vulnerability" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_calls: HashSet<&str> = [
            "Html.Raw",
            "Raw",
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "WriteLiteral",
            "Response.Write",
            "HttpUtility.HtmlDecode",
            "Server.HtmlEncode",
            "Url.PathEncode",
        ].into_iter().collect();

        for call in &tree.calls {
            let callee_lower = call.callee.to_lowercase();
            for dangerous in &dangerous_calls {
                if callee_lower.contains(&dangerous.to_lowercase()) {
                    let is_html_raw = callee_lower.contains("html.raw") || callee_lower == "raw";
                    let is_unsafe_encode = callee_lower.contains("httputility.htmldecode")
                        || callee_lower.contains("server.htmlencode");

                    let problem = if is_html_raw {
                        "XSS: Html.Raw() renders unescaped HTML content directly. \
                         If the content contains user input, attackers can inject malicious scripts."
                    } else if is_unsafe_encode {
                        "XSS: Unsafe encoding method. Server.HtmlEncode is outdated; use modern encoding APIs."
                    } else {
                        "XSS: Direct DOM manipulation with user-controlled input can lead to script injection."
                    };

                    let fix_hint = if is_html_raw {
                        "Remove Html.Raw() and let the view engine auto-encode. \
                         If HTML is intentional, validate against a strict allowlist of safe tags/attributes."
                    } else {
                        "Always encode user input before rendering. In Razor, use @model instead of @Html.Raw(). \
                         Use AntiXssEncoder or modern encoding libraries."
                    };

                    let snippet = tree.calls.iter()
                        .find(|c| c.callee == call.callee && c.start_line == call.start_line)
                        .map(|c| c.callee.clone())
                        .unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet,
                        problem: problem.to_string(),
                        fix_hint: fix_hint.to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                    break;
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-011 — Broken Authentication / Missing Authorization
// CWE-862 | OWASP A01:2021 | High severity
// Detects: Controller/Action methods without [Authorize] attribute
// ---------------------------------------------------------------------------

pub struct CSharpBrokenAuth;

impl LangRule for CSharpBrokenAuth {
    fn id(&self) -> &str { "CSHARP-011" }
    fn name(&self) -> &str { "Missing Authorization / Broken Authentication" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check function/method names that look like API endpoints or sensitive operations
        let sensitive_patterns = [
            (r"(?i)(login|auth|signin|authenticate)", "authentication endpoint"),
            (r"(?i)(admin|dashboard|manage|settings|config)", "administrative endpoint"),
            (r"(?i)(user|profile|account|passwd|password)", "user data endpoint"),
            (r"(?i)(api|rest|endpoint|controller)", "API endpoint"),
            (r"(?i)(payment|transaction|order|checkout)", "financial endpoint"),
            (r"(?i)(data|export|download|upload|file)", "data access endpoint"),
        ];

        // Check if [Authorize] attribute is present in the file (class or method level)
        let has_authorize = code.contains("[Authorize]")
            || code.contains("[AllowAnonymous]")
            || code.contains("IAuthorizationService")
            || code.contains("AuthorizeAttribute");

        let has_web_attrs = code.contains("[HttpGet]")
            || code.contains("[HttpPost]")
            || code.contains("[HttpPut]")
            || code.contains("[HttpDelete]")
            || code.contains("[Route")
            || code.contains("Controller")
            || code.contains("ApiController");

        if has_web_attrs && !has_authorize {
            // Likely an ASP.NET Core / MVC project without global auth
            for function in &tree.functions {
                let func_name_lower = function.name.to_lowercase();

                for (pattern, desc) in &sensitive_patterns {
                    if let Ok(re) = Regex::new(pattern) {
                        if re.is_match(&function.name) || re.is_match(&func_name_lower) {
                            let (start, end) = get_line_offsets(code, function.start_line);
                            let snippet = code.lines().nth(function.start_line - 1).unwrap_or("").to_string();

                            findings.push(LangFinding {
                                rule_id: self.id().to_string(),
                                severity: self.severity().to_string(),
                                line: function.start_line,
                                column: 0,
                                start_byte: start,
                                end_byte: end,
                                snippet,
                                problem: format!(
                                    "Potential broken authentication: {} appears to handle sensitive operations \
                                     but no [Authorize] attribute was found. \
                                     This endpoint may be accessible without authentication.",
                                    desc
                                ),
                                fix_hint: "Add [Authorize] attribute to the controller or action method. \
                                           Use policy-based authorization for fine-grained access control. \
                                           Consider [AllowAnonymous] only for explicitly public endpoints.".to_string(),
                                auto_fix_available: false,
                        replacement: String::new(),
                            });
                            break;
                        }
                    }
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-012 — XML External Entity (XXE)
// CWE-611 | High severity
// Detects: XmlReader / XDocument loading without disabling DTD processing
// ---------------------------------------------------------------------------

pub struct CSharpXxeVulnerability;

impl LangRule for CSharpXxeVulnerability {
    fn id(&self) -> &str { "CSHARP-012" }
    fn name(&self) -> &str { "XML External Entity (XXE) Vulnerability" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_calls: HashSet<&str> = [
            "XmlReader.Load",
            "XmlReader.Create",
            "XDocument.Load",
            "XElement.Load",
            "XmlDocument.Load",
            "XmlDocument.LoadXml",
            "Linq.XDocument",
            "Linq.XElement",
        ].into_iter().collect();

        for call in &tree.calls {
            if dangerous_calls.contains(call.callee.as_str()) {
                let (start, end) = get_line_offsets(code, call.start_line);
                let snippet = code.lines().nth(call.start_line - 1).unwrap_or("").to_string();

                // Check nearby lines for DTD/prohibit settings
                let context_start = call.start_line.saturating_sub(1);
                let context_end = (call.start_line + 2).min(code.lines().count());
                let context: String = (context_start..context_end)
                    .filter_map(|i| code.lines().nth(i))
                    .collect::<Vec<_>>()
                    .join("\n");

                let has_safe_settings = context.contains("DtdProcessing = DtdProcessing.Prohibit")
                    || context.contains("DtdProcessing = DtdProcessing.Ignore")
                    || context.contains("XmlResolver = null")
                    || context.contains("ProhibitDtd")
                    || context.contains("Feature.LowCardinality");

                if !has_safe_settings {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet,
                        problem: "Potential XXE: XML parsing without disabling external entities. \
                                  Attackers can exploit this to read local files, perform SSRF, or cause DoS.".to_string(),
                        fix_hint: "Set XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit and \
                                   XmlReaderSettings.XmlResolver = null. \
                                   For XmlDocument, set XmlUrlResolver = null and \
                                   XDocument/XElement: use XmlReader with safe settings.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        // Regex fallback
        let xml_re = Regex::new(
            r"(?i)(XmlReader|XDocument|XElement|XmlDocument|Linq)\.(Load|Parse|Read)\s*\("
        ).unwrap();

        for (i, line) in code.lines().enumerate() {
            if xml_re.is_match(line) {
                if !findings.iter().any(|f: &LangFinding| f.line == i + 1 && f.rule_id == self.id()) {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.to_string(),
                        problem: "XML processing detected. Ensure XXE protections are enabled.".to_string(),
                        fix_hint: "Configure XmlReader with DtdProcessing.Prohibit and XmlResolver = null. \
                                   Never load XML from untrusted sources.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-013 —敞開的重定向 (Open Redirect)
// CWE-601 | Medium severity
// Detects: Response.Redirect / RedirectToRoute / RedirectToAction with unvalidated input
// ---------------------------------------------------------------------------

pub struct CSharpOpenRedirect;

impl LangRule for CSharpOpenRedirect {
    fn id(&self) -> &str { "CSHARP-013" }
    fn name(&self) -> &str { "Open Redirect Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let redirect_calls: HashSet<&str> = [
            "Response.Redirect",
            "Response.RedirectPermanent",
            "RedirectToAction",
            "RedirectToRoute",
            "Redirect",
            "RedirectToPage",
            "LocalRedirect",
            "LocalRedirectPermanent",
            "RedirectToActionPermanent",
            "RedirectToRoutePermanent",
            "Server.Transfer",
            "Server.TransferRequest",
        ].into_iter().collect();

        for call in &tree.calls {
            if redirect_calls.contains(call.callee.as_str()) {
                let (start, end) = get_line_offsets(code, call.start_line);
                let snippet = code.lines().nth(call.start_line - 1).unwrap_or("").to_string();

                // Check if the argument contains request data (redirect to user-controlled URL)
                let has_user_input = snippet.to_lowercase().contains("request")
                    || snippet.to_lowercase().contains("querystring")
                    || snippet.to_lowercase().contains("query[")
                    || snippet.to_lowercase().contains("form[")
                    || snippet.to_lowercase().contains("params[")
                    || snippet.to_lowercase().contains("session")
                    || snippet.to_lowercase().contains("cookie");

                let problem = if has_user_input {
                    "Open redirect: redirect target appears to use unvalidated user input. \
                     Attackers can craft URLs to redirect victims to phishing or malware sites."
                } else {
                    "Redirect detected without apparent input validation. \
                     Ensure the redirect target is validated against a whitelist."
                };

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet,
                    problem: problem.to_string(),
                    fix_hint: "Validate redirect URLs against a whitelist of allowed domains. \
                               Never redirect based purely on user-supplied input without validation. \
                               Use Request.ApplicationPath for same-app redirects.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-014 — LDAP Injection
// CWE-90 | Medium severity
// Detects: LDAP query construction with user input
// ---------------------------------------------------------------------------

pub struct CSharpLdapInjection;

impl LangRule for CSharpLdapInjection {
    fn id(&self) -> &str { "CSHARP-014" }
    fn name(&self) -> &str { "LDAP Injection Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let ldap_calls: HashSet<&str> = [
            "DirectoryEntry",
            "DirectorySearcher",
            "LdapConnection",
            "PrincipalContext",
            "UserPrincipal",
            "GroupPrincipal",
            "LdapQuery",
            "SearchRequest",
        ].into_iter().collect();

        for call in &tree.calls {
            if ldap_calls.contains(call.callee.as_str()) {
                let (start, end) = get_line_offsets(code, call.start_line);
                let snippet = code.lines().nth(call.start_line - 1).unwrap_or("").to_string();

                // Check for filter string concatenation
                let has_filter = snippet.to_lowercase().contains("filter")
                    || snippet.contains("(")
                    || snippet.contains("=")
                    || snippet.contains("ldap")
                    || snippet.contains("cn=")
                    || snippet.contains("ou=");

                let has_user_input = snippet.to_lowercase().contains("request")
                    || snippet.to_lowercase().contains("params")
                    || snippet.to_lowercase().contains("input")
                    || snippet.to_lowercase().contains("query")
                    || snippet.contains("+");

                if has_filter && has_user_input {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet,
                        problem: "Potential LDAP injection: LDAP query constructed with user input. \
                                  Attackers can manipulate LDAP queries to bypass authentication \
                                  or extract sensitive directory information.".to_string(),
                        fix_hint: "Escape special LDAP characters in user input: * ( ) \\ NUL. \
                                   Use parameterized LDAP queries or encode input with proper LDAP escaping. \
                                   Allowlist input values where possible.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        // Regex fallback for LDAP query patterns
        let ldap_re = Regex::new(
            r"(?i)(DirectoryEntry|DirectorySearcher|LdapConnection|PrincipalContext)\s*\([^)]*\+"
        ).unwrap();

        for (i, line) in code.lines().enumerate() {
            if ldap_re.is_match(line) {
                if !findings.iter().any(|f: &LangFinding| f.line == i + 1 && f.rule_id == self.id()) {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.to_string(),
                        problem: "Potential LDAP injection: LDAP query construction with string concatenation.".to_string(),
                        fix_hint: "Escape LDAP special characters in user input. \
                                   Use safe query builder APIs or allowlist validation.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// AI-Generated Code Detection Rules
// ---------------------------------------------------------------------------

// ─── CSHARP-AI-001: Slopsquatting ───────────────────────────────────────────

pub struct CSharpSlopsquatting;

impl LangRule for CSharpSlopsquatting {
    fn id(&self) -> &str { "CSHARP-AI-001" }
    fn name(&self) -> &str { "AI-Hallucinated Dependency (Slopsquatting)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let hallucinated: Vec<&str> = vec![
            "Faker.NET", "Newtonsoft.Json.Hacked", "FakeHttpClient",
            "Mock ILogger", "TestFramework.Fake",
            "nuget.fake-package", "test-pkg-xyz",
        ];
        for imp in &tree.imports {
            for fake in &hallucinated {
                if imp.module.contains(fake) || imp.name.contains(fake) {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: imp.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: imp.module.clone(),
                        problem: format!("Slopsquatting Risk: The package '{}' appears to be hallucinated.", imp.module),
                        fix_hint: "Verify this package exists on nuget.org before installing.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── CSHARP-AI-002: Verbose Error Exposure ───────────────────────────────────

pub struct CSharpVerboseError;

impl LangRule for CSharpVerboseError {
    fn id(&self) -> &str { "CSHARP-AI-002" }
    fn name(&self) -> &str { "Verbose Error Exposure" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r#"return\s+StatusCode\s*\(\s*\d+\s*,\s*e\.Message"#, "Returning error message directly"),
            (r#"return\s+BadRequest\s*\(\s*e\.Message\s*\)"#, "BadRequest with exception message"),
            (r#"return\s+Ok\s*\(\s*e\.Message\s*\)"#, "Ok result with exception message"),
            (r#"throw\s+new\s+Exception\s*\(\s*e\.Message\s*\)"#, "Throwing exception with inner message"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Log error details, return sanitized generic message.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── CSHARP-AI-003: Missing Input Validation ─────────────────────────────────

pub struct CSharpMissingInputValidation;

impl LangRule for CSharpMissingInputValidation {
    fn id(&self) -> &str { "CSHARP-AI-003" }
    fn name(&self) -> &str { "Missing Input Validation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r#"(Request\.Query|Request\.Form|RouteData)\[.*\]\s*(?!.*Contains)"#, "Direct access to query/form without validation"),
            (r#"string\s+\w+\s*=\s*Request\[.*\]\s*;"#, "Request parameter assigned without validation"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Use model binding with DataAnnotations or explicit validation.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── CSHARP-AI-004: AI-Generated Code Marker ─────────────────────────────────

pub struct CSharpAiGenComment;

impl LangRule for CSharpAiGenComment {
    fn id(&self) -> &str { "CSHARP-AI-004" }
    fn name(&self) -> &str { "AI-Generated Code Marker" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
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
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: comment.start_line,
                            column: 0,
                            start_byte: 0,
                            end_byte: 0,
                            snippet: comment.text.clone(),
                            problem: "AI-Generated Code Detected".to_string(),
                            fix_hint: "Review AI-generated code carefully before production use.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// CSHARP-015 — Mass Assignment / Over-posting (CWE-915)
// OWASP A01:2021 | Medium severity
// Detects: JsonConvert.DeserializeObject without [JsonIgnore]
// ---------------------------------------------------------------------------

pub struct CSharpMassAssignment;

impl LangRule for CSharpMassAssignment {
    fn id(&self) -> &str { "CSHARP-015" }
    fn name(&self) -> &str { "Mass Assignment / Over-posting Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let mass_assign_patterns = [
            (r"(?i)JsonConvert\.DeserializeObject\s*<", "JSON deserialization that can bind arbitrary properties"),
            (r"(?i)JsonSerializer\.Deserialize\s*<", "System.Text.Json deserialization"),
            (r"(?i)FromBody|FromForm", "ASP.NET model binding from request body/form"),
            (r"(?i)\.Bind\(|\.Update\(|\.Patch\(", "EF Core binding methods that can mass-assign properties"),
        ];

        for (i, line) in code.lines().enumerate() {
            for (pat, label) in &mass_assign_patterns {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, i + 1);
                        findings.push(LangFinding {
                            rule_id: "CSHARP-015".to_string(),
                            severity: "medium".to_string(),
                            line: i + 1,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line.to_string(),
                            problem: format!("Mass assignment risk: {}. Without [JsonIgnore] or [BindNever] attributes, attackers can set properties they shouldn't be able to modify.", label),
                            fix_hint: "Use [JsonIgnore] on sensitive properties. Use [Bind(Include)] or [Bind(Exclude)] to explicitly allowlist/denylist properties. Consider using DTOs instead of domain entities.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                        break;
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-016 — Incorrect Authorization / Privilege Escalation (CWE-862, 863)
// OWASP A01:2021 | High severity
// Detects: Missing [Authorize] on controllers, incorrect role checks
// ---------------------------------------------------------------------------

pub struct CSharpIncorrectAuthorization;

impl LangRule for CSharpIncorrectAuthorization {
    fn id(&self) -> &str { "CSHARP-016" }
    fn name(&self) -> &str { "Incorrect Authorization / Privilege Escalation" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check for [Authorize] on class vs method level
        let has_class_auth = Regex::new(r#"(?i)\[Authorize\]"#)
            .map(|re| re.find_iter(code).any(|m| {
                let line = code[..m.start()].matches('\n').count() + 1;
                let class_line = code.lines().nth(line - 2.max(1)).unwrap_or("");
                class_line.contains("class") || class_line.contains("Controller")
            })).unwrap_or(false);

        let has_method_auth = Regex::new(r#"(?i)\[Authorize\]"#)
            .map(|re| re.is_match(code)).unwrap_or(false);

        let has_web = code.contains("Controller") || code.contains("ApiController")
            || code.contains("[HttpGet]") || code.contains("[HttpPost]");

        if has_web && !has_class_auth && !has_method_auth {
            for func in &tree.functions {
                let name_lower = func.name.to_lowercase();
                let sensitive = ["admin", "manage", "config", "settings", "user", "account",
                    "role", "permission", "delete", "update", "create", "export", "payment"];
                if sensitive.iter().any(|s| name_lower.contains(s)) {
                    let (start, end) = get_line_offsets(code, func.start_line);
                    let snippet = code.lines().nth(func.start_line - 1).unwrap_or("").to_string();
                    findings.push(LangFinding {
                        rule_id: "CSHARP-016".to_string(),
                        severity: "high".to_string(),
                        line: func.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet,
                        problem: "Sensitive method detected without any authorization attributes. This can allow unauthenticated access to privileged operations.".to_string(),
                        fix_hint: "Add [Authorize] to the method or class. Use [Authorize(Roles = \"Admin\")] for role-based access. Consider policy-based authorization with IAuthorizationService.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        // Detect hardcoded role checks that can be bypassed
        let bad_role_re = Regex::new(r##"(?i)User\.IsInRole\s*\(\s*['"][^'"]+['"]\s*\)"##).unwrap();
        for m in bad_role_re.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let snippet = code.lines().nth(line - 1).unwrap_or("");
            if !findings.iter().any(|f: &LangFinding| f.line == line) {
                findings.push(LangFinding {
                    rule_id: "CSHARP-016".to_string(),
                    severity: "high".to_string(),
                    line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: snippet.to_string(),
                    problem: "Role-based authorization check found. Ensure this is backed by proper server-side validation, not just client-provided claims.".to_string(),
                    fix_hint: "Always validate roles server-side with IAuthorizationService. Never rely solely on User.IsInRole() for critical decisions. Combine with policy-based authorization.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-017 — Insecure Cookie Configuration (CWE-614)
// OWASP A05:2021 | Medium severity
// Detects: HttpCookie without Secure, HttpOnly flags
// ---------------------------------------------------------------------------

pub struct CSharpInsecureCookie;

impl LangRule for CSharpInsecureCookie {
    fn id(&self) -> &str { "CSHARP-017" }
    fn name(&self) -> &str { "Insecure Cookie Configuration" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let cookie_patterns = [
            (r"(?i)new\s+HttpCookie\s*\(", "HttpCookie created without security flags"),
            (r"(?i)Response\.Cookies\.Add\s*\(", "Cookie added to response without security flags"),
            (r"(?i)CookieOptions\s*\{[^}]*\}\s*(?!\.Secure)(?!\.HttpOnly)", "CookieOptions without Secure or HttpOnly"),
        ];

        let has_secure = Regex::new(r"(?i)\.Secure\s*=\s*true").unwrap();
        let has_httponly = Regex::new(r"(?i)\.HttpOnly\s*=\s*true").unwrap();
        let has_samesite = Regex::new(r"(?i)\.SameSite\s*=").unwrap();

        for (i, line) in code.lines().enumerate() {
            for (pat, label) in &cookie_patterns {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) {
                        let has_sec = has_secure.is_match(line);
                        let has_httpon = has_httponly.is_match(line);
                        let has_sames = has_samesite.is_match(line);

                        if !has_sec || !has_httpon || !has_sames {
                            let (start, end) = get_line_offsets(code, i + 1);
                            let mut problems = vec![];
                            if !has_sec { problems.push("Secure=false"); }
                            if !has_httpon { problems.push("HttpOnly=false"); }
                            if !has_sames { problems.push("SameSite not set"); }

                            findings.push(LangFinding {
                                rule_id: "CSHARP-017".to_string(),
                                severity: "medium".to_string(),
                                line: i + 1,
                                column: 0,
                                start_byte: start,
                                end_byte: end,
                                snippet: line.to_string(),
                                problem: format!("Insecure cookie: {} — cookies without proper flags are vulnerable to XSS and CSRF attacks.", problems.join(", ")),
                                fix_hint: "Set Secure=true, HttpOnly=true, and SameSite=SameSiteMode.Strict (or Lax). Use CookieOptions: new CookieOptions { Secure = Required, HttpOnly = true, SameSite = SameSiteMode.Strict }.".to_string(),
                                auto_fix_available: false,
                        replacement: String::new(),
                            });
                        }
                        break;
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-018 — Deserialization Gadget Chain (CWE-502)
// OWASP A08:2021 | Critical severity
// Detects: TypeNameHandling = Auto in Newtonsoft.Json
// ---------------------------------------------------------------------------

pub struct CSharpDeserializationGadget;

impl LangRule for CSharpDeserializationGadget {
    fn id(&self) -> &str { "CSHARP-018" }
    fn name(&self) -> &str { "Deserialization Gadget Chain Vulnerability" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r"(?i)TypeNameHandling\s*=\s*TypeNameHandling\.Auto", "TypeNameHandling.Auto allows type resolution from JSON - gadget chain risk"),
            (r"(?i)TypeNameHandling\s*=\s*TypeNameHandling\.All", "TypeNameHandling.All is extremely dangerous"),
            (r"(?i)TypeNameHandling\s*=\s*TypeNameHandling\.Objects", "TypeNameHandling.Objects allows arbitrary type instantiation"),
            (r"(?i)SerializationBinder\s*=\s*null", "Null SerializationBinder allows arbitrary type loading"),
            (r"(?i)DefaultSettings\s*=.*TypeNameHandling", "Global JSON settings with TypeNameHandling enabled"),
            (r"(?i)JsonSerializerSettings.*TypeNameHandling\.Auto", "JsonSerializerSettings with TypeNameHandling.Auto"),
            (r"(?i)JavaScriptSerializer.*TypeResolver", "JavaScriptSerializer with custom TypeResolver is exploitable"),
        ];

        for (i, line) in code.lines().enumerate() {
            for (pat, problem) in &patterns {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, i + 1);
                        findings.push(LangFinding {
                            rule_id: "CSHARP-018".to_string(),
                            severity: "critical".to_string(),
                            line: i + 1,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line.to_string(),
                            problem: problem.to_string(),
                            fix_hint: "Always set TypeNameHandling = TypeNameHandling.None (default). If type info is needed, use a custom SerializationBinder with strict allowlist. Never deserialize untrusted input with type resolution enabled.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                        break;
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }
}

// ---------------------------------------------------------------------------
// CSHARP-019 — Regex Denial of Service (ReDoS) (CWE-1333)
// Medium severity
// Detects: Nested quantifiers in regex patterns, catastrophic backtracking
// ---------------------------------------------------------------------------

pub struct CSharpRegexDos;

impl LangRule for CSharpRegexDos {
    fn id(&self) -> &str { "CSHARP-019" }
    fn name(&self) -> &str { "Regex Denial of Service (ReDoS) Pattern" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // ReDoS patterns: nested quantifiers with overlapping alternatives
        let redos_patterns = [
            (r#"(?i)\([^)]*[+*][^)]*\)[+*]"#, "Nested quantifier: (a+)+ or (a*) * patterns cause catastrophic backtracking"),
            (r#"(?i)\([^)]*[+*][^)]*\)\{[^}]*\}\s*[+*]"#, "Nested quantifier with range"),
            (r#"(?i)\([^)]*\|[^)]*\)[+*]"#, "Alternation with quantifier can cause exponential backtracking"),
            (r#"(?i)\.[+*]\.[+*]"#, "Overlapping greedy quantifiers"),
            (r#"(?i)\([^)]*[^?]\)[+*]\s*\?"#, "Possessive quantifier or lazy overlap pattern"),
        ];

        let dangerous_keywords = ["email", "url", "uri", "host", "domain", "path", "input", "user",
            "string", "text", "pattern", "regex", "validate", "check", "parse"];

        for (i, line) in code.lines().enumerate() {
            if line.contains("Regex") || line.contains("Matches") || line.contains("IsMatch") {
                let line_lower = line.to_lowercase();
                if dangerous_keywords.iter().any(|k| line_lower.contains(k)) {
                    for (pat, problem) in &redos_patterns {
                        if let Ok(re) = Regex::new(pat) {
                            if re.is_match(line) {
                                let (start, end) = get_line_offsets(code, i + 1);
                                findings.push(LangFinding {
                                    rule_id: "CSHARP-019".to_string(),
                                    severity: "medium".to_string(),
                                    line: i + 1,
                                    column: 0,
                                    start_byte: start,
                                    end_byte: end,
                                    snippet: line.to_string(),
                                    problem: problem.to_string(),
                                    fix_hint: "Refactor regex to avoid nested quantifiers. Use atomic groups or possessive quantifiers (C# doesn't support natively, but restructure). Consider using RegexOptions.Debug or a static analysis tool to verify no ReDoS. Benchmark with long inputs.".to_string(),
                                    auto_fix_available: false,
                        replacement: String::new(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-020: XML External Entity (XXE)
// Severity: high | CWE-611
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpXxe;

impl LangRule for CSharpXxe {
    fn id(&self) -> &str { "CSHARP-020" }
    fn name(&self) -> &str { "XML External Entity (XXE)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["XmlDocument", "XmlReader", "XDocument.Load"];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "XML parser without XXE protection.".to_string(),
                    fix_hint: "Disable DTD processing: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-021: SQL Injection via EF Raw SQL
// Severity: critical | CWE-89
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpSqlInjectionEF;

impl LangRule for CSharpSqlInjectionEF {
    fn id(&self) -> &str { "CSHARP-021" }
    fn name(&self) -> &str { "SQL Injection via EF Raw SQL" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let sql_funcs = ["ExecuteSqlRaw", "ExecuteSqlCommand", "FromSqlRaw", "SqlQuery"];
        for call in &tree.calls {
            if sql_funcs.iter().any(|f| call.callee.contains(f)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("+") || args_str.contains("string.Format") || args_str.contains("$\"") {
                    let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "EF raw SQL query with string interpolation. SQL injection risk.".to_string(),
                        fix_hint: "Use parameterized queries: ExecuteSqlRaw(\"SELECT * FROM Users WHERE Id = {0}\", userId);.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-022: Path Traversal
// Severity: high | CWE-22
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpPathTraversalRaw;

impl LangRule for CSharpPathTraversalRaw {
    fn id(&self) -> &str { "CSHARP-022" }
    fn name(&self) -> &str { "Path Traversal Vulnerability" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["File.ReadAllText", "File.ReadLines", "File.Open", "File.Copy", "Directory.GetFiles"];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("Request") || args_str.contains("query") || args_str.contains("param") {
                    let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "File operation with user-controlled path. Path traversal risk.".to_string(),
                        fix_hint: "Validate paths: Path.GetFullPath(), Path.Combine() with a base directory, reject '..'.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-023: Insecure Random Number Generator
// Severity: medium | CWE-338
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpInsecureRandom;

impl LangRule for CSharpInsecureRandom {
    fn id(&self) -> &str { "CSHARP-023" }
    fn name(&self) -> &str { "Insecure Random Number Generator" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for call in &tree.calls {
            if call.callee.contains("new Random()") || call.callee.contains("Random()") {
                let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "System.Random is predictable and not suitable for security purposes.".to_string(),
                    fix_hint: "Use RandomNumberGenerator.GetInt32() or System.Security.Cryptography.RandomNumberGenerator.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-024: Hardcoded Connection Strings
// Severity: high | CWE-798
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpHardcodedConnectionString;

impl LangRule for CSharpHardcodedConnectionString {
    fn id(&self) -> &str { "CSHARP-024" }
    fn name(&self) -> &str { "Hardcoded Connection Strings" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for call in &tree.calls {
            if call.callee.contains("ConfigurationManager") || call.callee.contains("ConnectionStrings") {
                let args_str = call.arguments.join(" ");
                if !args_str.contains("env") && !args_str.contains("Environment") {
                    let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "Connection string may be hardcoded in source code.".to_string(),
                        fix_hint: "Use ConfigurationManager with external config or environment variables.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-025: Weak Cryptography
// Severity: high | CWE-327
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpWeakCrypto;

impl LangRule for CSharpWeakCrypto {
    fn id(&self) -> &str { "CSHARP-025" }
    fn name(&self) -> &str { "Weak Cryptography Usage" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["DES", "RC2", "RC4", "MD5", "SHA1", "RijndaelManaged"];
        for call in &tree.calls {
            let args_str = call.arguments.join(" ");
            if dangerous.iter().any(|d| call.callee.contains(d) || args_str.contains(d)) {
                let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "Weak cryptographic algorithm (DES/RC4/MD5/SHA1) detected.".to_string(),
                    fix_hint: "Use AES-256 (Aes.Create()) or SHA-256 for hashing.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-026: RCE via Deserialization
// Severity: critical | CWE-94
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpDeserializationRCE;

impl LangRule for CSharpDeserializationRCE {
    fn id(&self) -> &str { "CSHARP-026" }
    fn name(&self) -> &str { "Remote Code Execution via Deserialization" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["BinaryFormatter", "LosFormatter", "ObjectStateFormatter", "SoapFormatter", "NetDataContractSerializer"];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "Dangerous deserializer (BinaryFormatter/SoapFormatter) used. Can lead to RCE.".to_string(),
                    fix_hint: "Use System.Text.Json or Newtonsoft.Json with TypeNameHandling = None.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-027: Open Redirect
// Severity: medium | CWE-601
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpOpenRedirectRaw;

impl LangRule for CSharpOpenRedirectRaw {
    fn id(&self) -> &str { "CSHARP-027" }
    fn name(&self) -> &str { "Open Redirect Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let redirect_methods = ["Redirect", "RedirectToAction", "RedirectToRoute", "PermanentRedirect"];
        for call in &tree.calls {
            if redirect_methods.iter().any(|m| call.callee.contains(m)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("Request") || args_str.contains("query") || args_str.contains("returnUrl") || args_str.contains("url") {
                    let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "Redirect to user-controlled URL. Open redirect vulnerability.".to_string(),
                        fix_hint: "Validate redirect URLs against an allowlist of permitted domains.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-028: SSRF - Internal IPs
// Severity: medium | CWE-918
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpSsrf;

impl LangRule for CSharpSsrf {
    fn id(&self) -> &str { "CSHARP-028" }
    fn name(&self) -> &str { "Server-Side Request Forgery (SSRF)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let http_funcs = ["HttpClient", "WebClient", "WebRequest", "HttpWebRequest", "HttpRequestMessage"];
        for call in &tree.calls {
            if http_funcs.iter().any(|f| call.callee.contains(f)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("Request") || args_str.contains("query") || args_str.contains("url") {
                    let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "HTTP request with user-controlled URL. SSRF vulnerability.".to_string(),
                        fix_hint: "Validate and allowlist URLs. Block internal IP ranges.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-AI-005: AI Hardcoded Connection Strings
// Severity: high | CWE-798
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpAiHardcodedConnectionString;

impl LangRule for CSharpAiHardcodedConnectionString {
    fn id(&self) -> &str { "CSHARP-AI-005" }
    fn name(&self) -> &str { "AI: Hardcoded Connection Strings" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for call in &tree.calls {
            if call.callee.contains("ConfigurationManager.ConnectionStrings") || call.callee.contains("SqlConnection") {
                let args_str = call.arguments.join(" ");
                if args_str.contains("password") || args_str.contains("pwd") || args_str.contains("Server=") {
                    let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "AI-generated code may contain hardcoded connection strings.".to_string(),
                        fix_hint: "Store connection strings in configuration files with proper access controls.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-AI-006: AI SQL Injection via String Interpolation
// Severity: critical | CWE-89
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpAiSqlInjection;

impl LangRule for CSharpAiSqlInjection {
    fn id(&self) -> &str { "CSHARP-AI-006" }
    fn name(&self) -> &str { "AI: SQL Injection via String Interpolation" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let sql_funcs = ["ExecuteSqlRaw", "FromSqlRaw", "SqlQuery", "ExecuteSqlCommandAsync"];
        for call in &tree.calls {
            if sql_funcs.iter().any(|f| call.callee.contains(f)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("$\"") || args_str.contains("string.Format") {
                    let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "AI-generated SQL query with string interpolation.".to_string(),
                        fix_hint: "Use parameterized queries: ExecuteSqlRaw(\"...{0}\", param);.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-AI-007: AI Command Injection
// Severity: critical | CWE-78
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpAiCommandInjection;

impl LangRule for CSharpAiCommandInjection {
    fn id(&self) -> &str { "CSHARP-AI-007" }
    fn name(&self) -> &str { "AI: Command Injection - Process.Start()" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for call in &tree.calls {
            if call.callee.contains("Process.Start") || call.callee.contains("Shell.Execute") {
                let args_str = call.arguments.join(" ");
                if args_str.contains("Request") || args_str.contains("query") || args_str.contains("param") {
                    let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "AI-generated command execution with user-controlled input.".to_string(),
                        fix_hint: "Validate input against allowlist. Use ProcessStartInfo with arguments separately.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-AI-008: AI XXE via XmlDocument
// Severity: high | CWE-611
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpAiXxe;

impl LangRule for CSharpAiXxe {
    fn id(&self) -> &str { "CSHARP-AI-008" }
    fn name(&self) -> &str { "AI: XXE via XmlDocument" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for call in &tree.calls {
            if call.callee.contains("XmlDocument") || call.callee.contains("XDocument.Load") {
                let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "AI-generated XML parser without XXE protection.".to_string(),
                    fix_hint: "Disable DTD: xmlDoc.XmlResolver = null; for XDocument: use Load with XmlReader settings.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-AI-009: AI Insecure Deserialization
// Severity: critical | CWE-502
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpAiInsecureDeserialization;

impl LangRule for CSharpAiInsecureDeserialization {
    fn id(&self) -> &str { "CSHARP-AI-009" }
    fn name(&self) -> &str { "AI: Insecure Deserialization - BinaryFormatter" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["BinaryFormatter", "LosFormatter", "SoapFormatter"];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "AI-generated code uses dangerous BinaryFormatter. Can lead to RCE.".to_string(),
                    fix_hint: "Use System.Text.Json for serialization. Never deserialize untrusted data.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-AI-010: AI Path Traversal
// Severity: high | CWE-22
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpAiPathTraversal;

impl LangRule for CSharpAiPathTraversal {
    fn id(&self) -> &str { "CSHARP-AI-010" }
    fn name(&self) -> &str { "AI: Path Traversal Vulnerability" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let file_ops = ["File.ReadAllText", "File.Copy", "File.Delete", "Directory.GetFiles"];
        for call in &tree.calls {
            if file_ops.iter().any(|f| call.callee.contains(f)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("Request") || args_str.contains("query") || args_str.contains("id") {
                    let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "AI-generated file operation with user-controlled path.".to_string(),
                        fix_hint: "Validate and sanitize file paths. Use Path.GetFullPath() and reject '..'.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// CSHARP-029 — SSRF Deep Check (CWE-918)
// OWASP A10:2021 | High severity
// Detects HTTP requests with user-controlled URLs and internal IP access
// ---------------------------------------------------------------------------
pub struct CSharpSsrfDeep;

impl LangRule for CSharpSsrfDeep {
    fn id(&self) -> &str { "CSHARP-029" }
    fn name(&self) -> &str { "SSRF - Deep Check with Internal IP Detection" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let http_funcs = [
            "HttpClient.GetAsync",
            "HttpClient.PostAsync",
            "HttpClient.GetStringAsync",
            "HttpClient.GetByteArrayAsync",
            "HttpClient.PutAsync",
            "HttpClient.DeleteAsync",
            "HttpClient.SendAsync",
            "WebClient.DownloadString",
            "WebClient.DownloadData",
            "WebClient.OpenRead",
            "WebClient.UploadString",
            "HttpWebRequest.Create",
            "WebRequest.Create",
            "RestClient.Get",
            "RestClient.Post",
            "RestClient.Put",
            "RestClient.Delete",
            "HttpClientFactory.CreateClient",
            "IHttpClientFactory.CreateBuilder",
        ];

        let user_input_patterns = [
            "Request.Query",
            "Request.Params",
            "Request[\"",
            "Request.Form",
            "routeData.Values",
            "queryString",
            "Request.Url",
            "Request.Path",
            "Request.Headers",
            "Request.ServerVariables",
        ];

        let internal_ip_patterns = [
            "169.254.169.254",
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
            "::1",
            "metadata.google.internal",
            "metadata.azure.com",
        ];

        for call in &tree.calls {
            if http_funcs.iter().any(|f| call.callee.contains(f)) {
                let args_str = call.arguments.join(" ");
                let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();

                let has_user_input = user_input_patterns.iter().any(|p| args_str.contains(p));
                let has_internal_ip = internal_ip_patterns.iter().any(|ip| args_str.contains(ip) || line_text.contains(ip));

                if has_internal_ip {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: "high".to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "HTTP request to internal IP address detected. This could allow SSRF attacks to access cloud metadata services (169.254.169.254) or internal infrastructure.".to_string(),
                        fix_hint: "Block internal IP ranges. Validate URLs against an allowlist of permitted external domains. Never allow direct access to cloud metadata endpoints.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                } else if has_user_input {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: "high".to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "HTTP request with user-controlled URL detected. SSRF vulnerability.".to_string(),
                        fix_hint: "Validate and allowlist URLs. Block internal IP ranges (127.0.0.1, 169.254.169.254, etc.). Use Uri.TryCreate() to parse and validate the URL before making requests.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        // Also check for internal IPs in string literals with HTTP-related keywords
        let ip_re = Regex::new(r#"(?i)["']https?://[^"']*(?:169\.254\.169\.254|127\.0\.0\.1|localhost)["']"#).unwrap();
        for (i, line) in code.lines().enumerate() {
            if ip_re.is_match(line) && !findings.iter().any(|f: &LangFinding| f.line == i + 1) {
                let (start, end) = get_line_offsets(code, i + 1);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: "high".to_string(),
                    line: i + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.to_string(),
                    problem: "URL with internal IP or localhost detected in code. SSRF risk.".to_string(),
                    fix_hint: "Remove hardcoded internal URLs. Use external domain allowlists for any dynamic URL construction.".to_string(),
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

// ---------------------------------------------------------------------------
// CSHARP-030 — Weak JWT Verification (CWE-347)
// Critical severity
// Detects insecure JWT token validation patterns
// ---------------------------------------------------------------------------
pub struct CSharpWeakJwt;

impl LangRule for CSharpWeakJwt {
    fn id(&self) -> &str { "CSHARP-030" }
    fn name(&self) -> &str { "Weak JWT Token Verification" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check for JwtSecurityTokenHandler.ValidateToken with weak parameters
        let weak_validation_patterns = [
            (r"ValidateToken\s*\([^,]+,\s*null\s*,", "ValidateToken called with null validation parameters - no signature/issuer/audience validation"),
            (r"ValidateIssuer\s*=\s*false", "Issuer validation disabled in JWT"),
            (r"ValidateAudience\s*=\s*false", "Audience validation disabled in JWT"),
            (r"ValidateLifetime\s*=\s*false", "Token expiration validation disabled"),
            (r"ValidateIssuerSigningKey\s*=\s*false", "Signing key validation disabled - accepts any signature"),
            (r"RequireExpirationTime\s*=\s*false", "Expiration time not required"),
            (r"RequireSignedTokens\s*=\s*false", "Signed tokens not required"),
        ];

        for (i, line) in code.lines().enumerate() {
            // Check for JwtSecurityTokenHandler
            if line.contains("JwtSecurityTokenHandler") || line.contains("ValidateToken") {
                for (pat, problem) in &weak_validation_patterns {
                    if let Ok(re) = Regex::new(pat) {
                        if re.is_match(line) {
                            let (start, end) = get_line_offsets(code, i + 1);
                            findings.push(LangFinding {
                                rule_id: self.id().to_string(),
                                severity: "critical".to_string(),
                                line: i + 1,
                                column: 0,
                                start_byte: start,
                                end_byte: end,
                                snippet: line.to_string(),
                                problem: problem.to_string(),
                                fix_hint: "Enable all JWT validation: ValidateIssuer=true, ValidateAudience=true, ValidateLifetime=true, ValidateIssuerSigningKey=true. Use a proper key validation routine.".to_string(),
                                auto_fix_available: false,
                        replacement: String::new(),
                            });
                            break;
                        }
                    }
                }
            }

            // Check for weak/hardcoded signing keys
            if line.contains("SymmetricSecurityKey") || line.contains("SigningKey") {
                let weak_key_patterns = [
                    (r"new\s+byte\[0\]", "Empty byte array used as signing key"),
                    (r"new\s+byte\[\s*8\s*\]", "Only 8 bytes for symmetric key - too short"),
                    (r"new\s+byte\[\s*16\s*\]", "16 bytes may be insufficient for HS256"),
                    (r#""[^"]{0,32}""#, "Short hardcoded string used as key"),
                    (r"(?i)your-?secret|placeholder|changeme|temp|test", "Placeholder or test key detected"),
                ];

                for (pat, problem) in &weak_key_patterns {
                    if let Ok(re) = Regex::new(pat) {
                        if re.is_match(line) {
                            let (start, end) = get_line_offsets(code, i + 1);
                            findings.push(LangFinding {
                                rule_id: self.id().to_string(),
                                severity: "critical".to_string(),
                                line: i + 1,
                                column: 0,
                                start_byte: start,
                                end_byte: end,
                                snippet: line.to_string(),
                                problem: problem.to_string(),
                                fix_hint: "Use a cryptographically strong key of at least 256 bits (32 bytes) for HS256. Store keys securely in environment variables or a secrets manager. Never use placeholder or short keys.".to_string(),
                                auto_fix_available: false,
                        replacement: String::new(),
                            });
                            break;
                        }
                    }
                }
            }
        }

        // Check calls for JwtSecurityTokenHandler.ValidateToken
        for call in &tree.calls {
            if call.callee.contains("ValidateToken") {
                let args_str = call.arguments.join(" ");
                let line_text = code.lines().nth(call.start_line - 1).unwrap_or_default();

                // Very weak: null validation parameters
                if args_str.contains("null") {
                    let has_weak_params = code.lines()
                        .skip(call.start_line.saturating_sub(5))
                        .take(10)
                        .any(|l| l.contains("ValidateIssuer = false")
                            || l.contains("ValidateAudience = false")
                            || l.contains("ValidateLifetime = false")
                            || l.contains("ValidateIssuerSigningKey = false"));

                    if has_weak_params && !findings.iter().any(|f: &LangFinding| f.line == call.start_line) {
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: "critical".to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: 0,
                            end_byte: 0,
                            snippet: line_text.trim().to_string(),
                            problem: "JWT validation with disabled security checks detected. Tokens can be forged.".to_string(),
                            fix_hint: "Enable all validation parameters. Use Microsoft.IdentityModel.Tokens.TokenValidationParameters with proper issuer, audience, and lifetime validation.".to_string(),
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

    fn supports_auto_fix(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

pub fn csharp_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        // Existing
        Box::new(CSharpConsoleWrite),
        Box::new(CSharpTodoComments),
        // Security rules
        Box::new(CSharpSqlInjection),
        Box::new(CSharpInsecureDeserialization),
        Box::new(CSharpHardcodedSecrets),
        Box::new(CSharpCommandInjection),
        Box::new(CSharpWeakCryptography),
        Box::new(CSharpPathTraversal),
        Box::new(CSharpInsecureRandomness),
        Box::new(CSharpXssVulnerability),
        Box::new(CSharpBrokenAuth),
        Box::new(CSharpXxeVulnerability),
        Box::new(CSharpOpenRedirect),
        Box::new(CSharpLdapInjection),
        Box::new(CSharpSlopsquatting),
        Box::new(CSharpVerboseError),
        Box::new(CSharpMissingInputValidation),
        Box::new(CSharpAiGenComment),
        // New rules CSHARP-015 to CSHARP-019
        Box::new(CSharpMassAssignment),
        Box::new(CSharpIncorrectAuthorization),
        Box::new(CSharpInsecureCookie),
        Box::new(CSharpDeserializationGadget),
        Box::new(CSharpRegexDos),
        // New rules CSHARP-020 to CSHARP-028 and AI rules
        Box::new(CSharpXxe),
        Box::new(CSharpSqlInjectionEF),
        Box::new(CSharpPathTraversalRaw),
        Box::new(CSharpInsecureRandom),
        Box::new(CSharpHardcodedConnectionString),
        Box::new(CSharpWeakCrypto),
        Box::new(CSharpDeserializationRCE),
        Box::new(CSharpOpenRedirectRaw),
        Box::new(CSharpSsrf),
        Box::new(CSharpSsrfDeep),
        Box::new(CSharpWeakJwt),
        Box::new(CSharpAiHardcodedConnectionString),
        Box::new(CSharpAiSqlInjection),
        Box::new(CSharpAiCommandInjection),
        Box::new(CSharpAiXxe),
        Box::new(CSharpAiInsecureDeserialization),
        Box::new(CSharpAiPathTraversal),
    ]
}
