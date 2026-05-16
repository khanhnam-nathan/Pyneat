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

use crate::rules::base::{extract_snippet, Fix, Finding, Rule, Severity};
use once_cell::sync::Lazy;
use tree_sitter::Tree;

/// Returns true if `code` looks like Python source (has typical Python syntax markers).
/// This is used to prevent Python-specific auto-fixes from being applied to non-Python code.
fn looks_like_python(code: &str) -> bool {
    let code_lower = &code.to_lowercase()[..code.len().min(4096)];
    let python_indicators = [
        "def ", "import ", "from ", "class ", "self.", "elif ", "except ",
        " __init__", " __name__", "async def", "with open", "lambda ",
        "print(", "sys.path", "os.path", ".join(", "enumerate(",
    ];
    python_indicators.iter().any(|p| code_lower.contains(p))
}

/// SEC-001: Command Injection Detection
pub struct CommandInjectionRule;

impl Rule for CommandInjectionRule {
    fn id(&self) -> &str {
        "SEC-001"
    }

    fn name(&self) -> &str {
        "Command Injection"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Pattern 1: os.system with string concatenation or variable argument
        // Matches: os.system("cmd " + var), os.system(cmd + args), os.system(user_input)
        // Does NOT match: os.system("echo hello"), os.system("ls -la")
        if let Ok(re) = regex::Regex::new(r"os\.system\s*\(\s*([^)]+)\s*\)") {
            for m in re.captures_iter(code) {
                let full_match = m.get(0).unwrap();
                let arg = m.get(1).map(|g| g.as_str()).unwrap_or("");

                // Heuristic: only flag if argument contains string concatenation (+)
                // or is a bare identifier (variable reference) rather than a string literal
                let has_concat = arg.contains('+');
                let is_bare_var = !arg.starts_with('"') && !arg.starts_with('\'')
                    && !arg.starts_with("f\"") && !arg.starts_with("f'")
                    && !arg.is_empty();

                if has_concat || is_bare_var {
                    let snippet = extract_snippet(code, full_match.start(), full_match.end());
                    let auto_fix = full_match.as_str().contains("os.system");
                    findings.push(Finding {
                        rule_id: "SEC-001".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-78".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A03:2021".to_string()),
                        start: full_match.start(),
                        end: full_match.end(),
                        snippet,
                        problem: if is_bare_var && !has_concat {
                            "User-controlled argument passed to os.system(). This can allow command injection attacks.".to_string()
                        } else {
                            "User input is passed directly to a shell command through string concatenation. This can allow command injection attacks.".to_string()
                        },
                        fix_hint: "Use subprocess.run with shell=False and pass command as a list of arguments instead of a string.".to_string(),
                        auto_fix_available: auto_fix,
                        replacement: String::new(),
                    });
                }
            }
        }

        // Pattern 2: subprocess.run with shell=True
        if let Ok(re) = regex::Regex::new(r"subprocess\.run\s*\([^)]*shell\s*=\s*True") {
            for m in re.find_iter(code) {
                let snippet = extract_snippet(code, m.start(), m.end());
                findings.push(Finding {
                    rule_id: "SEC-001".to_string(),
                    severity: Severity::Critical.as_str().to_string(),
                    cwe_id: Some("CWE-78".to_string()),
                    cvss_score: Some(9.8),
                    owasp_id: Some("A03:2021".to_string()),
                    start: m.start(),
                    end: m.end(),
                    snippet,
                    problem: "subprocess.run with shell=True allows shell metacharacter injection. This can allow command injection attacks.".to_string(),
                    fix_hint: "Use subprocess.run with shell=False and pass command as a list of arguments.".to_string(),
                    auto_fix_available: false,
                            replacement: String::new(),
                });
            }
        }

        // Pattern 3: os.popen (always dangerous — no shell isolation)
        if let Ok(re) = regex::Regex::new(r"os\.popen\s*\(") {
            for m in re.find_iter(code) {
                let snippet = extract_snippet(code, m.start(), m.end());
                findings.push(Finding {
                    rule_id: "SEC-001".to_string(),
                    severity: Severity::Critical.as_str().to_string(),
                    cwe_id: Some("CWE-78".to_string()),
                    cvss_score: Some(9.8),
                    owasp_id: Some("A03:2021".to_string()),
                    start: m.start(),
                    end: m.end(),
                    snippet,
                    problem: "os.popen() executes a command via shell — equivalent to shell=True with no argument sanitization.".to_string(),
                    fix_hint: "Use subprocess.run([...], shell=False) or the subprocess module's higher-level functions.".to_string(),
                    auto_fix_available: true,
                            replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<Fix> {
        // Partial fix for os.system -> subprocess.run
        let original = &code[finding.start..finding.end];
        if original.contains("os.system") {
            Some(Fix {
                rule_id: self.id().to_string(),
                description: "Replace os.system() with subprocess.run()".to_string(),
                original: original.to_string(),
                replacement: "// TODO: Replace os.system() with subprocess.run([...], shell=False)".to_string(),
                start: finding.start,
                end: finding.end,
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool {
        true
    }
}

/// SEC-002: SQL Injection Detection
pub struct SqlInjectionRule;

impl Rule for SqlInjectionRule {
    fn id(&self) -> &str {
        "SEC-002"
    }

    fn name(&self) -> &str {
        "SQL Injection"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            // Pattern 1: concat INSIDE execute() — catches cursor.execute("SELECT * FROM " + table)
            (r#"(cursor|db|connection)\.execute\s*\([^)]*\+"#, "SQL query with string concatenation inside execute()"),
            // Pattern 2: query variable assigned with concat, then passed to execute()
            // Common Python pattern — no semicolons needed:
            //   query = "SELECT * FROM users WHERE username = '" + username + "'"
            //   cursor.execute(query)
            (r#"(?s)(query|sql|statement|cmd)\s*=\s*\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)[^\"]*\"[^\n]*\+\s*\w+.*?(?:execute|exec|query)\s*\("#, "SQL query variable built with concatenation then passed to execute()"),
            // Pattern 3: double-quoted SQL string ending with ' + ' — direct concat
            (r#"query\s*=\s*\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^\"]*\"[^\n]*\+\s*\w+"#, "SQL query string concatenated with variable — injection risk"),
            // Pattern 4: f-string with SQL keyword — f'SELECT * FROM {user_input}'
            (r#"f['\"].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)[^'\"]*\{[^}]+\}[^'\"]*['\"]"#, "SQL query with f-string interpolation — parameterizable"),
            // Pattern 5: .format() in SQL string
            (r#"['\"].*?(?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*\.\s*format\s*\([^)]+\)"#, "SQL query using .format() interpolation"),
        ];

        for (pattern, _) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-002".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-89".to_string()),
                        cvss_score: Some(9.9),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: "SQL query is constructed using string concatenation, which can allow SQL injection attacks.".to_string(),
                        fix_hint: "Use parameterized queries (placeholders) instead of string concatenation: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))".to_string(),
                        auto_fix_available: true,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<Fix> {
        let original = &code[finding.start..finding.end];
        let replacement = original
            .replace("cursor.execute(f\"", "cursor.execute(\"")
            .replace("execute(query %", "execute(query, ")
            .replace("execute(query % (", "execute(query, (")
            .replace("execute(query.format", "execute(query, params")
            .replace("cursor.execute(sql.format", "cursor.execute(sql, params");
        if replacement != original {
            Some(Fix {
                rule_id: self.id().to_string(),
                description: "Use parameterized queries instead of string formatting".to_string(),
                original: original.to_string(),
                replacement,
                start: finding.start,
                end: finding.end,
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool {
        true
    }
}

/// SEC-003: Eval/Exec Usage Detection
pub struct EvalExecRule;

impl Rule for EvalExecRule {
    fn id(&self) -> &str {
        "SEC-003"
    }

    fn name(&self) -> &str {
        "Eval/Exec Usage"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn supported_languages(&self) -> Option<&'static [&'static str]> {
        Some(&["python"])
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"\beval\s*\(", "eval()"),
            (r"\bexec\s*\(", "exec()"),
        ];

        for (pattern, _) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-003".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-95".to_string()),
                        cvss_score: Some(9.1),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: "Use of eval() or exec() can execute arbitrary code. User input in these functions can lead to remote code execution.".to_string(),
                        fix_hint: "Avoid eval() and exec(). Use ast.literal_eval() for safe evaluation of literals, or restructure code to avoid dynamic execution.".to_string(),
                        auto_fix_available: looks_like_python(code),
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<Fix> {
        let original = &code[finding.start..finding.end];
        if !original.contains("eval(") || original.contains("ast.literal_eval") {
            return None;
        }
        let replacement = original.replace("eval(", "ast.literal_eval(");
        Some(Fix {
            rule_id: self.id().to_string(),
            description: "Replace eval() with ast.literal_eval() for safe evaluation".to_string(),
            original: original.to_string(),
            replacement,
            start: finding.start,
            end: finding.end,
        })
    }

    fn supports_auto_fix(&self) -> bool {
        true
    }
}

/// SEC-004: Deserialization RCE Detection
pub struct DeserializationRceRule;

impl Rule for DeserializationRceRule {
    fn id(&self) -> &str {
        "SEC-004"
    }

    fn name(&self) -> &str {
        "Deserialization RCE"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"pickle\.(loads|load)\s*\(", "pickle.loads() or pickle.load()"),
            (r"yaml\.load\s*\(", "yaml.load() without Loader"),
            (r"marshal\.loads\s*\(", "marshal.loads()"),
            (r"shelve\.open", "shelve.open()"),
        ];

        for (pattern, _) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());

                    // Special case for yaml.load - can be auto-fixed
                    let auto_fix = m.as_str().contains("yaml.load")
                        && !code[m.start()..m.end()].contains("Loader=");

                    findings.push(Finding {
                        rule_id: "SEC-004".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-502".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: "Unsafe deserialization can lead to remote code execution (RCE). This is especially dangerous if data comes from untrusted sources.".to_string(),
                        fix_hint: if auto_fix {
                            "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader). For pickle: only unpickle data from trusted sources, consider json or msgpack as safer alternatives.".to_string()
                        } else {
                            "For pickle: only unpickle data from trusted sources, consider json or msgpack as safer alternatives.".to_string()
                        },
                        auto_fix_available: auto_fix,
                                replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<Fix> {
        let original = &code[finding.start..finding.end];
        if original.contains("yaml.load") && !original.contains("Loader=") {
            Some(Fix {
                rule_id: self.id().to_string(),
                description: "Replace yaml.load() with yaml.safe_load()".to_string(),
                original: original.to_string(),
                replacement: original.replace("yaml.load(", "yaml.safe_load("),
                start: finding.start,
                end: finding.end,
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool {
        true
    }
}

/// SEC-005: Path Traversal Detection
pub struct PathTraversalRule;

impl Rule for PathTraversalRule {
    fn id(&self) -> &str {
        "SEC-005"
    }

    fn name(&self) -> &str {
        "Path Traversal"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Pattern: open() with user-controlled path
        let open_pattern = r"open\s*\([^)]*(?:user|path|file|filename|filename|from|input)[^)]*\)";
        if let Ok(re) = regex::Regex::new(open_pattern) {
            for m in re.find_iter(code) {
                let snippet = extract_snippet(code, m.start(), m.end());
                findings.push(Finding {
                    rule_id: "SEC-005".to_string(),
                    severity: Severity::Critical.as_str().to_string(),
                    cwe_id: Some("CWE-22".to_string()),
                    cvss_score: Some(8.6),
                    owasp_id: Some("A01:2021".to_string()),
                    start: m.start(),
                    end: m.end(),
                    snippet,
                    problem: "File path constructed from user input without proper validation may allow path traversal attacks (e.g., ../../etc/passwd).".to_string(),
                    fix_hint: "Validate and sanitize user input. Use os.path.basename() to extract just the filename. Consider using pathlib.Path and strict validation.".to_string(),
                    auto_fix_available: false,
                            replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }
}

/// SEC-010: Hardcoded Secrets Detection
pub struct HardcodedSecretsRule;

impl Rule for HardcodedSecretsRule {
    fn id(&self) -> &str {
        "SEC-010"
    }

    fn name(&self) -> &str {
        "Hardcoded Secrets"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns: Vec<(&str, &str)> = vec![
            // ===== API Keys & Tokens =====
            (r#"api[_-]?key\s*[=:]\s*['"][a-zA-Z0-9]{20,}['"]"#, "API key assignment"),
            (r#"api[_-]?secret\s*[=:]\s*['"][^'"]+['"]"#, "API secret assignment"),
            (r#"access[_-]?key[_-]?id\s*[=:]\s*['"][^'"]+['"]"#, "Access key ID assignment"),
            (r#"secret[_-]?key\s*[=:]\s*['"][^'"]+['"]"#, "Secret key assignment"),
            (r#"(password|passwd|pwd)\s*[=:]\s*['"][^'"]+['"]"#, "Password assignment"),
            (r#"(token|auth[_-]?token|access[_-]?token)\s*[=:]\s*['"][a-zA-Z0-9_\-]{20,}['"]"#, "Token assignment"),

            // ===== Cloud Provider Keys =====
            (r#"sk-[a-zA-Z0-9]{20,}"#, "Stripe API key"),
            (r#"rk_[a-zA-Z0-9]{20,}"#, "Stripe Restricted API key"),
            (r#"ghp_[a-zA-Z0-9]{36,}"#, "GitHub Personal Access Token"),
            (r#"gho_[a-zA-Z0-9]{36,}"#, "GitHub OAuth Token"),
            (r#"ghu_[a-zA-Z0-9]{36,}"#, "GitHub User Access Token"),
            (r#"xox[baprs]-[a-zA-Z0-9]{10,}"#, "Slack Token"),
            (r#"xox[baprs]-[a-zA-Z0-9_-]{10,}"#, "Slack Token (extended)"),
            (r#"AIza[0-9A-Za-z_-]{35}"#, "Google API Key"),
            (r#"ya29\.[0-9A-Za-z_-]+"#, "Google OAuth Access Token"),
            (r#"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"#, "Google OAuth Client ID"),
            (r#"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#, "Amazon MWS Auth Token"),
            (r#"AKIA[0-9A-Z]{16}"#, "AWS Access Key ID"),
            (r#"['"][0-9a-f]{40}['"]"#, "AWS Secret Access Key (hex)"),

            // ===== Azure Keys =====
            (r#"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"#, "Azure Storage Connection String"),
            (r#"[a-zA-Z0-9+/]{86}==['"]"#, "Azure Shared Key"),

            // ===== Database Connection Strings =====
            (r#"mongodb\+srv://[^:'"]+:[^:'"]+@"#, "MongoDB Connection String with credentials"),
            (r#"mysql://[^:'"]+:[^:'"]+@[^/'"]+"#, "MySQL Connection String"),
            (r#"postgresql://[^:'"]+:[^:'"]+@[^/'"]+"#, "PostgreSQL Connection String"),
            (r#"redis://[^:'"]+:[^:'"]+@"#, "Redis Connection String with credentials"),
            (r#"sqlserver://[^:'"]+:[^:'"]+@"#, "SQL Server Connection String"),
            (r#"mongodb://[^:'"]+:[^:'"]+@"#, "MongoDB Connection String"),

            // ===== JWT & OAuth =====
            (r#"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"#, "JWT Token"),
            (r#"Bearer\s+[a-zA-Z0-9_\-\.]+"#, "Bearer Token"),

            // ===== SSH & Private Keys =====
            (r#"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"#, "Private Key (PEM)"),
            (r#"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----"#, "OpenSSH Private Key"),
            (r#"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----"#, "EC Private Key"),
            (r#"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----"#, "DSA Private Key"),
            (r#"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----"#, "PGP Private Key"),

            // ===== Encryption Keys =====
            (r#"encryption[_-]?key\s*[=:]\s*['"][^'"]+['"]"#, "Encryption key assignment"),
            (r#"crypt[_-]?key\s*[=:]\s*['"][^'"]+['"]"#, "Crypt key assignment"),
            (r#"secret[_-]?key\s*[=:]\s*['"][^'"]+['"]"#, "Secret key assignment"),

            // ===== Payment & Finance =====
            (r#"sq0csp-[a-zA-Z0-9_-]{43}"#, "Square OAuth Secret"),
            (r#"sq0atp-[a-zA-Z0-9_-]{22}"#, "Square Access Token"),
            (r#"(paypal|braintree)[_-]?(api[_-]?key|secret|token)\s*[=:]\s*['"][^'"]+['"]"#, "Payment API key"),

            // ===== Social Media & Third-party =====
            (r#"twilio[_-]?(account[_-]?sid|auth[_-]?token)\s*[=:]\s*['"][^'"]+['"]"#, "Twilio credentials"),
            (r#"sendgrid[_-]?api[_-]?key\s*[=:]\s*['"][^'"]+['"]"#, "SendGrid API Key"),
            (r#"mailgun[_-]?api[_-]?key\s*[=:]\s*['"][^'"]+['"]"#, "Mailgun API Key"),
            (r#"[0-9a-f]{32}-[0-9a-f]{16}"#, "Generic Secret Pattern (32 hex + 16 hex)"),

            // ===== Environment-like secrets =====
            (r#"SECRET[_-]?(KEY|TOKEN|PASSWORD)\s*[=:]\s*['"][^'")\s]{8,}['"]"#, "Environment secret variable"),
            (r#"PRIVATE[_-]?TOKEN\s*[=:]\s*['"][^'"]+['"]"#, "Private token"),
            (r#"HEROKU_API_KEY\s*[=:]\s*['"][a-zA-Z0-9_-]{20,}['"]"#, "Heroku API Key"),
            (r#"STRIPE[_-]?(LIVE|TEST)[_-]?(SECRET|KEY)\s*[=:]\s*['"][^'"]+['"]"#, "Stripe secret key"),

            // ===== Docker & Container =====
            (r#"(docker[_-]?hub)?[_-]?registry[_-]?password\s*[=:]\s*['"][^'"]+['"]"#, "Container registry password"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-010".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-798".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: format!("Potential hardcoded secret detected: {}", desc),
                        fix_hint: "Store secrets in environment variables or a secure secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Use os.environ.get('SECRET_NAME') or a secrets library.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<Fix> {
        let original = &code[finding.start..finding.end];
        let replacement = original
            .trim_end_matches('"')
            .trim_end_matches('\'')
            .trim_end_matches(' ')
            .trim_end_matches('\t');
        if replacement.contains('=') {
            let parts: Vec<&str> = replacement.splitn(2, '=').collect();
            if parts.len() == 2 {
                let var_name = parts[0].trim().to_string();
                let hint = format!("{} = os.environ.get('{}') or ''  # TODO: set via env var", var_name, var_name.to_uppercase());
                return Some(Fix {
                    rule_id: self.id().to_string(),
                    description: "Replace hardcoded secret with environment variable".to_string(),
                    original: original.to_string(),
                    replacement: hint,
                    start: finding.start,
                    end: finding.end,
                });
            }
        }
        None
    }

    fn supports_auto_fix(&self) -> bool { true }
}

/// SEC-011: Weak Cryptography Detection
pub struct WeakCryptoRule;

impl Rule for WeakCryptoRule {
    fn id(&self) -> &str {
        "SEC-011"
    }

    fn name(&self) -> &str {
        "Weak Cryptography"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn supported_languages(&self) -> Option<&'static [&'static str]> {
        Some(&["python"])
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"hashlib\.(md5|sha1)\s*\(", "Weak hash function (MD5/SHA1)"),
            (r"crypto\.Cipher\(", "Weak crypto cipher usage"),
            (r"SSLContext\s*\(\s*SSL\s*\.", "Insecure SSL/TLS version"),
            (r"random\.(random|randint|choice)\s*\(", "Random module for security"),
            (r"secrets\.SystemRandom\(\)", "Proper secure random"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-011".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-327".to_string()),
                        cvss_score: Some(7.4),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: format!("Weak cryptography detected: {}", desc),
                        fix_hint: "Use cryptographic hash functions like SHA-256 or SHA-3. For SSL/TLS, use TLS 1.2 or higher. For random numbers in security contexts, use the secrets module.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }
}

/// SEC-012: Insecure SSL/TLS Usage
pub struct InsecureSslRule;

impl Rule for InsecureSslRule {
    fn id(&self) -> &str {
        "SEC-012"
    }

    fn name(&self) -> &str {
        "Insecure SSL/TLS"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"ssl\.PROTOCOL_\w+\s*=\s*SSLv2", "SSLv2 protocol"),
            (r"ssl\.PROTOCOL_\w+\s*=\s*SSLv3", "SSLv3 protocol"),
            (r"ssl\.PROTOCOL_\w+\s*=\s*TLSv1", "TLSv1.0 protocol"),
            (r"ssl\.PROTOCOL_\w+\s*=\s*TLSv1_1", "TLSv1.1 protocol"),
            (r"check_hostname\s*=\s*False", "Hostname check disabled"),
            (r"verify\s*=\s*False", "SSL verification disabled"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-012".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-295".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: format!("Insecure SSL/TLS configuration: {}", desc),
                        fix_hint: "Use TLS 1.2 or higher. Enable certificate verification. Enable hostname checking.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }
}

/// SEC-013: XXE (XML External Entity) Detection
pub struct XxeRule;

impl Rule for XxeRule {
    fn id(&self) -> &str {
        "SEC-013"
    }

    fn name(&self) -> &str {
        "XML External Entity (XXE)"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"xml\.etree\.ElementTree\.parse\([^)]*dtd\s*=", "DTD parsing enabled"),
            (r"lxml\.etree\.parse\([^)]*no_network\s*=\s*False", "lxml network access enabled"),
            (r"from\s+defusedxml\s+import", "Using defusedxml (good practice)"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    let is_safe = m.as_str().contains("defusedxml");

                    if !is_safe {
                        findings.push(Finding {
                            rule_id: "SEC-013".to_string(),
                            severity: Severity::High.as_str().to_string(),
                            cwe_id: Some("CWE-611".to_string()),
                            cvss_score: Some(8.0),
                            owasp_id: Some("A05:2021".to_string()),
                            start: m.start(),
                            end: m.end(),
                            snippet,
                            problem: format!("Potential XXE vulnerability: {}", desc),
                            fix_hint: "Use defusedxml library for parsing untrusted XML. Disable DTD and external entities.".to_string(),
                            auto_fix_available: false,
                                    replacement: String::new(),
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }
}

/// SEC-014: YAML Unsafe Load (Auto-fix available)
pub struct YamlUnsafeRule;

impl Rule for YamlUnsafeRule {
    fn id(&self) -> &str {
        "SEC-014"
    }

    fn name(&self) -> &str {
        "YAML Unsafe Load"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // yaml.load without Loader parameter
        let yaml_pattern = r"yaml\.load\s*\(\s*([^,\)]+)";
        if let Ok(re) = regex::Regex::new(yaml_pattern) {
            for m in re.find_iter(code) {
                let snippet = extract_snippet(code, m.start(), m.end());

                // Check if there's a Loader parameter
                let full_context = &code[m.start()..std::cmp::min(m.end() + 100, code.len())];
                let has_loader = full_context.contains("Loader=");

                if !has_loader {
                    findings.push(Finding {
                        rule_id: "SEC-014".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-502".to_string()),
                        cvss_score: Some(8.1),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: "YAML load without safe Loader can lead to arbitrary code execution.".to_string(),
                        fix_hint: "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).".to_string(),
                        auto_fix_available: true,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<Fix> {
        let original = &code[finding.start..finding.end];
        if original.contains("yaml.load") && !original.contains("Loader=") {
            Some(Fix {
                rule_id: self.id().to_string(),
                description: "Replace yaml.load() with yaml.safe_load()".to_string(),
                original: original.to_string(),
                replacement: original.replace("yaml.load(", "yaml.safe_load("),
                start: finding.start,
                end: finding.end,
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool {
        true
    }
}

/// SEC-015: Assert in Production
pub struct AssertInProductionRule;

impl Rule for AssertInProductionRule {
    fn id(&self) -> &str {
        "SEC-015"
    }

    fn name(&self) -> &str {
        "Assert in Production"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Match assert statements that check permissions or security
        let patterns = [
            (r"assert\s+.*(admin|permission|authorized|authenticated|role)", "Assert for authorization"),
            (r"assert\s+.*(is_admin|is_authenticated|has_permission)", "Assert for security checks"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-015".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-585".to_string()),
                        cvss_score: Some(6.5),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: format!("Assert statement used for security: {}", desc),
                        fix_hint: "Assertions can be disabled with -O flag. Use proper if/raise statements for security checks.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }
}

/// SEC-016: Debug Mode Enabled
pub struct DebugModeRule;

impl Rule for DebugModeRule {
    fn id(&self) -> &str {
        "SEC-016"
    }

    fn name(&self) -> &str {
        "Debug Mode Enabled"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"DEBUG\s*=\s*True"#, "DEBUG=True in code"),
            (r#"debug\s*=\s*True"#, "debug=True in code"),
            (r#"app\.run\s*\([^)]*debug\s*=\s*True", "Flask debug mode"),
            (r#"debug\s*=\s*True\s*#\s*.*(?:production|live)"#, "Debug in production comment"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-016".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-11".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: format!("Debug mode enabled: {}", desc),
                        fix_hint: "Disable debug mode in production. Set DEBUG=False and use environment variables for configuration.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }
}

/// SEC-017: CORS Wildcard
pub struct CorsWildcardRule;

impl Rule for CorsWildcardRule {
    fn id(&self) -> &str {
        "SEC-017"
    }

    fn name(&self) -> &str {
        "CORS Wildcard"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"'Access-Control-Allow-Origin'\s*:\s*'\*'"#, "CORS allow all origin"),
            (r#"Access-Control-Allow-Origin\s*=\s*"\*""#, "CORS allow all origin"),
            (r#"'Access-Control-Allow-Credentials'\s*:\s*'true'"#, "CORS with credentials and wildcard"),
            (r"allow_credentials\s*=\s*True.*CORS\([^)]*origins\s*=\s*\[", "CORS with credentials and multiple origins"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-017".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-942".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: format!("CORS misconfiguration: {}", desc),
                        fix_hint: "Don't use wildcard (*) for Access-Control-Allow-Origin with credentials. Specify exact origins instead.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }
}

/// SEC-018: JWT None Algorithm
pub struct JwtNoneRule;

impl Rule for JwtNoneRule {
    fn id(&self) -> &str {
        "SEC-018"
    }

    fn name(&self) -> &str {
        "JWT None Algorithm"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"algorithm\s*=\s*['"]none['"]"#, "JWT algorithm set to 'none'"),
            (r#"jwt\.decode\([^)]*algorithms\s*=\s*\[['\"]*none['\"]*\]"#, "JWT decode with 'none' algorithm"),
            (r#"\.(header|decode|encode)\s*\([^)]*verify\s*=\s*False"#, "JWT verification disabled"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-018".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-347".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: format!("JWT security issue: {}", desc),
                        fix_hint: "Use RS256 or ES256 algorithm. Always verify signatures. Don't use algorithm 'none'.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }
}

/// SEC-019: Weak Random for Security
pub struct WeakRandomRule;

impl Rule for WeakRandomRule {
    fn id(&self) -> &str {
        "SEC-019"
    }

    fn name(&self) -> &str {
        "Weak Random (Security Context)"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"import\s+random\s*;?\s*random\.(random|randint|randrange|choice)", "Using random module for security"),
            (r"from\s+random\s+import.*random", "Importing random for security purposes"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-019".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-338".to_string()),
                        cvss_score: Some(7.4),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: format!("Using weak random for security: {}", desc),
                        fix_hint: "Use the secrets module for security-sensitive operations: secrets.choice(), secrets.randbelow(), etc.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }
}

// ============================================================================
// MEDIUM SEVERITY RULES (SEC-020 ~ SEC-034)
// ============================================================================

/// SEC-020: LDAP Injection
pub struct LdapInjectionRule;

impl Rule for LdapInjectionRule {
    fn id(&self) -> &str { "SEC-020" }
    fn name(&self) -> &str { "LDAP Injection" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(ldap|ldap3)\.(search|search_s)\s*\([^)]*\+[^)]*\)"#, "LDAP query with string concatenation"),
            (r#"ldap\.initialize\([^)]*)\+[^)]*\)"#, "LDAP connection with string concatenation"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-020".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-90".to_string()),
                        cvss_score: Some(6.1),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Potential LDAP injection: {}", desc),
                        fix_hint: "Use parameterized LDAP queries. Escape special characters in user input before using in LDAP filters.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-021: Cross-Site Scripting (XSS)
pub struct XssRule;

impl Rule for XssRule {
    fn id(&self) -> &str { "SEC-021" }
    fn name(&self) -> &str { "Cross-Site Scripting (XSS)" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(markup|mark_safe)\s*\("#, "Django mark_safe usage"),
            (r#"\.innerHTML\s*="#, "innerHTML assignment"),
            (r#"dangerouslySetInnerHTML\s*="#, "React dangerouslySetInnerHTML"),
            (r#"render_template_string\s*\("#, "Flask render_template_string"),
            (r#"Response\s*\(\s*request\.args\."#, "Flask response with user input"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-021".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-79".to_string()),
                        cvss_score: Some(6.1),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Potential XSS vulnerability: {}", desc),
                        fix_hint: "Sanitize and escape user input before rendering. Use templating engines with auto-escaping.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-022: Server-Side Request Forgery (SSRF)
pub struct SsrfRule;

impl Rule for SsrfRule {
    fn id(&self) -> &str { "SEC-022" }
    fn name(&self) -> &str { "Server-Side Request Forgery (SSRF)" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(requests\.(get|post|put|delete)|urllib\.request)\s*\([^)]*(?:url|urlopen)\s*="#, "HTTP request with URL variable"),
            (r#"requests\.[a-z]+\s*\([^)]*%s"#, "String formatting in URL"),
            (r#"fetch\s*\([^)]*template\s*="#, "Fetch with template variable"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-022".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-918".to_string()),
                        cvss_score: Some(6.5),
                        owasp_id: Some("A10:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Potential SSRF vulnerability: {}", desc),
                        fix_hint: "Validate and whitelist URLs. Don't use user input directly in URLs. Use URL parsing libraries to extract and validate components.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-023: Open Redirect
pub struct OpenRedirectRule;

impl Rule for OpenRedirectRule {
    fn id(&self) -> &str { "SEC-023" }
    fn name(&self) -> &str { "Open Redirect" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            // Only flag redirect with actual user input sources (request.*, args.get, form.get, etc.)
            (r#"redirect\s*\([^)]*(?:request\.(?:args|form|values|json|data)|\$\{|args\.get|form\.get)"#, "Redirect with user-controlled input"),
            // Header-based redirect with user input
            (r#"Location\s*:\s*.*request\."#, "HTTP Location header with user input"),
            // File path with user input
            (r#"send_file\s*\([^)]*request\."#, "send_file with user-controlled path"),
            // url_for is safe — does NOT take user input directly
            // (.url_for usage is safe, we removed the overly-broad pattern)
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-023".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-601".to_string()),
                        cvss_score: Some(6.1),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Potential open redirect: {}", desc),
                        fix_hint: "Validate and whitelist redirect URLs. Never use user input directly for redirects.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-026: Insecure Temporary File
pub struct InsecureTempFileRule;

impl Rule for InsecureTempFileRule {
    fn id(&self) -> &str { "SEC-026" }
    fn name(&self) -> &str { "Insecure Temporary File" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"tempfile\.mktemp\s*\("#, "tempfile.mktemp (insecure)"),
            (r#"os\.mkstemp\s*\(\s*\)"#, "mkstemp without proper cleanup"),
            (r#"open\s*\(\s*\(.*temp.*\)"#, "Direct temp file creation"),
            (r#"NamedTemporaryFile\s*\([^)]*delete\s*=\s*False"#, "TempFile with delete=False"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-026".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-377".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Insecure temporary file usage: {}", desc),
                        fix_hint: "Use tempfile.TemporaryDirectory or NamedTemporaryFile with delete=True. Ensure proper cleanup.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-027: JWT Verification Disabled (duplicate check)
pub struct JwtVerificationDisabledRule;

impl Rule for JwtVerificationDisabledRule {
    fn id(&self) -> &str { "SEC-027" }
    fn name(&self) -> &str { "JWT Verification Disabled" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"jwt\.decode\s*\([^)]*verify\s*=\s*False"#, "JWT decode with verify=False"),
            (r#"jwt\.encode\s*\([^)]*algorithm\s*=\s*['\"]none['\"]"#, "JWT encode with algorithm='none'"),
            (r#"PyJWT\(\)\.decode\s*\([^)]*options\s*=\s*{[^}]*'verify_signature'\s*:\s*False"#, "PyJWT with verify_signature disabled"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-027".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-347".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("JWT verification disabled: {}", desc),
                        fix_hint: "Always verify JWT signatures. Use secure algorithms like RS256. Validate all claims.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-028: Cookie Missing HttpOnly
pub struct CookieHttpOnlyRule;

impl Rule for CookieHttpOnlyRule {
    fn id(&self) -> &str { "SEC-028" }
    fn name(&self) -> &str { "Cookie Missing HttpOnly" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"set_cookie\s*\([^)]*httponly\s*=\s*False"#, "Cookie with httponly=False"),
            (r#"response\.set_cookie\s*\([^)]*(?!.*httponly)"#, "set_cookie without httponly"),
            (r#"Cookie\s*\(.*httponly\s*=\s*False"#, "Cookie without HttpOnly"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-028".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-1004".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Cookie missing HttpOnly flag: {}", desc),
                        fix_hint: "Set HttpOnly=True for session cookies and sensitive data cookies to prevent XSS access.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-029: Cookie Missing Secure Flag
pub struct CookieSecureFlagRule;

impl Rule for CookieSecureFlagRule {
    fn id(&self) -> &str { "SEC-029" }
    fn name(&self) -> &str { "Cookie Missing Secure Flag" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"set_cookie\s*\([^)]*secure\s*=\s*False"#, "Cookie with secure=False"),
            (r#"response\.set_cookie\s*\([^)]*(?!.*secure)"#, "set_cookie without secure flag"),
            (r#"cookie\s*=.*httponly\s*=.*secure\s*=\s*False"#, "Cookie with secure=False"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-029".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-614".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Cookie missing Secure flag: {}", desc),
                        fix_hint: "Set Secure=True for all cookies in production to ensure they're only sent over HTTPS.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-030: Missing Security Header
pub struct MissingSecurityHeaderRule;

impl Rule for MissingSecurityHeaderRule {
    fn id(&self) -> &str { "SEC-030" }
    fn name(&self) -> &str { "Missing Security Header" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"@app\.after_request\s*def\s+add_headers[^:]*:"#, "after_request decorator found"),
            (r#"response\.headers\[.*Security"#, "Security header setting"),
            (r#"middleware.*security"#, "Security middleware"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-030".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-693".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Missing security headers: {}", desc),
                        fix_hint: "Add security headers: X-Content-Type-Options, X-Frame-Options, CSP, Strict-Transport-Security.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-031: TRACE Method Enabled
pub struct TraceMethodRule;

impl Rule for TraceMethodRule {
    fn id(&self) -> &str { "SEC-031" }
    fn name(&self) -> &str { "TRACE Method Enabled" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"app\.route\s*\([^)]*methods\s*=\s*\[[^]]*'TRACE'"#, "TRACE method enabled"),
            (r#"allow\s*=\s*\[.*'TRACE'"#, "Allow TRACE in CORS"),
            (r#"ALLOWED_METHODS.*TRACE"#, "TRACE in allowed methods"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-031".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-15".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("TRACE method enabled: {}", desc),
                        fix_hint: "Disable TRACE method. It can be used in Cross-Site Tracing (XST) attacks.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-032: X-Content-Type-Options Missing
pub struct XContentTypeOptionsRule;

impl Rule for XContentTypeOptionsRule {
    fn id(&self) -> &str { "SEC-032" }
    fn name(&self) -> &str { "X-Content-Type-Options Missing" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"X-Content-Type-Options\s*:"#, "Header found"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-032".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-693".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("X-Content-Type-Options header: {}", desc),
                        fix_hint: "Add 'X-Content-Type-Options: nosniff' header to prevent MIME sniffing.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-033: X-Frame-Options Missing
pub struct XFrameOptionsRule;

impl Rule for XFrameOptionsRule {
    fn id(&self) -> &str { "SEC-033" }
    fn name(&self) -> &str { "X-Frame-Options Missing" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"X-Frame-Options\s*:"#, "Header found"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-033".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-1021".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("X-Frame-Options header: {}", desc),
                        fix_hint: "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header to prevent clickjacking.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-034: Content-Security-Policy Missing
pub struct CspMissingRule;

impl Rule for CspMissingRule {
    fn id(&self) -> &str { "SEC-034" }
    fn name(&self) -> &str { "Content-Security-Policy Missing" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"Content-Security-Policy\s*:"#, "CSP header found"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-034".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-693".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Content-Security-Policy header: {}", desc),
                        fix_hint: "Add a strict CSP header to prevent XSS and data injection attacks.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// ============================================================================
// LOW SEVERITY RULES (SEC-040 ~ SEC-049)
// ============================================================================

/// SEC-040: Sensitive Information in Comments (LOW)
pub struct SensitiveCommentRule;

impl Rule for SensitiveCommentRule {
    fn id(&self) -> &str { "SEC-040" }
    fn name(&self) -> &str { "Sensitive Information in Comments" }
    fn severity(&self) -> Severity { Severity::Low }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(?i)#.*(?:password|passwd|pwd)\s*=\s*['"][^'"]+['"]"#, "Hardcoded password in comment"),
            (r#"(?i)#.*(?:api[_-]?key|secret[_-]?key)\s*=\s*['"][^'"]+['"]"#, "API key in comment"),
            (r#"(?i)#.*token\s*=\s*['"][a-zA-Z0-9_-]{20,}['"]"#, "Token in comment"),
            (r#"(?i)#.*(?:private[_-]?key)\s*=\s*['\"][^'\"]+['\"]"#, "Private key in comment"),
            (r#"(?i)#.*TODO.*(?:password|api[_-]?key|token|secret)"#, "TODO containing sensitive data"),
            (r#"(?i)#.*FIXME.*(?:password|api[_-]?key|token|secret)"#, "FIXME containing sensitive data"),
            (r#"(?i)#.*HACK.*(?:password|api[_-]?key|token|secret)"#, "HACK containing sensitive data"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-040".to_string(),
                        severity: Severity::Low.as_str().to_string(),
                        cwe_id: Some("CWE-312".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Sensitive data in comment: {}", desc),
                        fix_hint: "Remove sensitive data from comments. Store credentials in environment variables.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-041: Information Disclosure in Errors (LOW)
pub struct InfoDisclosureRule;

impl Rule for InfoDisclosureRule {
    fn id(&self) -> &str { "SEC-041" }
    fn name(&self) -> &str { "Information Disclosure in Errors" }
    fn severity(&self) -> Severity { Severity::Low }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"traceback\.print_exc\s*\("#, "Exposing stack trace to user"),
            (r#"traceback\.format_exc\s*\("#, "Formatting stack trace"),
            (r#"__debug__"#, "Debug flag present"),
            (r"raise\s+\w+\s*\(\s*\w+\s*\)", "Re-raising exception without wrapping"),
            (r"except\s*:\s*\n\s*pass", "Bare except with pass"),
            (r#"werkzeug\.debug\.DebuggedApplication"#, "Werkzeug debug mode"),
            (r#"app\.run\s*\([^)]*debug\s*=\s*True", "Flask debug mode enabled"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-041".to_string(),
                        severity: Severity::Low.as_str().to_string(),
                        cwe_id: Some("CWE-209".to_string()),
                        cvss_score: Some(4.3),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Information disclosure: {}", desc),
                        fix_hint: "Use structured error responses instead of exposing stack traces. Log errors server-side.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-044: EXIF Data in Uploads (LOW)
pub struct ExifDataRule;

impl Rule for ExifDataRule {
    fn id(&self) -> &str { "SEC-044" }
    fn name(&self) -> &str { "EXIF Data in Uploads" }
    fn severity(&self) -> Severity { Severity::Low }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(?i)Image\.open\s*\([^)]*\)\s*[^.]*\.save\s*\("#, "Image save without EXIF stripping"),
            (r#"PIL\.Image\.open\s*\([^)]*\)\s*[^.]*\.save\s*\("#, "PIL image save without EXIF stripping"),
            (r#"(?i)\.getexif\s*\(\s*\)"#, "Getting EXIF data"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-044".to_string(),
                        severity: Severity::Low.as_str().to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        cvss_score: Some(4.6),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("EXIF data handling: {}", desc),
                        fix_hint: "Strip EXIF metadata from uploaded images using PIL or similar library before saving.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-045: Missing Referrer Policy (LOW)
pub struct MissingReferrerPolicyRule;

impl Rule for MissingReferrerPolicyRule {
    fn id(&self) -> &str { "SEC-045" }
    fn name(&self) -> &str { "Missing Referrer-Policy Header" }
    fn severity(&self) -> Severity { Severity::Low }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"Referrer-Policy"#, "Referrer-Policy header found"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-045".to_string(),
                        severity: Severity::Low.as_str().to_string(),
                        cwe_id: Some("CWE-693".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Referrer-Policy: {}", desc),
                        fix_hint: "Add 'Referrer-Policy: strict-origin-when-cross-origin' header to HTTP responses.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-046: Security Feature Disabled (MEDIUM)
pub struct SecurityDisabledRule;

impl Rule for SecurityDisabledRule {
    fn id(&self) -> &str { "SEC-046" }
    fn name(&self) -> &str { "Security Feature Disabled" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"verify\s*=\s*False"#, "SSL verification disabled"),
            (r#"check_hostname\s*=\s*False"#, "Hostname check disabled"),
            (r#"ssl\._create_unverified_context\s*\("#, "Unverified SSL context"),
            (r#"requests\.[a-z]+\s*\([^)]*verify\s*=\s*False"#, "requests with verify=False"),
            (r#"urllib3\.util\.ssl_\?create_default_context\s*\(\s*\)\s*\.\s*verify\s*=\s*False"#, "urllib3 SSL verify disabled"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-046".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-295".to_string()),
                        cvss_score: Some(6.5),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Security feature disabled: {}", desc),
                        fix_hint: "Enable SSL verification. Use verify=True or provide the correct CA bundle path.".to_string(),
                        auto_fix_available: true,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<Fix> {
        let original = &code[finding.start..finding.end];
        if original.contains("verify=False") {
            Some(Fix {
                rule_id: self.id().to_string(),
                description: "Enable SSL verification".to_string(),
                original: original.to_string(),
                replacement: original.replace("verify=False", "verify=True"),
                start: finding.start,
                end: finding.end,
            })
        } else if original.contains("check_hostname=False") {
            Some(Fix {
                rule_id: self.id().to_string(),
                description: "Enable hostname checking".to_string(),
                original: original.to_string(),
                replacement: original.replace("check_hostname=False", "check_hostname=True"),
                start: finding.start,
                end: finding.end,
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool { true }
}

/// SEC-047: Insufficient Anti-Automation (LOW)
pub struct AntiAutomationRule;

impl Rule for AntiAutomationRule {
    fn id(&self) -> &str { "SEC-047" }
    fn name(&self) -> &str { "Insufficient Anti-Automation" }
    fn severity(&self) -> Severity { Severity::Low }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"@app\.route\s*\([^)]*\)\s*\ndef\s+(login|signin|register)"#, "Login route without anti-automation"),
            (r#"@app\.route\s*\([^)]*\)\s*\ndef\s+(submit|contact|feedback)"#, "Form submission without anti-automation"),
            (r#"@app\.route\s*\([^)]*\)\s*\ndef\s+(password_reset|forgot)"#, "Password reset without anti-automation"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-047".to_string(),
                        severity: Severity::Low.as_str().to_string(),
                        cwe_id: Some("CWE-799".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Insufficient anti-automation: {}", desc),
                        fix_hint: "Add CAPTCHA, rate limiting, or other anti-automation controls to sensitive endpoints.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-048: Privacy Violation - PII in Logs (LOW)
pub struct PiiLogRule;

impl Rule for PiiLogRule {
    fn id(&self) -> &str { "SEC-048" }
    fn name(&self) -> &str { "Privacy Violation - PII in Logs" }
    fn severity(&self) -> Severity { Severity::Low }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(?i)(logging|logger|print)\s*\([^)]*(?:email|phone|ssn|social[_-]?security|credit[_-]?card|card[_-]?number)\s*[^\)]*\)"#, "Logging PII"),
            (r#"\b\d{3}-\d{2}-\d{4}\b"#, "SSN pattern in code"),
            (r#"\b(?:\d{4}[-\s]?){3}\d{4}\b"#, "Credit card number pattern"),
            (r#"(?i)(?:email|phone|address).*=\s*f?['\"][^'\"]*\{[^}]+\}[^'\"]*['\"]"#, "PII in f-string"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-048".to_string(),
                        severity: Severity::Low.as_str().to_string(),
                        cwe_id: Some("CWE-359".to_string()),
                        cvss_score: Some(4.6),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("PII in logs: {}", desc),
                        fix_hint: "Mask or hash PII before logging. Use placeholder identifiers instead.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-049: Weak Password Policy (LOW)
pub struct WeakPasswordRule;

impl Rule for WeakPasswordRule {
    fn id(&self) -> &str { "SEC-049" }
    fn name(&self) -> &str { "Weak Password Policy" }
    fn severity(&self) -> Severity { Severity::Low }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"re\.match\s*\(\s*r['\"]\^?\.{1,4}\$?", "Password validation too permissive (1-4 chars)"),
            (r#"if\s+len\s*\([^)]*\)\s*[<>]=?\s*[3-4]"#, "Length check only (too short)"),
            (r#"not\s+re\.search.*(?:upper|digit|special).*password"#, "Missing complexity check"),
            (r#"(?i)validate.*(?:password|pwd).*(?:min|max).*=\s*[3-4]"#, "Weak minimum length requirement"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-049".to_string(),
                        severity: Severity::Low.as_str().to_string(),
                        cwe_id: Some("CWE-521".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A07:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Weak password policy: {}", desc),
                        fix_hint: "Enforce minimum 8 characters with mixed case, numbers, and special characters.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// ============================================================================
// INFO SEVERITY RULES (SEC-050 ~ SEC-059)
// ============================================================================

/// SEC-050: Deprecated Security Function (INFO)
pub struct DeprecatedFunctionRule;

impl Rule for DeprecatedFunctionRule {
    fn id(&self) -> &str { "SEC-050" }
    fn name(&self) -> &str { "Deprecated Security Function" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"ssl\.wrap_socket\s*\("#, "Deprecated ssl.wrap_socket()"),
            (r#"xml\.dom\.minidom\.parse"#, "xml.dom.minidom (XXE risk)"),
            (r#"Crypto\.Cipher"#, "PyCrypto (deprecated, use cryptography)"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-050".to_string(),
                        severity: Severity::Info.as_str().to_string(),
                        cwe_id: Some("CWE-327".to_string()),
                        cvss_score: Some(3.1),
                        owasp_id: Some("A06:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Deprecated function: {}", desc),
                        fix_hint: "Use SHA-256+ for hashing, use cryptography library instead of PyCrypto.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-051: Missing Function-Level Access Control (INFO)
pub struct MissingAccessControlRule;

impl Rule for MissingAccessControlRule {
    fn id(&self) -> &str { "SEC-051" }
    fn name(&self) -> &str { "Missing Function-Level Access Control" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"@app\.route\s*\([^)]*\)\s*\ndef\s+(admin|delete|manage|config|setup|reset)"#, "Sensitive function without explicit auth"),
            (r#"@app\.route\s*\([^)]*\)\s*\ndef\s+(user|profile|account|settings)"#, "User-related function without explicit auth"),
            (r#"def\s+(delete|remove|destroy|modify|update)_[a-z_]+\s*\("#, "Destructive function without permission check"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-051".to_string(),
                        severity: Severity::Info.as_str().to_string(),
                        cwe_id: Some("CWE-284".to_string()),
                        cvss_score: Some(3.1),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Missing access control: {}", desc),
                        fix_hint: "Add authorization decorators like @login_required, @require_roles, or permission checks.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-052: Improper Error Handling (INFO)
pub struct ImproperErrorHandlingRule;

impl Rule for ImproperErrorHandlingRule {
    fn id(&self) -> &str { "SEC-052" }
    fn name(&self) -> &str { "Improper Error Handling" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"except\s+Exception\s+as\s+\w+\s*:\s*\n\s*raise\s+\w+"#, "Re-raising exception without wrapping"),
            (r#"except\s*:\s*\n\s*pass"#, "Swallowing exceptions silently"),
            (r#"except\s+BaseException"#, "Catching BaseException (too broad)"),
            (r#"try:.*except.*:.*pass"#, "Empty exception handler"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-052".to_string(),
                        severity: Severity::Info.as_str().to_string(),
                        cwe_id: Some("CWE-390".to_string()),
                        cvss_score: Some(3.1),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Improper error handling: {}", desc),
                        fix_hint: "Log errors appropriately and return structured error responses. Never silently swallow exceptions.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-053: Integer Overflow (INFO)
pub struct IntegerOverflowRule;

impl Rule for IntegerOverflowRule {
    fn id(&self) -> &str { "SEC-053" }
    fn name(&self) -> &str { "Integer Overflow Potential" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"int\s*\([^)]*\)\s*\+\s*\d{5,}"#, "Large integer addition without bounds check"),
            (r#"\[[\s\S]*?\]\s*\[(?:user|input|from).*\]"#, "Array access with untrusted index"),
            (r#"range\s*\([^)]*(?:user|input|len)"#, "Range with untrusted length"),
            (r#"counter\s*\+=\s*\d+"#, "Counter increment without overflow check"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-053".to_string(),
                        severity: Severity::Info.as_str().to_string(),
                        cwe_id: Some("CWE-190".to_string()),
                        cvss_score: Some(3.1),
                        owasp_id: Some("A04:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Potential integer overflow: {}", desc),
                        fix_hint: "Add bounds checking before arithmetic operations. Use Python's arbitrary precision integers or explicit overflow handling.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-054: TOCTOU Race Condition (INFO)
pub struct ToctouInfoRule;

impl Rule for ToctouInfoRule {
    fn id(&self) -> &str { "SEC-054" }
    fn name(&self) -> &str { "TOCTOU Race Condition" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"os\.path\.exists\s*\(.*\)\s*:\s*\n\s*.*open\s*\("#, "File exists check before open (TOCTOU)"),
            (r#"if\s+.*:\s*\n\s*.*os\.(chmod|chown|rename|remove)"#, "Permission check before file operation (TOCTOU)"),
            (r#"is_admin\s*=\s*True\s*:\s*\n\s*.*\.(delete|modify|execute)"#, "is_admin check before action (TOCTOU)"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-054".to_string(),
                        severity: Severity::Info.as_str().to_string(),
                        cwe_id: Some("CWE-367".to_string()),
                        cvss_score: Some(3.1),
                        owasp_id: Some("A04:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("TOCTOU race condition: {}", desc),
                        fix_hint: "Use atomic operations or file locking. Perform check and operation in a single transaction.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-055: Improper Certificate Validation (INFO)
pub struct CertificateValidationRule;

impl Rule for CertificateValidationRule {
    fn id(&self) -> &str { "SEC-055" }
    fn name(&self) -> &str { "Improper Certificate Validation" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"check_hostname\s*=\s*False"#, "Hostname checking disabled"),
            (r#"verify\s*=\s*False"#, "SSL verification disabled"),
            (r#"ssl\._create_unverified_context"#, "Unverified SSL context"),
            (r#"requests\.get\s*\([^)]*verify\s*=\s*False"#, "requests without SSL verification"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-055".to_string(),
                        severity: Severity::Info.as_str().to_string(),
                        cwe_id: Some("CWE-295".to_string()),
                        cvss_score: Some(3.1),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Improper certificate validation: {}", desc),
                        fix_hint: "Always verify SSL certificates. Use the system's CA bundle.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-056: Missing Encryption for Sensitive Data (INFO)
pub struct MissingEncryptionRule;

impl Rule for MissingEncryptionRule {
    fn id(&self) -> &str { "SEC-056" }
    fn name(&self) -> &str { "Missing Encryption for Sensitive Data" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(?i)(password|secret|token|key)\s*=\s*['\"][^'\"]{8,}['\"]"#, "Hardcoded sensitive string"),
            (r#"base64\.(b64encode|b64decode)\s*\([^)]*(?:password|secret|token)"#, "Base64 encoding sensitive data"),
            (r#"(?i).*\.encrypt\s*\(\s*[^)]*\)\s*(?:#.*not\s+encrypted)?"#, "Encryption call detected"),
            (r#" Fernet\s*\(\s*\)"#, "Fernet initialization found"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-056".to_string(),
                        severity: Severity::Info.as_str().to_string(),
                        cwe_id: Some("CWE-311".to_string()),
                        cvss_score: Some(3.1),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Missing encryption: {}", desc),
                        fix_hint: "Use proper encryption (Fernet, cryptography library) for sensitive data. Don't store in plaintext.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-057: Improper Restriction of Rendered UI Layer (INFO)
pub struct UiLayerRestrictionRule;

impl Rule for UiLayerRestrictionRule {
    fn id(&self) -> &str { "SEC-057" }
    fn name(&self) -> &str { "Improper Restriction of Rendered UI Layer" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"iframe.*src\s*=\s*['\"][^'\"]*['\"]"#, "iframe embedding detected"),
            (r#"X-Frame-Options"#, "X-Frame-Options header"),
            (r#"data:text/html"#, "data: URI with HTML content"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-057".to_string(),
                        severity: Severity::Info.as_str().to_string(),
                        cwe_id: Some("CWE-1021".to_string()),
                        cvss_score: Some(3.1),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("UI layer restriction issue: {}", desc),
                        fix_hint: "Use X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-058: SSRF Cloud Metadata (MEDIUM)
pub struct SsrfCloudRule;

impl Rule for SsrfCloudRule {
    fn id(&self) -> &str { "SEC-058" }
    fn name(&self) -> &str { "SSRF - Cloud Metadata Service" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(?i)169\.254\.169\.254"#, "AWS/Cloud metadata IP address"),
            (r#"(?i)http://metadata\.google"#, "GCP metadata endpoint"),
            (r#"(?i)metadata\.azure\.com"#, "Azure metadata endpoint"),
            (r#"(?i)(requests|urllib).*(?:metadata|instance-data|latest/meta-data)"#, "Cloud metadata service access"),
            (r#"(?i)(requests|urllib).*169\.254"#, "Access to link-local address"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-058".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-918".to_string()),
                        cvss_score: Some(6.5),
                        owasp_id: Some("A10:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("SSRF targeting cloud metadata: {}", desc),
                        fix_hint: "Validate and whitelist URLs. Block access to metadata endpoints from untrusted input.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// SEC-059: Business Logic Vulnerability (INFO)
pub struct BusinessLogicRule;

impl Rule for BusinessLogicRule {
    fn id(&self) -> &str { "SEC-059" }
    fn name(&self) -> &str { "Business Logic Vulnerability" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(?i)(price|amount|total|cost)\s*=\s*float\s*\([^)]*\)"#, "Price/amount conversion without rounding"),
            (r#"(?i)(discount|coupon|rate)\s*=\s*\([^)]*\)\s*#.*not\s+validated"#, "Business value not validated"),
            (r#"Decimal\s*\([^)]*(?:user|input|request)"#, "Decimal from untrusted input without validation"),
            (r#"(?i)(price|amount|quantity)\s*[+\-*/]\s*=?\s*[^;]*\s*#.*race"#, "Race condition in business calculation"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-059".to_string(),
                        severity: Severity::Info.as_str().to_string(),
                        cwe_id: Some("CWE-841".to_string()),
                        cvss_score: Some(3.1),
                        owasp_id: Some("A04:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Business logic issue: {}", desc),
                        fix_hint: "Validate business rules server-side. Use Decimal for financial calculations. Add rate limiting.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// ============================================================================
// NEW SECURITY RULES (SEC-113 to SEC-117)
// ============================================================================

// SEC-113: NoSQL / MongoDB Injection (CRITICAL)
static NOSQL_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"\$\s*where\s*[=:]\s*[^}]*(?:request|input|param|user|args|body)"#,
     "NoSQL injection: $where clause with user input — potential code injection"),
    (r#"db\[\s*[^]]+\]\.find\s*\([^)]*\+[^)]*(?:request|input|param|user)"#,
     "NoSQL injection: MongoDB find() with string concatenation"),
    (r#"collection\.find_one\s*\([^)]*\+[^)]*(?:request|input|param|user)"#,
     "NoSQL injection: find_one with string concatenation"),
    (r#"db\.collection\.(?:find|find_one|insert_one|update_one)\s*\([^)]*(?:request|input|param|user|body)"#,
     "NoSQL operation with user-controlled data"),
]);

pub struct NoSqlInjectionRule;

impl Rule for NoSqlInjectionRule {
    fn id(&self) -> &str { "SEC-113" }
    fn name(&self) -> &str { "NoSQL / MongoDB Injection" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, desc) in NOSQL_PATTERNS.iter() {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-113".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-943".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("NoSQL injection vulnerability: {}", desc),
                        fix_hint: "Use MongoDB $eq operator or parameterized queries. Never include user input directly in NoSQL queries.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// SEC-114: JWT Algorithm Confusion (CRITICAL)
static JWT_ALG_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"jwt\.decode\s*\([^)]*algorithms\s*=\s*\[[^\]]+\][^)]*\)"#,
     "JWT decode with multiple/flexible algorithms — algorithm confusion risk (alg:none / key confusion)"),
    (r#"algorithms\s*=\s*\[\s*['\"]RS256['\"],\s*['\"]HS256['\"]\s*\]"#,
     "JWT with both RS256 and HS256 algorithms — public RSA key can be used as HMAC secret"),
    (r#"algorithms\s*[=:]\s*\[\s*['\"]?none['\"]?\s*\]"#,
     "JWT with 'none' algorithm — signature is not verified, token can be forged"),
]);

pub struct JwtAlgorithmConfusionRule;

impl Rule for JwtAlgorithmConfusionRule {
    fn id(&self) -> &str { "SEC-114" }
    fn name(&self) -> &str { "JWT Algorithm Confusion Attack" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, desc) in JWT_ALG_PATTERNS.iter() {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-114".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-347".to_string()),
                        cvss_score: Some(9.1),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("JWT algorithm confusion: {}", desc),
                        fix_hint: "Use a hardcoded algorithm (e.g., HS256). Never allow the client to specify the algorithm. Validate the algorithm matches your expectation.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// SEC-115: OAuth CSRF — Missing State Validation (HIGH)
static OAUTH_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"(?:oauth_|/oauth/)(?:callback|auth)"#,
     "OAuth callback endpoint detected"),
    (r#"(?:request\.args|request\.values|request\.args\.get)\s*\(\s*['\"]code['\"]"#,
     "OAuth code received without evident state parameter validation"),
]);

pub struct OAuthMissingStateRule;

impl Rule for OAuthMissingStateRule {
    fn id(&self) -> &str { "SEC-115" }
    fn name(&self) -> &str { "OAuth CSRF — Missing State Parameter Validation" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, desc) in OAUTH_PATTERNS.iter() {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-115".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-352".to_string()),
                        cvss_score: Some(7.1),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("OAuth CSRF vulnerability: {}", desc),
                        fix_hint: "Generate a cryptographically random state parameter in the authorization request and validate it on callback to prevent CSRF attacks.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// SEC-116: Dynamic Import — Code Injection (CRITICAL)
static DYNAMIC_IMPORT_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"__import__\s*\([^)]*(?:request|input|param|user|args|body)"#,
     "Dynamic __import__ with user-controlled module name — code execution risk"),
    (r#"importlib\.import_module\s*\([^)]*(?:request|input|param|user|args|body)"#,
     "importlib.import_module with user input — arbitrary code execution risk"),
    (r#"getattr\s*\(\s*sys\.modules\s*,\s*[^)]*(?:request|input|param|user)"#,
     "getattr on sys.modules with user input — module attribute injection"),
    (r#"importlib\.import_module\s*\(\s*\w+\s*\)(?!\s*#)"#,
     "Dynamic import without hardcoded module — verify module name is not user-controlled"),
]);

pub struct DynamicImportInjectionRule;

impl Rule for DynamicImportInjectionRule {
    fn id(&self) -> &str { "SEC-116" }
    fn name(&self) -> &str { "Dynamic Import — Code Injection via User-Controlled Module Name" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, desc) in DYNAMIC_IMPORT_PATTERNS.iter() {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-116".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-94".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Dynamic import injection: {}", desc),
                        fix_hint: "Never use user input to import modules dynamically. Use a whitelist of allowed modules and validate the module name against that list.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// SEC-117: SSRF Advanced — Cloud Metadata + Dangerous URL Protocols (HIGH)
static SSRF_ADVANCED_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"169\.254\.169\.254"#, "AWS metadata endpoint (169.254.169.254) — SSRF risk gives cloud credentials"),
    (r#"metadata\.google\.internal"#, "GCP metadata endpoint — SSRF risk gives cloud credentials"),
    (r#"metadata\.azure\.com"#, "Azure metadata endpoint — SSRF risk gives cloud credentials"),
    (r#"kubernetes\.docker\.internal"#, "Kubernetes internal metadata — SSRF risk"),
    (r#"(?:requests|urllib)\.(?:get|post|put|delete|head)\s*\([^)]*['\"]?file://"#, "URL with file:// scheme — local file access via SSRF"),
    (r#"(?:requests|urllib)\.(?:get|post|put|delete|head)\s*\([^)]*['\"]?gopher://"#, "URL with gopher:// scheme — SSRF to internal services"),
    (r#"(?:requests|urllib)\.(?:get|post|put|delete|head)\s*\([^)]*['\"]?dict://"#, "URL with dict:// scheme — SSRF to memcached/redis"),
    (r#"(?:requests|urllib)\.(?:get|post|put|delete|head)\s*\([^)]*['\"]?ldap://"#, "URL with ldap:// scheme — SSRF to internal directory services"),
    (r#"http://10\.\d+\.\d+\.\d+"#, "HTTP request to private IP range (10.x) — SSRF risk"),
    (r#"http://172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+"#, "HTTP request to private IP range (172.16-31.x) — SSRF risk"),
    (r#"http://192\.168\.\d+\.\d+"#, "HTTP request to private IP range (192.168.x) — SSRF risk"),
    (r#"http://127\.\d+\.\d+\.\d+"#, "HTTP request to localhost — SSRF risk"),
    (r#"http://0\.0\.0\.0"#, "HTTP request to 0.0.0.0 — SSRF risk"),
]);

pub struct SsrfAdvancedRule;

impl Rule for SsrfAdvancedRule {
    fn id(&self) -> &str { "SEC-117" }
    fn name(&self) -> &str { "SSRF Advanced — Cloud Metadata + Dangerous URL Protocols" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, desc) in SSRF_ADVANCED_PATTERNS.iter() {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-117".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-918".to_string()),
                        cvss_score: Some(8.6),
                        owasp_id: Some("A10:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Advanced SSRF: {}", desc),
                        fix_hint: "Validate and whitelist URLs. Block access to cloud metadata endpoints, private IP ranges, and dangerous URL schemes (file://, gopher://, dict://, ldap://).".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// ============================================================================
// RULE REGISTRY
// ============================================================================

use crate::rules::sec060::AutocompleteEnabledRule;
use crate::rules::sec061::MissingSriRule;
use crate::rules::sec062::MissingContentTypeValidationRule;
use crate::rules::sec063::MissingRateLimitingRule;
use crate::rules::sec064::WeakJwtSecretRule;
use crate::rules::sec065::InsecureLogoutRule;
use crate::rules::sec066::TimingAttackRule;
use crate::rules::sec067::WeakServerValidationRule;
use crate::rules::sec068::FrontendPriceManipulationRule;
use crate::rules::sec069::DangerousDependenciesRule;
use crate::rules::sec070::DockerVulnerabilityRule;
use crate::rules::sec071::WeakJwtPayloadRule;
use crate::rules::sec072::MissingCspNonceRule;
// SEC-073 to SEC-090 (PHP Security Rules) are now in php_rules/php.rs
use crate::rules::php_rules;

/// Get all security rules.
#[allow(clippy::redundant_allocation)]
pub fn all_security_rules() -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = vec![
        // Critical
        Box::new(CommandInjectionRule),
        Box::new(SqlInjectionRule),
        Box::new(EvalExecRule),
        // Note: DeserializationRceRule removed - SEC-004 is handled by InsecureDeserializationRule in extended_security.rs (SEC-087)
        Box::new(PathTraversalRule),
        Box::new(NoSqlInjectionRule),
        Box::new(JwtAlgorithmConfusionRule),
        Box::new(DynamicImportInjectionRule),
        // High
        Box::new(HardcodedSecretsRule),
        // Note: WeakCryptoRule removed - SEC-011 is handled by WeakHashRule in extended_security.rs (SEC-076)
        Box::new(InsecureSslRule),
        Box::new(XxeRule),
        Box::new(YamlUnsafeRule),
        Box::new(AssertInProductionRule),
        Box::new(DebugModeRule),
        Box::new(CorsWildcardRule),
        Box::new(JwtNoneRule),
        Box::new(WeakRandomRule),
        Box::new(OAuthMissingStateRule),
        Box::new(SsrfAdvancedRule),
        // Medium
        Box::new(LdapInjectionRule),
        Box::new(XssRule),
        Box::new(SsrfRule),
        Box::new(OpenRedirectRule),
        Box::new(crate::rules::sec024::Sec024),
        Box::new(crate::rules::sec025::Sec025),
        Box::new(crate::rules::sec026::Sec026),
        Box::new(JwtVerificationDisabledRule),
        Box::new(CookieHttpOnlyRule),
        Box::new(CookieSecureFlagRule),
        Box::new(MissingSecurityHeaderRule),
        Box::new(TraceMethodRule),
        Box::new(XContentTypeOptionsRule),
        Box::new(XFrameOptionsRule),
        Box::new(CspMissingRule),
        // Note: DeserializationRceRule removed - SEC-004 is handled by InsecureDeserializationRule in extended_security.rs (SEC-087)
        // SEC-060 to SEC-072 (New rules)
        Box::new(AutocompleteEnabledRule),
        Box::new(MissingSriRule),
        Box::new(MissingContentTypeValidationRule),
        Box::new(MissingRateLimitingRule),
        Box::new(WeakJwtSecretRule),
        Box::new(InsecureLogoutRule),
        Box::new(TimingAttackRule),
        Box::new(WeakServerValidationRule),
        Box::new(FrontendPriceManipulationRule),
        Box::new(DangerousDependenciesRule),
        Box::new(DockerVulnerabilityRule),
        Box::new(WeakJwtPayloadRule),
        Box::new(MissingCspNonceRule),
        // SEC-073 to SEC-090 (PHP Security Rules)
        Box::new(php_rules::php::PhpSqlInjectionRule),
        Box::new(php_rules::php::PhpXssRule),
        Box::new(php_rules::php::PhpInsecureFileUploadRule),
        Box::new(php_rules::php::PhpLooseComparisonRule),
        Box::new(php_rules::php::PhpEvalAssertRule),
        Box::new(php_rules::php::PhpUnserializeRule),
        Box::new(php_rules::php::PhpIncludeTraversalRule),
        Box::new(php_rules::php::PhpHardcodedSecretsRule),
        Box::new(php_rules::php::PhpCommandInjectionRule),
        Box::new(php_rules::php::PhpSsrfRule),
        Box::new(php_rules::php::PhpDebugModeRule),
        Box::new(php_rules::php::PhpSessionRule),
        Box::new(php_rules::php::PhpCsrfRule),
        Box::new(php_rules::php::PhpXxeRule),
        Box::new(php_rules::php::PhpOpenRedirectRule),
        Box::new(php_rules::php::PhpLdapInjectionRule),
        Box::new(php_rules::php::PhpMassAssignmentRule),
        Box::new(php_rules::php::PhpInfoDisclosureRule),
        // Low
        Box::new(SensitiveCommentRule),
        Box::new(InfoDisclosureRule),
        Box::new(crate::rules::sec042::Sec042),
        Box::new(crate::rules::sec043::Sec043),
        Box::new(crate::rules::sec044::Sec044),
        Box::new(MissingReferrerPolicyRule),
        Box::new(SecurityDisabledRule),
        Box::new(AntiAutomationRule),
        Box::new(PiiLogRule),
        Box::new(WeakPasswordRule),
        // Info
        Box::new(DeprecatedFunctionRule),
        Box::new(MissingAccessControlRule),
        Box::new(ImproperErrorHandlingRule),
        Box::new(IntegerOverflowRule),
        Box::new(ToctouInfoRule),
        Box::new(CertificateValidationRule),
        Box::new(MissingEncryptionRule),
        Box::new(UiLayerRestrictionRule),
        Box::new(SsrfCloudRule),
        Box::new(BusinessLogicRule),
    ];
    // Add extended security rules (SEC-073 to SEC-105+)
    rules.extend(crate::rules::extended_security::all_extended_security_rules());
    // Add hackingtool-inspired rules (SEC-118 to SEC-125)
    rules.extend(crate::rules::hackingtool_patterns::all_hackingtool_rules());
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::tree_sitter::parse;
    use crate::rules::extended_security::{
        SqlInjectionSinkRule, XssSinkRule, LfiSinkRule, CsrfSinkRule, SsrfSinkRule,
        OpenRedirectSinkRule,
    };

    #[test]
    fn test_command_injection() {
        let rule = CommandInjectionRule;
        let code = r#"
import os
user_input = "ls -la"
os.system(user_input)
"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "SEC-001");
    }

    #[test]
    fn test_sql_injection() {
        let rule = SqlInjectionRule;
        let code = r#"cursor.execute("SELECT * FROM users WHERE id=" + user_id)"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "SEC-002");
    }

    #[test]
    fn test_eval_usage() {
        let rule = EvalExecRule;
        let code = "result = eval(user_input)";
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "SEC-003");
    }

    #[test]
    fn test_yaml_unsafe_load() {
        let rule = DeserializationRceRule;
        let code = "data = yaml.load(user_yaml)";
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "SEC-004");
        assert!(findings[0].auto_fix_available);
    }

    #[test]
    fn test_yaml_safe_load_auto_fix() {
        let rule = DeserializationRceRule;
        let code = "data = yaml.load(user_yaml)";
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        if let Some(fix) = rule.fix(&findings[0], code) {
            assert!(fix.replacement.contains("safe_load"));
        }
    }

    #[test]
    fn test_path_traversal() {
        let rule = PathTraversalRule;
        let code = r#"
with open(user_filename) as f:
    content = f.read()
"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "SEC-005");
    }

    // ========================================================================
    // Phase 2: Vulnerable Sink Detection Tests (SEC-126 to SEC-131)
    // These rules detect VULNERABLE CODE that hackingtool exploits target.
    // ========================================================================

    #[test]
    fn test_sec126_sqli_fstring_sink() {
        let rule = SqlInjectionSinkRule;
        let code = r#"cursor.execute(f"SELECT * FROM users WHERE name={username}" % password)"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "f-string in cursor.execute should be detected");
        assert_eq!(findings[0].rule_id, "SEC-126");
    }

    #[test]
    fn test_sec126_sqli_percent_format_sink() {
        let rule = SqlInjectionSinkRule;
        let code = r#"cursor.execute("SELECT * FROM admin WHERE pass='%s'" % password)"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "%-formatting in SQL should be detected");
        assert_eq!(findings[0].rule_id, "SEC-126");
    }

    #[test]
    fn test_sec126_sqli_user_input_sink() {
        let rule = SqlInjectionSinkRule;
        let code = r#"db.execute("SELECT * FROM users WHERE id='%s'" % request.args['id'])"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "f-string with request input in SQL should be detected");
        assert_eq!(findings[0].rule_id, "SEC-126");
    }

    #[test]
    fn test_sec127_xss_render_template_string() {
        let rule = XssSinkRule;
        let code = r#"render_template_string(request.args.get('template', ''))"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "render_template_string with user input should be detected");
        assert_eq!(findings[0].rule_id, "SEC-127");
    }

    #[test]
    fn test_sec127_xss_mark_safe() {
        let rule = XssSinkRule;
        let code = r#"mark_safe(request.GET['content'])"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "mark_safe with user input should be detected");
        assert_eq!(findings[0].rule_id, "SEC-127");
    }

    #[test]
    fn test_sec127_xss_htmlresponse() {
        let rule = XssSinkRule;
        let code = r#"HTMLResponse(content=user_input)"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "HTMLResponse with user input should be detected");
        assert_eq!(findings[0].rule_id, "SEC-127");
    }

    #[test]
    fn test_sec128_lfi_open_user_path() {
        let rule = LfiSinkRule;
        let code = r#"with open(f"templates/{request.args.get('page')}.html") as f:"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "open() with user path should be detected");
        assert_eq!(findings[0].rule_id, "SEC-128");
    }

    #[test]
    fn test_sec128_lfi_send_from_directory() {
        let rule = LfiSinkRule;
        let code = r#"send_from_directory('static', request.args.get('file'))"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "send_from_directory with user input should be detected");
        assert_eq!(findings[0].rule_id, "SEC-128");
    }

    #[test]
    fn test_sec128_lfi_pathlib() {
        let rule = LfiSinkRule;
        let code = r#"Path(request.args['path'])"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "pathlib.Path with user input should be detected");
        assert_eq!(findings[0].rule_id, "SEC-128");
    }

    #[test]
    fn test_sec129_csrf_exempt() {
        let rule = CsrfSinkRule;
        let code = r#"@csrf_exempt
@app.route('/transfer', methods=['POST'])
def transfer():
    amount = request.form['amount']"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "@csrf_exempt should be detected");
        assert_eq!(findings[0].rule_id, "SEC-129");
    }

    #[test]
    fn test_sec130_ssrf_requests_url() {
        let rule = SsrfSinkRule;
        let code = r#"requests.get(request.args.get('url'))"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "requests.get with user URL should be detected");
        assert_eq!(findings[0].rule_id, "SEC-130");
    }

    #[test]
    fn test_sec130_ssrf_aws_metadata() {
        let rule = SsrfSinkRule;
        let code = r#"requests.get('http://169.254.169.254/latest/meta-data/')"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "AWS metadata endpoint should be detected");
        assert_eq!(findings[0].rule_id, "SEC-130");
    }

    #[test]
    fn test_sec130_ssrf_urllib() {
        let rule = SsrfSinkRule;
        let code = r#"urllib.request.urlopen(request.args.get('target'))"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "urllib.urlopen with user URL should be detected");
        assert_eq!(findings[0].rule_id, "SEC-130");
    }

    #[test]
    fn test_sec131_open_redirect_flask() {
        let rule = OpenRedirectSinkRule;
        let code = r#"return redirect(request.args.get('next'))"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "Flask redirect with user input should be detected");
        assert_eq!(findings[0].rule_id, "SEC-131");
    }

    #[test]
    fn test_sec131_open_redirect_django() {
        let rule = OpenRedirectSinkRule;
        let code = r#"HttpResponseRedirect(request.GET['next'])"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "Django HttpResponseRedirect with user input should be detected");
        assert_eq!(findings[0].rule_id, "SEC-131");
    }

    #[test]
    fn test_sec131_open_redirect_fastapi() {
        let rule = OpenRedirectSinkRule;
        let code = r#"RedirectResponse(url=request.query_params.get('next'))"#;
        let tree = parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty(), "FastAPI RedirectResponse with user input should be detected");
        assert_eq!(findings[0].rule_id, "SEC-131");
    }

    // ========================================================================
    // Hackingtool Pattern Tests (SEC-118 to SEC-125)
    // ========================================================================

    #[test]
    fn test_sec118_social_engineering_maskphish() {
        let code = "curl -sSL https://github.com/jaybutera/maskphish | bash";
        let tree = parse(code).unwrap();
        let rules = crate::rules::hackingtool_patterns::all_hackingtool_rules();
        let sec118 = &rules[0];
        let findings = sec118.detect(&tree, code);
        assert!(!findings.is_empty(), "maskphish pattern should be detected by SEC-118");
    }

    #[test]
    fn test_sec119_rogue_ap_wifiphisher() {
        let code = "wifiphisher -i wlan0";
        let tree = parse(code).unwrap();
        let rules = crate::rules::hackingtool_patterns::all_hackingtool_rules();
        let sec119 = &rules[1];
        let findings = sec119.detect(&tree, code);
        assert!(!findings.is_empty(), "wifiphisher should be detected by SEC-119");
    }

    #[test]
    fn test_sec120_curl_pipe_bash() {
        let code = "curl -sSL https://example.com/install.sh | sudo bash";
        let tree = parse(code).unwrap();
        let rules = crate::rules::hackingtool_patterns::all_hackingtool_rules();
        let sec120 = &rules[2];
        let findings = sec120.detect(&tree, code);
        assert!(!findings.is_empty(), "curl pipe bash should be detected by SEC-120");
    }

    #[test]
    fn test_sec121_surveillance_keylogger() {
        let code = "pynput.keyboard import Listener; keylog = Listener(on_press=record_key)";
        let tree = parse(code).unwrap();
        let rules = crate::rules::hackingtool_patterns::all_hackingtool_rules();
        let sec121 = &rules[3];
        let findings = sec121.detect(&tree, code);
        assert!(!findings.is_empty(), "pynput keylogger should be detected by SEC-121");
    }

    #[test]
    fn test_sec122_c2_sliver() {
        let code = "sliver server --gmt";
        let tree = parse(code).unwrap();
        let rules = crate::rules::hackingtool_patterns::all_hackingtool_rules();
        let sec122 = &rules[4];
        let findings = sec122.detect(&tree, code);
        assert!(!findings.is_empty(), "sliver C2 should be detected by SEC-122");
    }

    #[test]
    fn test_sec123_backdoor_fatrat() {
        let code = "python TheFatRat.py -p backend.exe";
        let tree = parse(code).unwrap();
        let rules = crate::rules::hackingtool_patterns::all_hackingtool_rules();
        let sec123 = &rules[5];
        let findings = sec123.detect(&tree, code);
        assert!(!findings.is_empty(), "TheFatRat should be detected by SEC-123");
    }

    #[test]
    fn test_sec124_credential_hydra() {
        let code = "hydra -l admin -P rockyou.txt ssh://target";
        let tree = parse(code).unwrap();
        let rules = crate::rules::hackingtool_patterns::all_hackingtool_rules();
        let sec124 = &rules[6];
        let findings = sec124.detect(&tree, code);
        assert!(!findings.is_empty(), "hydra brute-force should be detected by SEC-124");
    }

    #[test]
    fn test_sec125_network_bettercap() {
        let code = "bettercap -X -P HUD";
        let tree = parse(code).unwrap();
        let rules = crate::rules::hackingtool_patterns::all_hackingtool_rules();
        let sec125 = &rules[7];
        let findings = sec125.detect(&tree, code);
        assert!(!findings.is_empty(), "bettercap MITM should be detected by SEC-125");
    }
}
