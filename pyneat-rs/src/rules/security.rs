//! Security rules for pyneat-rs.
//!
//! Implements SEC-001 through SEC-059 security rules.

use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

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
        let patterns = [
            (r"os\.system\s*\(", "os.system()"),
            (r"subprocess\.run\s*\([^)]*shell\s*=\s*True", "subprocess.run with shell=True"),
            (r"os\.popen\s*\(", "os.popen()"),
        ];

        for (pattern, _) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
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
                        problem: "User input is passed directly to a shell command. This can allow command injection attacks.".to_string(),
                        fix_hint: "Use subprocess.run with shell=False and pass command as a list of arguments instead of a string.".to_string(),
                        auto_fix_available: false,
                    });
                }
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
            (r#"(cursor|db|connection)\.execute\s*\([^)]*\+"#, "SQL query with string concatenation"),
            (r#"f['"].*SELECT.*\{[^}]+\}.*['"]"#, "SQL query with f-string interpolation"),
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
                        auto_fix_available: false,
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
                        auto_fix_available: false,
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
            (r#"redirect\s*\([^)]*(?:next|redirect|return|url|path)"#, "Redirect with URL parameter"),
            (r#"Location\s*:\s*.*request\."#, "HTTP Location header with user input"),
            (r#"send_file\s*\([^)]*request\."#, "send_file with user-controlled path"),
            (r#"\.url_for\s*\([^)]*\)", "Flask url_for usage"),
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
            (r#"hashlib\.(md5|sha1)\s*\("#, "Deprecated hash function (MD5/SHA1)"),
            (r#"ssl\.wrap_socket\s*\("#, "Deprecated ssl.wrap_socket()"),
            (r#"hashlib\.new\s*\(['\"]md5['\"]"#, "hashlib.new with MD5"),
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
    let rules: Vec<Box<dyn Rule>> = vec![
        // Critical
        Box::new(CommandInjectionRule),
        Box::new(SqlInjectionRule),
        Box::new(EvalExecRule),
        Box::new(DeserializationRceRule),
        Box::new(PathTraversalRule),
        // High
        Box::new(HardcodedSecretsRule),
        Box::new(WeakCryptoRule),
        Box::new(InsecureSslRule),
        Box::new(XxeRule),
        Box::new(YamlUnsafeRule),
        Box::new(AssertInProductionRule),
        Box::new(DebugModeRule),
        Box::new(CorsWildcardRule),
        Box::new(JwtNoneRule),
        Box::new(WeakRandomRule),
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
    rules
}

/// Extract a code snippet around the match (1-3 lines).
fn extract_snippet(source: &str, start: usize, end: usize) -> String {
    // Find the start of the line containing the match
    let line_start = source[..start]
        .rfind('\n')
        .map(|i| i + 1)
        .unwrap_or(0);

    // Find the end of the line containing the match
    let line_end = source[end..]
        .find('\n')
        .map(|i| end + i)
        .unwrap_or(source.len());

    // Also include one line before if available
    let context_before = if line_start > 0 {
        source[..line_start - 1]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0)
    } else {
        line_start
    };

    let snippet = &source[context_before..line_end];
    snippet.lines().take(3).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::tree_sitter::parse;

    #[test]
    fn test_command_injection() {
        let rule = CommandInjectionRule;
        let code = r#"
import os
os.system("ls -la")
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
}
