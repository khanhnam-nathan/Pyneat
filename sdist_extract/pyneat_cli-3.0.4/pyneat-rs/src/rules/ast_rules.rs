//! AST-based security rules using tree-sitter for semantic analysis.
//!
//! Unlike regex-based rules in security.rs, these rules walk the actual
//! tree-sitter AST to perform semantic analysis, providing higher accuracy
//! and fewer false positives/negatives.
//!
//! Copyright (C) 2026 PyNEAT Authors

use crate::rules::base::{extract_snippet, Finding, Rule, Severity};
use crate::scanner::tree_sitter::{walk_tree, NodeInfo};
use tree_sitter::Tree;
use std::collections::HashSet;

// --------------------------------------------------------------------------
// AST Rule trait - extends base Rule with tree-sitter support
// --------------------------------------------------------------------------

/// Extension trait providing AST-based detection on top of the base Rule trait.
/// Rules can override these methods to perform deep semantic analysis using
/// the tree-sitter parse tree.
pub trait AstRule {
    /// Walk the tree-sitter AST and detect issues.
    /// The default implementation does nothing (use regex-based detect).
    fn detect_ast(&self, tree: &Tree, code: &str) -> Vec<Finding> {
        let _ = (tree, code);
        Vec::new()
    }

    /// Check if this rule provides AST-based detection.
    fn has_ast_detection(&self) -> bool {
        false
    }
}

// --------------------------------------------------------------------------
// AST-based SEC-001: Command Injection
// Detects os.system, os.popen, subprocess.run(shell=True)
// --------------------------------------------------------------------------

pub struct AstCommandInjectionRule;

impl AstCommandInjectionRule {
    pub fn new() -> Self {
        Self
    }
}

impl AstRule for AstCommandInjectionRule {
    fn has_ast_detection(&self) -> bool {
        true
    }
}

impl Rule for AstCommandInjectionRule {
    fn id(&self) -> &str {
        "SEC-001-AST"
    }

    fn name(&self) -> &str {
        "Command Injection (AST-based)"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, tree: &Tree, code: &str) -> Vec<Finding> {
        let regex_findings = self.detect_regex(code);
        let ast_findings = self.detect_ast(tree, code);

        let mut all: Vec<_> = regex_findings
            .into_iter()
            .chain(ast_findings.into_iter())
            .collect();
        all.sort_by_key(|f| f.start);
        all.dedup_by_key(|f| f.start);
        all
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<crate::rules::base::Fix> {
        let original = &code[finding.start..finding.end];
        if original.contains("os.system") {
            Some(crate::rules::base::Fix {
                rule_id: self.id().to_string(),
                description: "Replace os.system() with subprocess.run()".to_string(),
                original: original.to_string(),
                replacement: "subprocess.run([...], shell=False, check=True)".to_string(),
                start: finding.start,
                end: finding.end,
            })
        } else if original.contains("subprocess.run") && original.contains("shell=True") {
            Some(crate::rules::base::Fix {
                rule_id: self.id().to_string(),
                description: "Set shell=False in subprocess.run".to_string(),
                original: original.to_string(),
                replacement: original.replace("shell=True", "shell=False"),
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

impl AstCommandInjectionRule {
    fn detect_regex(&self, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let patterns = [
            r"os\.system\s*\(",
            r"subprocess\.run\s*\([^)]*shell\s*=\s*True",
            r"os\.popen\s*\(",
        ];

        for pattern in &patterns {
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
                        problem: "User input is passed directly to a shell command.".to_string(),
                        fix_hint: "Use subprocess.run with shell=False and pass command as a list.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn detect_ast(&self, tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen_starts: HashSet<usize> = HashSet::new();

        for pattern in &["os.system", "os.popen"] {
            if let Ok(re) = regex::Regex::new(&regex::escape(pattern)) {
                for m in re.find_iter(code) {
                    seen_starts.insert(m.start());
                }
            }
        }

        walk_tree(tree, code, |info| {
            if info.node_type == "call" {
                let text = info.text();
                let is_dangerous = text.contains("system")
                    || text.contains("popen")
                    || text.contains("spawn")
                    || text.contains("exec");

                if is_dangerous && !seen_starts.contains(&info.start_byte) {
                    if !text.contains("subprocess.run") || text.contains("shell=True") {
                        let snippet = extract_snippet(code, info.start_byte, info.end_byte);
                        findings.push(Finding {
                            rule_id: "SEC-001".to_string(),
                            severity: Severity::Critical.as_str().to_string(),
                            cwe_id: Some("CWE-78".to_string()),
                            cvss_score: Some(9.8),
                            owasp_id: Some("A03:2021".to_string()),
                            start: info.start_byte,
                            end: info.end_byte,
                            snippet,
                            problem: "Shell execution detected via AST analysis.".to_string(),
                            fix_hint: "Use subprocess.run with shell=False.".to_string(),
                            auto_fix_available: false,
                        });
                        seen_starts.insert(info.start_byte);
                    }
                }
            }
        });

        findings.sort_by_key(|f| f.start);
        findings
    }
}

// --------------------------------------------------------------------------
// AST-based SEC-010: Hardcoded Secrets
// Uses AST to distinguish test data from production secrets
// --------------------------------------------------------------------------

pub struct AstHardcodedSecretsRule;

impl AstHardcodedSecretsRule {
    pub fn new() -> Self {
        Self
    }

    fn classify_secret(var_name: &str, value: &str) -> (&'static str, f32) {
        let var_lower = var_name.to_lowercase();
        let value_lower = value.to_lowercase();

        let test_indicators = ["test", "mock", "fake", "dummy", "sample", "example", "dev", "debug", "localhost", "placeholder", "todo"];
        let prod_indicators = ["prod", "production", "live", "real", "primary", "master"];

        let test_count = test_indicators.iter().filter(|p| var_lower.contains(*p)).count();
        let prod_count = prod_indicators.iter().filter(|p| var_lower.contains(*p)).count();

        if test_count > 0 && prod_count == 0 {
            return ("test_secret", 0.85);
        }
        if prod_count > 0 {
            return ("production_secret", 0.9);
        }

        // Check for placeholder values
        let placeholders = ["changeme", "your-secret", "your_secret", "example-key", "example_key", "test-token", "test_token"];
        if placeholders.iter().any(|p| value_lower.contains(p)) {
            return ("placeholder", 0.95);
        }

        // Check for real credential format
        let cred_patterns = [
            r"AKIA[0-9A-Z]{16}",
            r"ghp_[a-zA-Z0-9]{36}",
            r"glpat-[a-zA-Z0-9-]{20}",
            r"sk-[a-zA-Z0-9]{48}",
            r"sk_live_[a-zA-Z0-9]{24}",
        ];
        for pat in &cred_patterns {
            if let Ok(re) = regex::Regex::new(pat) {
                if re.is_match(value) {
                    return ("production_secret", 0.9);
                }
            }
        }

        if value.len() >= 32 {
            return ("production_secret", 0.6);
        }

        ("unknown", 0.5)
    }

    fn extract_assignment_parts(text: &str) -> (String, Option<String>) {
        if let Some(pos) = text.find('=') {
            let before = &text[..pos];
            if before.contains("==") || before.contains("!=") || before.contains("<=") || before.contains(">=") {
                return (String::new(), None);
            }
            let var_name = before.trim().to_string();
            let value = text[pos + 1..].trim().to_string();
            return (var_name, Some(value));
        }
        (String::new(), None)
    }

    fn detect_credential_formats(&self, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let cred_patterns = [
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "CWE-798"),
            (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token", "CWE-798"),
            (r"glpat-[a-zA-Z0-9-]{20}", "GitLab Personal Access Token", "CWE-798"),
            (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key", "CWE-798"),
            (r"sk_live_[a-zA-Z0-9]{24}", "Stripe API Key", "CWE-798"),
            (r"xox[baprs]-[a-zA-Z0-9-]{10,}", "Slack Token", "CWE-798"),
        ];

        for (pattern, cred_type, cwe) in cred_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-010".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some(cwe.to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: format!("Hardcoded {} detected", cred_type),
                        fix_hint: "Use environment variables instead of hardcoding secrets.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }
}

impl AstRule for AstHardcodedSecretsRule {
    fn has_ast_detection(&self) -> bool {
        true
    }
}

impl Rule for AstHardcodedSecretsRule {
    fn id(&self) -> &str {
        "SEC-010-AST"
    }

    fn name(&self) -> &str {
        "Hardcoded Secrets (AST-based)"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree, code, |info| {
            if matches!(info.node_type.as_str(), "assignment" | "augmented_assignment") {
                let text = info.text();
                let (var_name, value) = Self::extract_assignment_parts(text);

                if var_name.is_empty() || value.is_none() {
                    return;
                }
                let value = value.unwrap();

                let secret_indicators = ["api_key", "apikey", "api-key", "secret", "password", "passwd", "token", "auth", "credential", "private_key", "aws_key", "jwt_secret", "encryption_key", "bearer"];
                let is_secret_var = secret_indicators.iter().any(|p| var_name.to_lowercase().contains(p));

                if !is_secret_var {
                    return;
                }

                let (secret_type, _) = Self::classify_secret(&var_name, &value);

                let (problem, severity) = match secret_type {
                    "placeholder" => (format!("Placeholder secret: {}", value), Severity::Low),
                    "test_secret" => (format!("Test/development secret: {}", value), Severity::Medium),
                    "production_secret" => (format!("Hardcoded production secret: {}", &value[..value.len().min(20)]), Severity::High),
                    _ => (format!("Potential hardcoded secret: {}", value), Severity::Medium),
                };

                let snippet = extract_snippet(code, info.start_byte, info.end_byte);
                findings.push(Finding {
                    rule_id: "SEC-010".to_string(),
                    severity: severity.as_str().to_string(),
                    cwe_id: Some("CWE-798".to_string()),
                    cvss_score: Some(7.5),
                    owasp_id: Some("A02:2021".to_string()),
                    start: info.start_byte,
                    end: info.end_byte,
                    snippet,
                    problem,
                    fix_hint: format!("Use env vars: {} = os.environ.get('{}')", var_name, var_name.to_uppercase()),
                    auto_fix_available: false,
                });
            }
        });

        findings.extend(self.detect_credential_formats(code));

        findings.sort_by_key(|f| f.start);
        findings.dedup_by_key(|f| f.start);
        findings
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<crate::rules::base::Fix> {
        let original = &code[finding.start..finding.end];
        Some(crate::rules::base::Fix {
            rule_id: self.id().to_string(),
            description: "Replace hardcoded secret with environment variable".to_string(),
            original: original.to_string(),
            replacement: "// TODO: Replace with os.environ.get('SECRET_NAME')".to_string(),
            start: finding.start,
            end: finding.end,
        })
    }
}

// --------------------------------------------------------------------------
// AST-based SEC-002: SQL Injection
// Walks AST to find execute() calls with string concatenation
// --------------------------------------------------------------------------

pub struct AstSqlInjectionRule;

impl AstSqlInjectionRule {
    pub fn new() -> Self {
        Self
    }
}

impl AstRule for AstSqlInjectionRule {
    fn has_ast_detection(&self) -> bool {
        true
    }
}

impl Rule for AstSqlInjectionRule {
    fn id(&self) -> &str {
        "SEC-002-AST"
    }

    fn name(&self) -> &str {
        "SQL Injection (AST-based)"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen_starts: HashSet<usize> = HashSet::new();

        // Regex pass
        let patterns = [
            r"cursor\.execute\s*\([^)]+\+",
            r"db\.execute\s*\([^)]+\+",
            r"connection\.execute\s*\([^)]+\+",
        ];

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    seen_starts.insert(m.start());
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
                        problem: "SQL query built by string concatenation - injection risk.".to_string(),
                        fix_hint: "Use parameterized queries with placeholders.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        // AST pass
        walk_tree(tree, code, |info| {
            if info.node_type == "call" {
                let text = info.text();
                let sql_patterns = ["execute", "query", "cursor"];
                let has_sql = sql_patterns.iter().any(|p| text.contains(p));

                if has_sql && !seen_starts.contains(&info.start_byte) {
                    let ctx_start = info.start_byte.saturating_sub(200);
                    let ctx_end = (info.start_byte + 200).min(code.len());
                    let context = &code[ctx_start..ctx_end];

                    let is_concat = context.contains('+') || context.contains("f\"") || context.contains("format(");
                    if is_concat {
                        let snippet = extract_snippet(code, info.start_byte, info.end_byte);
                        findings.push(Finding {
                            rule_id: "SEC-002".to_string(),
                            severity: Severity::Critical.as_str().to_string(),
                            cwe_id: Some("CWE-89".to_string()),
                            cvss_score: Some(9.9),
                            owasp_id: Some("A03:2021".to_string()),
                            start: info.start_byte,
                            end: info.end_byte,
                            snippet,
                            problem: "SQL query built by string concatenation - injection risk.".to_string(),
                            fix_hint: "Use parameterized queries with placeholders.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        });

        findings.sort_by_key(|f| f.start);
        findings.dedup_by_key(|f| f.start);
        findings
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<crate::rules::base::Fix> {
        let original = &code[finding.start..finding.end];
        Some(crate::rules::base::Fix {
            rule_id: self.id().to_string(),
            description: "Use parameterized queries to prevent SQL injection".to_string(),
            original: original.to_string(),
            replacement: "// TODO: Replace with parameterized query".to_string(),
            start: finding.start,
            end: finding.end,
        })
    }
}

// --------------------------------------------------------------------------
// Module exports
// --------------------------------------------------------------------------

pub fn all_ast_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(AstCommandInjectionRule::new()),
        Box::new(AstSqlInjectionRule::new()),
        Box::new(AstHardcodedSecretsRule::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_injection() {
        let rule = AstCommandInjectionRule::new();
        let code = "import os\nos.system(\"ls -la\")";
        let tree = crate::scanner::tree_sitter::parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.rule_id == "SEC-001"));
    }

    #[test]
    fn test_secrets_classification() {
        let (t1, _) = AstHardcodedSecretsRule::classify_secret("test_api_key", "changeme");
        assert_eq!(t1, "test_secret");

        let (t2, _) = AstHardcodedSecretsRule::classify_secret("PROD_KEY", "ghp_abcdefghijklmnopqrstuvwxyz1234567890");
        assert_eq!(t2, "production_secret");

        let (t3, _) = AstHardcodedSecretsRule::classify_secret("api_key", "changeme");
        assert_eq!(t3, "placeholder");
    }

    #[test]
    fn test_sql_injection() {
        let rule = AstSqlInjectionRule::new();
        let code = "cursor.execute(\"SELECT * FROM users WHERE id=\" + user_id)";
        let tree = crate::scanner::tree_sitter::parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.rule_id == "SEC-002"));
    }
}
