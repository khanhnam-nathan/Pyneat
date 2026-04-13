//! SEC-064: Weak JWT Secret
//!
//! Detects hardcoded weak secrets used for JWT signing

use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

/// SEC-064: Weak JWT Secret Rule
///
/// CWE-344: Use of Evidence Derived from Attack Vector
pub struct WeakJwtSecretRule;

impl Rule for WeakJwtSecretRule {
    fn id(&self) -> &str { "SEC-064" }
    fn name(&self) -> &str { "Weak JWT Secret Key" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let patterns = [
            (r#"(?i)(?:JWT_SECRET|JWT_KEY|SECRET_KEY|APP_SECRET)\s*[=:]\s*['"](?:secret|secret_key|123456|password|admin|changeme|your-secret|my-secret)['"]"#, "Hardcoded weak JWT secret"),
            (r#"jwt\.encode\([^)]*,\s*['"][a-zA-Z0-9_\-]{1,50}['"]"#, "JWT encode with hardcoded short secret"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-064".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-344".to_string()),
                        cvss_score: Some(9.1),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Weak or hardcoded JWT secret: {}", desc),
                        fix_hint: "Use cryptographically strong secret (256+ bits) from environment variables.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings.dedup_by(|a, b| a.start == b.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

fn extract_snippet(source: &str, start: usize, end: usize) -> String {
    let line_start = source[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = source[end..].find('\n').map(|i| end + i).unwrap_or(source.len());
    let context_before = if line_start > 0 {
        source[..line_start - 1].rfind('\n').map(|i| i + 1).unwrap_or(0)
    } else {
        line_start
    };
    let snippet = &source[context_before..line_end];
    snippet.lines().take(3).collect::<Vec<_>>().join("\n")
}
