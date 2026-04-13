//! SEC-071: Sensitive Data in JWT
//!
//! Detects sensitive data stored in JWT payload

use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

/// SEC-071: Weak JWT Payload Rule
///
/// CWE-315: Cleartext Storage of Sensitive Data
pub struct WeakJwtPayloadRule;

impl Rule for WeakJwtPayloadRule {
    fn id(&self) -> &str { "SEC-071" }
    fn name(&self) -> &str { "Sensitive Data in JWT Payload" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let patterns = [
            (r#"(?i)jwt\.encode\s*\(\s*\{[^}]*(?:password|passwd|secret|ssn|credit|card)"#, "JWT payload contains sensitive data"),
            (r#"(?i)\{[^{}]*['\"]?(?:password|secret|credit_card|ssn|token|api_key)['\"]?\s*:"#, "JWT payload structure contains sensitive field"),
            (r#"(?i)(?:localStorage|sessionStorage)\.(?:setItem|getItem)\([^)]*(?:token|jwt)"#, "JWT stored in web storage"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-071".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-315".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Sensitive data in JWT: {}", desc),
                        fix_hint: "JWT is only Base64 encoded, not encrypted. Never store sensitive data in JWT payload.".to_string(),
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
