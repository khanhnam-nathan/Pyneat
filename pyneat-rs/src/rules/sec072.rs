//! SEC-072: Missing CSP Nonce
//!
//! Detects Content-Security-Policy without nonce for inline scripts

use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

/// SEC-072: Missing CSP Nonce Rule
///
/// CWE-1021: Improper Restriction of Rendered UI Layers
pub struct MissingCspNonceRule;

impl Rule for MissingCspNonceRule {
    fn id(&self) -> &str { "SEC-072" }
    fn name(&self) -> &str { "Missing CSP Nonce for Inline Scripts" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let inline_script_pattern = r#"<script[^>]*>(?![\s\S]*?nonce[\s\S]*?</script>)"#;
        let csp_pattern = r#"Content-Security-Policy[^;]*script-src[^;]*"#;

        if let Ok(script_re) = regex::Regex::new(inline_script_pattern) {
            if let Ok(csp_re) = regex::Regex::new(csp_pattern) {
                let has_csp = csp_re.is_match(code);
                let has_nonce = code.contains("nonce");

                for m in script_re.find_iter(code) {
                    let matched = m.as_str();
                    if !matched.contains("src=") && has_csp && !has_nonce {
                        let snippet = extract_snippet(code, m.start(), m.end());
                        findings.push(Finding {
                            rule_id: "SEC-072".to_string(),
                            severity: Severity::Medium.as_str().to_string(),
                            cwe_id: Some("CWE-1021".to_string()),
                            cvss_score: Some(5.3),
                            owasp_id: Some("A05:2021".to_string()),
                            start: m.start(), end: m.end(), snippet,
                            problem: "Inline script with CSP but without nonce protection".to_string(),
                            fix_hint: "Add nonce to CSP: Content-Security-Policy: script-src 'nonce-{RANDOM}'.".to_string(),
                            auto_fix_available: false,
                        });
                    }
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
