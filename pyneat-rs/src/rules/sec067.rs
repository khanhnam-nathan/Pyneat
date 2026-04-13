//! SEC-067: Weak Server-side Validation
//!
//! Detects when input validation is only done client-side

use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

/// SEC-067: Weak Server-side Validation Rule
///
/// CWE-20: Improper Input Validation
pub struct WeakServerValidationRule;

impl Rule for WeakServerValidationRule {
    fn id(&self) -> &str { "SEC-067" }
    fn name(&self) -> &str { "Weak Server-side Validation" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let client_only_patterns = [
            (r#"(?i)<script[^>]*>[\s\S]{0,500}(?:password|passwd).*?(?:regex|pattern|minlength|maxlength)[\s\S]{0,500}</script>"#, "Client-side password validation without server check"),
            (r#"(?i)(?:onsubmit|submit)\s*=\s*['"]?return\s+validate"#, "Form validation without server-side counterpart"),
            (r#"<input[^>]*\bpattern\s*=\s*['\"][^'\"]+['\"][^>]*>"#, "HTML5 pattern validation without server validation"),
        ];

        let has_server_validation = [
            r"(?i)(?:request\.validate|validate_input|sanitize|clean_input)",
            r"(?i)(?:form\.is_valid|validate\()",
        ];

        let server_validation_found = has_server_validation.iter().any(|p| {
            regex::Regex::new(p).map(|re| re.is_match(code)).unwrap_or(false)
        });

        for (pattern, desc) in &client_only_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    if !server_validation_found {
                        let snippet = extract_snippet(code, m.start(), m.end());
                        findings.push(Finding {
                            rule_id: "SEC-067".to_string(),
                            severity: Severity::High.as_str().to_string(),
                            cwe_id: Some("CWE-20".to_string()),
                            cvss_score: Some(7.5),
                            owasp_id: Some("A01:2021".to_string()),
                            start: m.start(), end: m.end(), snippet,
                            problem: format!("Client-side validation only: {}", desc),
                            fix_hint: "Always validate input server-side. Client-side validation can be bypassed.".to_string(),
                            auto_fix_available: false,
                        });
                    }
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
