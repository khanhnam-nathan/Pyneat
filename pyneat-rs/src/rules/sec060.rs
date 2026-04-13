//! SEC-060: Autocomplete Enabled on Sensitive Forms
//!
//! Detects when autocomplete attribute is enabled on sensitive form fields

use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

/// SEC-060: Autocomplete Enabled Rule
///
/// CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
pub struct AutocompleteEnabledRule;

impl Rule for AutocompleteEnabledRule {
    fn id(&self) -> &str { "SEC-060" }
    fn name(&self) -> &str { "Autocomplete Enabled on Sensitive Fields" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"<input[^>]*\btype\s*=\s*["']?(?:password|creditcard|card|cc|ssn|security)?["']?[^>]*\bautocomplete\s*=\s*["']?on["']?"#, "Password field with autocomplete enabled"),
            (r#"<input[^>]*\bautocomplete\s*=\s*["']?on["']?[^>]*\btype\s*=\s*["']?(?:password|creditcard|card|cc|ssn|security)?["']?"#, "Sensitive field with autocomplete enabled"),
            (r#"(?:PasswordInput|CreditCardField|SSNField)\s*\([^)]*autocomplete\s*=\s*['"]?on['"]?"#, "Django/Flask sensitive field with autocomplete"),
            (r#"<(?:Input|Password|CreditCard)[^>]*\bautoComplete\s*=\s*["']?(?:on|true)["']?"#, "React/Vue component with autocomplete enabled"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-060".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Autocomplete enabled on sensitive field: {}", desc),
                        fix_hint: "Add autocomplete='off' or autocomplete='new-password' to sensitive input fields.".to_string(),
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

/// Extract snippet helper
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
