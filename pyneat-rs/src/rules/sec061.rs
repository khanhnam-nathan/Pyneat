//! SEC-061: Missing Subresource Integrity (SRI)
//!
//! Detects when external scripts/stylesheets are loaded without integrity check

use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

/// SEC-061: Missing SRI Rule
///
/// CWE-345: Insufficient Verification of Data Authenticity
pub struct MissingSriRule;

impl Rule for MissingSriRule {
    fn id(&self) -> &str { "SEC-061" }
    fn name(&self) -> &str { "Missing Subresource Integrity (SRI)" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let external_script_pattern = r#"<script\s+[^>]*\bsrc\s*=\s*["']https?://[^"']+["'][^>]*>"#;
        let integrity_pattern = r#"integrity\s*="#;

        if let Ok(script_re) = regex::Regex::new(external_script_pattern) {
            if let Ok(int_re) = regex::Regex::new(integrity_pattern) {
                for m in script_re.find_iter(code) {
                    let matched = m.as_str();
                    if !int_re.is_match(matched) && !matched.contains("localhost") && !matched.contains("127.0.0.1") {
                        let snippet = extract_snippet(code, m.start(), m.end());
                        findings.push(Finding {
                            rule_id: "SEC-061".to_string(),
                            severity: Severity::Medium.as_str().to_string(),
                            cwe_id: Some("CWE-345".to_string()),
                            cvss_score: Some(6.5),
                            owasp_id: Some("A05:2021".to_string()),
                            start: m.start(), end: m.end(), snippet,
                            problem: "External script loaded without Subresource Integrity (SRI)".to_string(),
                            fix_hint: "Add integrity and crossorigin attributes to external scripts.".to_string(),
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
