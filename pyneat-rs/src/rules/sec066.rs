//! SEC-066: Timing Attack Vulnerability
//!
//! Detects string comparison that could be vulnerable to timing attacks

use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

/// SEC-066: Timing Attack Vulnerability Rule
///
/// CWE-208: Observable Timing Discrepancy
pub struct TimingAttackRule;

impl Rule for TimingAttackRule {
    fn id(&self) -> &str { "SEC-066" }
    fn name(&self) -> &str { "Timing Attack Vulnerability" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let vulnerable_patterns = [
            (r#"(?i)(?:token|api_key|password|secret|auth)\s*[=:]\s*[^;]+(?!hmac\.compare|secrets\.compare|timing_safe)"#, "Direct comparison of sensitive data"),
            (r#"(?i)==\s*(?:token|api_key|password|secret|auth|key)"#, "Direct equality check on sensitive value"),
        ];

        for (pattern, desc) in &vulnerable_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let matched = m.as_str();
                    if !matched.contains("hmac.compare") && !matched.contains("secrets.compare") &&
                       !matched.contains("timing_safe") && !matched.contains("compare_digest") {
                        let snippet = extract_snippet(code, m.start(), m.end());
                        findings.push(Finding {
                            rule_id: "SEC-066".to_string(),
                            severity: Severity::Medium.as_str().to_string(),
                            cwe_id: Some("CWE-208".to_string()),
                            cvss_score: Some(5.3),
                            owasp_id: Some("A02:2021".to_string()),
                            start: m.start(), end: m.end(), snippet,
                            problem: format!("Potential timing attack vulnerability: {}", desc),
                            fix_hint: "Use timing-safe comparison: hmac.compare_digest(a, b) or secrets.compare_digest(a, b).".to_string(),
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
