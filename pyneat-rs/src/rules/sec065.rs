//! SEC-065: Insecure Logout
//!
//! Detects when session is not properly destroyed on logout

use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

/// SEC-065: Insecure Logout Rule
///
/// CWE-613: Insufficient Session Expiration
pub struct InsecureLogoutRule;

impl Rule for InsecureLogoutRule {
    fn id(&self) -> &str { "SEC-065" }
    fn name(&self) -> &str { "Incomplete Session Destruction on Logout" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let logout_patterns = [
            (r#"(?i)(?:def|async\s+def)\s+(?:logout|signout)\s*\([^)]*\)\s*:\s*(?![\s\S]{0,500}(?:session\.pop|delete|flush|destroy|clear|invalidate))"#, "Logout function missing session destruction"),
            (r#"(?i)response\.delete_cookie\([^)]+\)(?![\s\S]{0,200}(?:session|delete|flush|destroy|clear))"#, "Cookie deletion without server-side session destruction"),
        ];

        for (pattern, desc) in &logout_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-065".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-613".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A07:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Insecure logout pattern: {}", desc),
                        fix_hint: "Properly destroy session server-side: session.flush(), session.delete(), or session.invalidate().".to_string(),
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
