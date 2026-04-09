//! SEC-043: Missing Security Headers
use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

pub struct Sec043;

impl Rule for Sec043 {
    fn id(&self) -> &str { "SEC-043" }
    fn name(&self) -> &str { "Missing Security Headers" }
    fn severity(&self) -> Severity { Severity::Low }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"@app\.after_request\s*\n\s*def\s+add_headers[^:]*:"#, "Flask after_request without security headers"),
            (r#"response\.headers\[.*(?:X-Frame-Options|X-Content-Type-Options|Content-Security-Policy)"#, "Security header found"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-043".to_string(),
                        severity: Severity::Low.as_str().to_string(),
                        cwe_id: Some("CWE-693".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Security headers may be missing: {}", desc),
                        fix_hint: "Add security headers: X-Frame-Options, X-Content-Type-Options, CSP, HSTS, Referrer-Policy.".to_string(),
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
    let line_start = source[..start]
        .rfind('\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let line_end = source[end..]
        .find('\n')
        .map(|i| end + i)
        .unwrap_or(source.len());
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
