//! SEC-042: Sensitive Data in Logs Rule
use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

pub struct Sec042;

impl Rule for Sec042 {
    fn id(&self) -> &str { "SEC-042" }
    fn name(&self) -> &str { "Sensitive Data in Logs" }
    fn severity(&self) -> Severity { Severity::Low }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(?i)logging\.(info|debug|warning|error|critical)\s*\([^)]*(?:password|passwd|secret|token|api[_-]?key)\s*[^\)]*\)"#, "Logging sensitive data"),
            (r#"(?i)logger\.(info|debug|warning|error|critical)\s*\([^)]*(?:password|passwd|secret|token|api[_-]?key)\s*[^\)]*\)"#, "Logging sensitive data with logger"),
            (r#"print\s*\([^)]*(?:password|passwd|secret|token|credit_card|ssn)\s*[^\)]*\)"#, "Printing sensitive data"),
            (r#"(?i)log\.[a-z]+\s*\([^)]*(?:password|passwd|secret|token)\s*[^\)]*\)"#, "Log call with sensitive data"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-042".to_string(),
                        severity: Severity::Low.as_str().to_string(),
                        cwe_id: Some("CWE-532".to_string()),
                        cvss_score: Some(4.6),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Sensitive data logged: {}", desc),
                        fix_hint: "Use structured logging with field masking. Redact sensitive data before logging.".to_string(),
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
