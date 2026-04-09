//! SEC-025: Time-of-Check Time-of-Use (TOCTOU)
use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

pub struct Sec025;

impl Rule for Sec025 {
    fn id(&self) -> &str { "SEC-025" }
    fn name(&self) -> &str { "Time-of-Check Time-of-Use (TOCTOU)" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"os\.path\.exists\s*\(.*\)\s*:\s*\n\s*.*open\s*\("#, "Check file exists before open"),
            (r#"if\s+.*:\s*\n\s*.*os\.chmod\s*\("#, "Check permission before chmod"),
            (r#"if\s+.*:\s*\n\s*.*os\.rename\s*\("#, "Check before rename"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-025".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-367".to_string()),
                        cvss_score: Some(6.3),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Potential TOCTOU vulnerability: {}", desc),
                        fix_hint: "Use atomic operations. Check and use in the same operation. Use file locking.".to_string(),
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
