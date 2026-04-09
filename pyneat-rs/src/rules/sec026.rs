//! SEC-026: Insecure Temporary File
use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

pub struct Sec026;

impl Rule for Sec026 {
    fn id(&self) -> &str { "SEC-026" }
    fn name(&self) -> &str { "Insecure Temporary File" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"tempfile\.mktemp\s*\("#, "tempfile.mktemp (insecure)"),
            (r#"os\.mkstemp\s*\(\s*\)"#, "mkstemp without proper cleanup"),
            (r#"open\s*\(\s*\(.*temp.*\)"#, "Direct temp file creation"),
            (r#"NamedTemporaryFile\s*\([^)]*delete\s*=\s*False"#, "TempFile with delete=False"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-026".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-377".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Insecure temporary file usage: {}", desc),
                        fix_hint: "Use tempfile.TemporaryDirectory or NamedTemporaryFile with delete=True. Ensure proper cleanup.".to_string(),
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
