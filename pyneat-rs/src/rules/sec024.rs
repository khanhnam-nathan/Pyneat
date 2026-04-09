//! SEC-024: Mass Assignment Rule
use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

pub struct Sec024;

impl Rule for Sec024 {
    fn id(&self) -> &str { "SEC-024" }
    fn name(&self) -> &str { "Mass Assignment" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(User|Model|Object)\s*\(.*\*\*request\."#, "Model instantiation with request dict"),
            (r#"\.update\s*\(\s*\*\*.*{"#, "Update with unpacked dict"),
            (r#"\.\s*create\s*\([^)]*\*\*{"#, "Create with kwargs from user"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-024".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-915".to_string()),
                        cvss_score: Some(6.5),
                        owasp_id: Some("A04:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Potential mass assignment: {}", desc),
                        fix_hint: "Use explicit field assignment instead of passing request data directly. Whitelist allowed fields.".to_string(),
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
