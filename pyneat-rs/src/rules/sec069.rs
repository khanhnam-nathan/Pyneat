//! SEC-069: Dangerous Dependencies
//!
//! Detects potentially dangerous or outdated dependencies

use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

/// SEC-069: Dangerous Dependencies Rule
///
/// CWE-1104: Use of Unmaintained Third-Party Components
pub struct DangerousDependenciesRule;

impl Rule for DangerousDependenciesRule {
    fn id(&self) -> &str { "SEC-069" }
    fn name(&self) -> &str { "Dangerous or Outdated Dependencies" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let is_dep_file = code.contains("requirements.txt") ||
                          code.contains("setup.py") ||
                          code.contains("pyproject.toml") ||
                          code.contains("Pipfile");

        if is_dep_file {
            let dangerous_deps = [
                (r#"(?i)requests\s*[=<>~]+\s*(?:1\.|2\.[0-9]\.)"#, "Outdated requests library"),
                (r#"(?i)(?:django|flask)\s*[=<>~]+\s*[0-2]\."#, "Outdated web framework"),
                (r#"(?i)pycrypto\s*[=<>~]*"#, "PyCrypto is unmaintained, use pycryptodome"),
                (r#"(?i)(?:debug|dev)[_-]?(?:only)?\s*[=<>~]*\s*['"]?(?:pdb|ipdb|pudb)"#, "Debug package in dependencies"),
                (r#"(?i)pickle\s*[=<>~]*"#, "Pickle usage - consider json or msgpack"),
            ];

            for (pattern, desc) in &dangerous_deps {
                if let Ok(re) = regex::Regex::new(pattern) {
                    for m in re.find_iter(code) {
                        let snippet = extract_snippet(code, m.start(), m.end());
                        findings.push(Finding {
                            rule_id: "SEC-069".to_string(),
                            severity: Severity::Medium.as_str().to_string(),
                            cwe_id: Some("CWE-1104".to_string()),
                            cvss_score: Some(5.3),
                            owasp_id: Some("A06:2021".to_string()),
                            start: m.start(), end: m.end(), snippet,
                            problem: format!("Potentially dangerous dependency: {}", desc),
                            fix_hint: "Use up-to-date packages. Run 'pip list --outdated' to check.".to_string(),
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
