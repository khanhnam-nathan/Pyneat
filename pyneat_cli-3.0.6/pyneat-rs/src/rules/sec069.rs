//! PyNeat Rust Security Scanner
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU Affero General Public License as published
//! by the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//! GNU Affero General Public License for more details.
//!
//! You should have received a copy of the GNU Affero General Public License
//! along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::rules::base::{extract_snippet, Fix, Finding, Rule, Severity};
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
