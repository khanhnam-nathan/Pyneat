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
