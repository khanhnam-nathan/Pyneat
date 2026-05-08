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
