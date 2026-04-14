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

pub struct Sec044;

impl Rule for Sec044 {
    fn id(&self) -> &str { "SEC-044" }
    fn name(&self) -> &str { "EXIF Data in Uploads" }
    fn severity(&self) -> Severity { Severity::Low }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(?i)Image\.open\s*\([^)]*\)\s*[^.]*\.save\s*\("#, "Image save without EXIF stripping"),
            (r#"PIL\.Image\.open\s*\([^)]*\)\s*[^.]*\.save\s*\("#, "PIL image save without EXIF stripping"),
            (r#"(?i)\.getexif\s*\(\s*\)"#, "Getting EXIF data"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-044".to_string(),
                        severity: Severity::Low.as_str().to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        cvss_score: Some(4.6),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("EXIF data handling: {}", desc),
                        fix_hint: "Strip EXIF metadata from uploaded images using PIL or similar library before saving.".to_string(),
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
