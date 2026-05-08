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

/// SEC-062: Missing Content-Type Validation Rule
///
/// CWE-434: Unrestricted Upload of File with Dangerous Type
pub struct MissingContentTypeValidationRule;

impl Rule for MissingContentTypeValidationRule {
    fn id(&self) -> &str { "SEC-062" }
    fn name(&self) -> &str { "Missing Content-Type Validation" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let patterns = [
            (r#"(?i)(?:file|request)\.files\.get\([^)]+\)[^;]*;"#, "Flask file upload without Content-Type check"),
            (r#"(?i)(?:save|write|upload)\s*\([^)]*\bfile\b[^)]*\)(?![\s\S]{0,200}(?:content_type|content-type|mimetype))"#, "File operation without Content-Type validation"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-062".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-434".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A04:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("File upload without proper Content-Type validation: {}", desc),
                        fix_hint: "Always validate Content-Type header server-side. Use python-magic for actual file type detection.".to_string(),
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
