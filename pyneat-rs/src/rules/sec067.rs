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

/// SEC-067: Weak Server-side Validation Rule
///
/// CWE-20: Improper Input Validation
pub struct WeakServerValidationRule;

impl Rule for WeakServerValidationRule {
    fn id(&self) -> &str { "SEC-067" }
    fn name(&self) -> &str { "Weak Server-side Validation" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let client_only_patterns = [
            (r#"(?i)<script[^>]*>[\s\S]{0,500}(?:password|passwd).*?(?:regex|pattern|minlength|maxlength)[\s\S]{0,500}</script>"#, "Client-side password validation without server check"),
            (r#"(?i)(?:onsubmit|submit)\s*=\s*['"]?return\s+validate"#, "Form validation without server-side counterpart"),
            (r#"<input[^>]*\bpattern\s*=\s*['\"][^'\"]+['\"][^>]*>"#, "HTML5 pattern validation without server validation"),
        ];

        let has_server_validation = [
            r"(?i)(?:request\.validate|validate_input|sanitize|clean_input)",
            r"(?i)(?:form\.is_valid|validate\()",
        ];

        let server_validation_found = has_server_validation.iter().any(|p| {
            regex::Regex::new(p).map(|re| re.is_match(code)).unwrap_or(false)
        });

        for (pattern, desc) in &client_only_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    if !server_validation_found {
                        let snippet = extract_snippet(code, m.start(), m.end());
                        findings.push(Finding {
                            rule_id: "SEC-067".to_string(),
                            severity: Severity::High.as_str().to_string(),
                            cwe_id: Some("CWE-20".to_string()),
                            cvss_score: Some(7.5),
                            owasp_id: Some("A01:2021".to_string()),
                            start: m.start(), end: m.end(), snippet,
                            problem: format!("Client-side validation only: {}", desc),
                            fix_hint: "Always validate input server-side. Client-side validation can be bypassed.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings.dedup_by(|a, b| a.start == b.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}
