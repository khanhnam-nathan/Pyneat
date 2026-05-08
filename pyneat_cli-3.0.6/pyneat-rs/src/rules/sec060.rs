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

/// SEC-060: Autocomplete Enabled Rule
///
/// CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
pub struct AutocompleteEnabledRule;

impl Rule for AutocompleteEnabledRule {
    fn id(&self) -> &str { "SEC-060" }
    fn name(&self) -> &str { "Autocomplete Enabled on Sensitive Fields" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"<input[^>]*\btype\s*=\s*["']?(?:password|creditcard|card|cc|ssn|security)?["']?[^>]*\bautocomplete\s*=\s*["']?on["']?"#, "Password field with autocomplete enabled"),
            (r#"<input[^>]*\bautocomplete\s*=\s*["']?on["']?[^>]*\btype\s*=\s*["']?(?:password|creditcard|card|cc|ssn|security)?["']?"#, "Sensitive field with autocomplete enabled"),
            (r#"(?:PasswordInput|CreditCardField|SSNField)\s*\([^)]*autocomplete\s*=\s*['"]?on['"]?"#, "Django/Flask sensitive field with autocomplete"),
            (r#"<(?:Input|Password|CreditCard)[^>]*\bautoComplete\s*=\s*["']?(?:on|true)["']?"#, "React/Vue component with autocomplete enabled"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-060".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Autocomplete enabled on sensitive field: {}", desc),
                        fix_hint: "Add autocomplete='off' or autocomplete='new-password' to sensitive input fields.".to_string(),
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
