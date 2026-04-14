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

/// SEC-072: Missing CSP Nonce Rule
///
/// CWE-1021: Improper Restriction of Rendered UI Layers
pub struct MissingCspNonceRule;

impl Rule for MissingCspNonceRule {
    fn id(&self) -> &str { "SEC-072" }
    fn name(&self) -> &str { "Missing CSP Nonce for Inline Scripts" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let inline_script_pattern = r#"<script[^>]*>(?![\s\S]*?nonce[\s\S]*?</script>)"#;
        let csp_pattern = r#"Content-Security-Policy[^;]*script-src[^;]*"#;

        if let Ok(script_re) = regex::Regex::new(inline_script_pattern) {
            if let Ok(csp_re) = regex::Regex::new(csp_pattern) {
                let has_csp = csp_re.is_match(code);
                let has_nonce = code.contains("nonce");

                for m in script_re.find_iter(code) {
                    let matched = m.as_str();
                    if !matched.contains("src=") && has_csp && !has_nonce {
                        let snippet = extract_snippet(code, m.start(), m.end());
                        findings.push(Finding {
                            rule_id: "SEC-072".to_string(),
                            severity: Severity::Medium.as_str().to_string(),
                            cwe_id: Some("CWE-1021".to_string()),
                            cvss_score: Some(5.3),
                            owasp_id: Some("A05:2021".to_string()),
                            start: m.start(), end: m.end(), snippet,
                            problem: "Inline script with CSP but without nonce protection".to_string(),
                            fix_hint: "Add nonce to CSP: Content-Security-Policy: script-src 'nonce-{RANDOM}'.".to_string(),
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
