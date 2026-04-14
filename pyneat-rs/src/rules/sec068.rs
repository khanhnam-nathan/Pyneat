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

/// SEC-068: Frontend Price Manipulation Rule
///
/// CWE-641: Improper Restriction of Names or Values
pub struct FrontendPriceManipulationRule;

impl Rule for FrontendPriceManipulationRule {
    fn id(&self) -> &str { "SEC-068" }
    fn name(&self) -> &str { "Client-side Price Calculation Sent to Server" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let patterns = [
            (r#"(?i)(?:price|total|amount|subtotal)\s*=\s*(?:parseFloat|parseInt|\$)\s*\([^)]*\)[^;]*\.(?:post|send|fetch|ajax|axios)"#, "Client-side price sent to server"),
            (r#"(?i)(?:post|send|fetch)\s*\([^)]*(?:price|total|amount)\s*[^)]*\)"#, "Price data sent via AJAX"),
            (r#"(?i)<input[^>]*\btype\s*=\s*["']?hidden["']?[^>]*\b(?:price|total|amount)"#, "Hidden price field that could be manipulated"),
            (r#"(?i)request\.form\.get\(['"](?:price|total|amount|subtotal)"#, "Server receiving pre-calculated price from client"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-068".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-641".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A04:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Client-side price calculation detected: {}", desc),
                        fix_hint: "Calculate prices server-side only. Never trust client-submitted prices.".to_string(),
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
