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

pub struct Sec042;

impl Rule for Sec042 {
    fn id(&self) -> &str { "SEC-042" }
    fn name(&self) -> &str { "Sensitive Data in Logs" }
    fn severity(&self) -> Severity { Severity::Low }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(?i)logging\.(info|debug|warning|error|critical)\s*\([^)]*(?:password|passwd|secret|token|api[_-]?key)\s*[^\)]*\)"#, "Logging sensitive data"),
            (r#"(?i)logger\.(info|debug|warning|error|critical)\s*\([^)]*(?:password|passwd|secret|token|api[_-]?key)\s*[^\)]*\)"#, "Logging sensitive data with logger"),
            (r#"print\s*\([^)]*(?:password|passwd|secret|token|credit_card|ssn)\s*[^\)]*\)"#, "Printing sensitive data"),
            (r#"(?i)log\.[a-z]+\s*\([^)]*(?:password|passwd|secret|token)\s*[^\)]*\)"#, "Log call with sensitive data"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-042".to_string(),
                        severity: Severity::Low.as_str().to_string(),
                        cwe_id: Some("CWE-532".to_string()),
                        cvss_score: Some(4.6),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Sensitive data logged: {}", desc),
                        fix_hint: "Use structured logging with field masking. Redact sensitive data before logging.".to_string(),
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
