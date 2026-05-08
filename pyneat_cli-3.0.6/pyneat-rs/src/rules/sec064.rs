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

/// SEC-064: Weak JWT Secret Rule
///
/// CWE-344: Use of Evidence Derived from Attack Vector
pub struct WeakJwtSecretRule;

impl Rule for WeakJwtSecretRule {
    fn id(&self) -> &str { "SEC-064" }
    fn name(&self) -> &str { "Weak JWT Secret Key" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let patterns = [
            (r#"(?i)(?:JWT_SECRET|JWT_KEY|SECRET_KEY|APP_SECRET)\s*[=:]\s*['"](?:secret|secret_key|123456|password|admin|changeme|your-secret|my-secret)['"]"#, "Hardcoded weak JWT secret"),
            (r#"jwt\.encode\([^)]*,\s*['"][a-zA-Z0-9_\-]{1,50}['"]"#, "JWT encode with hardcoded short secret"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-064".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-344".to_string()),
                        cvss_score: Some(9.1),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Weak or hardcoded JWT secret: {}", desc),
                        fix_hint: "Use cryptographically strong secret (256+ bits) from environment variables.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings.dedup_by(|a, b| a.start == b.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}
