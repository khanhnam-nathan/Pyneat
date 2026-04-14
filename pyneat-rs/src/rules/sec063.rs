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

/// SEC-063: Missing Rate Limiting Rule
///
/// CWE-307: Improper Restriction of Excessive Authentication Attempts
pub struct MissingRateLimitingRule;

impl Rule for MissingRateLimitingRule {
    fn id(&self) -> &str { "SEC-063" }
    fn name(&self) -> &str { "Missing Rate Limiting on Sensitive Endpoints" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let sensitive_endpoints = [
            (r#"(?i)@app\.route\(['"/](?:login|signin|auth/authenticate)['"]"#, "Login endpoint"),
            (r#"(?i)@app\.route\(['"/](?:register|signup|create-account)['"]"#, "Registration endpoint"),
            (r#"(?i)@app\.route\(['"/](?:password/reset|forgot|recover)['"]"#, "Password reset endpoint"),
            (r#"(?i)@app\.route\(['"/](?:otp|2fa|two-factor|verify-code)['"]"#, "OTP/2FA endpoint"),
        ];

        let rate_limit_patterns = [
            r"(?i)@rate_limit",
            r"(?i)rate_limit",
            r"(?i)limiter\.limit",
            r"(?i)throttle",
        ];

        let has_rate_limit = rate_limit_patterns.iter().any(|p| {
            regex::Regex::new(p).map(|re| re.is_match(code)).unwrap_or(false)
        });

        for (endpoint_pattern, endpoint_name) in &sensitive_endpoints {
            if let Ok(re) = regex::Regex::new(endpoint_pattern) {
                for m in re.find_iter(code) {
                    if !has_rate_limit {
                        let snippet = extract_snippet(code, m.start(), m.end());
                        findings.push(Finding {
                            rule_id: "SEC-063".to_string(),
                            severity: Severity::Medium.as_str().to_string(),
                            cwe_id: Some("CWE-307".to_string()),
                            cvss_score: Some(5.3),
                            owasp_id: Some("A07:2021".to_string()),
                            start: m.start(), end: m.end(), snippet,
                            problem: format!("Sensitive endpoint '{}' without rate limiting protection", endpoint_name),
                            fix_hint: "Add rate limiting using @rate_limit decorator or flask-limiter middleware.".to_string(),
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
