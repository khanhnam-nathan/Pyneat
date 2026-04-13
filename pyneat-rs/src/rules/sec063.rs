//! SEC-063: Missing Rate Limiting
//!
//! Detects endpoints that handle sensitive operations without rate limiting

use crate::rules::base::{Fix, Finding, Rule, Severity};
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

fn extract_snippet(source: &str, start: usize, end: usize) -> String {
    let line_start = source[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = source[end..].find('\n').map(|i| end + i).unwrap_or(source.len());
    let context_before = if line_start > 0 {
        source[..line_start - 1].rfind('\n').map(|i| i + 1).unwrap_or(0)
    } else {
        line_start
    };
    let snippet = &source[context_before..line_end];
    snippet.lines().take(3).collect::<Vec<_>>().join("\n")
}
