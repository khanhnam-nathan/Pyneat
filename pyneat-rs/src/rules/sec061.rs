//! SEC-061: Missing Subresource Integrity (SRI)
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
//!
//! Detects when external scripts/stylesheets are loaded without integrity check

use crate::rules::base::{extract_snippet, Fix, Finding, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;
use tree_sitter::Tree;

/// SEC-061: Missing SRI Rule
///
/// CWE-345: Insufficient Verification of Data Authenticity
static EXTERNAL_SCRIPT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<script\s+[^>]*\bsrc\s*=\s*["']https?://[^"']+["'][^>]*>"#).unwrap()
});
static INTEGRITY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"integrity\s*="#).unwrap()
});

pub struct MissingSriRule;

impl Rule for MissingSriRule {
    fn id(&self) -> &str { "SEC-061" }
    fn name(&self) -> &str { "Missing Subresource Integrity (SRI)" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for m in EXTERNAL_SCRIPT_RE.find_iter(code) {
            let matched = m.as_str();
            if !INTEGRITY_RE.is_match(matched) && !matched.contains("localhost") && !matched.contains("127.0.0.1") {
                let snippet = extract_snippet(code, m.start(), m.end());
                findings.push(Finding {
                    rule_id: "SEC-061".to_string(),
                    severity: Severity::Medium.as_str().to_string(),
                    cwe_id: Some("CWE-345".to_string()),
                    cvss_score: Some(6.5),
                    owasp_id: Some("A05:2021".to_string()),
                    start: m.start(), end: m.end(), snippet,
                    problem: "External script loaded without Subresource Integrity (SRI)".to_string(),
                    fix_hint: "Add integrity and crossorigin attributes to external scripts.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}
