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

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use tree_sitter::Tree;

/// Severity levels for security findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// A finding represents a detected issue by a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Rule identifier (e.g., "SEC-001")
    pub rule_id: String,
    /// Severity level
    pub severity: String,
    /// CWE identifier
    pub cwe_id: Option<String>,
    /// CVSS base score (0.0 - 10.0)
    pub cvss_score: Option<f32>,
    /// OWASP identifier
    pub owasp_id: Option<String>,
    /// Start byte offset in source
    pub start: usize,
    /// End byte offset in source
    pub end: usize,
    /// Matched code snippet
    pub snippet: String,
    /// Problem description
    pub problem: String,
    /// Fix hint
    pub fix_hint: String,
    /// Whether auto-fix is available
    pub auto_fix_available: bool,
}

/// A fix represents a suggested change to fix a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fix {
    /// The rule that generated this fix
    pub rule_id: String,
    /// Description of the fix
    pub description: String,
    /// The original text to replace
    pub original: String,
    /// The replacement text
    pub replacement: String,
    /// Start byte offset
    pub start: usize,
    /// End byte offset
    pub end: usize,
}

/// The core Rule trait that all rules must implement.
pub trait Rule: Send + Sync {
    /// Get the unique identifier for this rule.
    fn id(&self) -> &str;

    /// Get the human-readable name for this rule.
    fn name(&self) -> &str;

    /// Get the severity level for this rule.
    fn severity(&self) -> Severity;

    /// Detect issues in the given code.
    ///
    /// Returns a list of findings sorted by position in the source.
    fn detect(&self, tree: &Tree, code: &str) -> Vec<Finding>;

    /// Apply fixes for a specific finding.
    ///
    /// Returns `None` if auto-fix is not available for this finding.
    fn fix(&self, finding: &Finding, code: &str) -> Option<Fix>;

    /// Check if this rule supports auto-fix.
    fn supports_auto_fix(&self) -> bool {
        false
    }

    /// Check if this rule is enabled by default.
    fn enabled_by_default(&self) -> bool {
        true
    }
}

/// Extension trait for iterating over rules.
pub trait RuleRegistry {
    fn get_rule(&self, id: &str) -> Option<&dyn Rule>;
    fn all_rules(&self) -> Vec<&dyn Rule>;
}

/// Extract a code snippet bounded by byte offsets, returning up to 3 lines of context.
///
/// Finds the line containing `start`, the line containing `end`, and up to
/// one line of context before for better readability in security reports.
#[inline]
pub fn extract_snippet(source: &str, start: usize, end: usize) -> String {
    let line_start = source[..start]
        .rfind('\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let line_end = source[end..]
        .find('\n')
        .map(|i| end + i)
        .unwrap_or(source.len());
    let context_before = if line_start > 0 {
        source[..line_start - 1]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0)
    } else {
        line_start
    };
    let snippet = &source[context_before..line_end];
    snippet.lines().take(3).collect::<Vec<_>>().join("\n")
}
