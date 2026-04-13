//! Base rule trait and types.
//!
//! Defines the core `Rule` trait that all rules must implement.

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
