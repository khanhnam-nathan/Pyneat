//! Unified Findings Deduplication
//!
//! This module provides cross-layer deduplication and merging for all finding types:
//! - Security rules (LangFinding)
//! - Taint analysis (TaintFinding)
//! - AI security (legacy regex + AST-aware)
//! - Enterprise compliance
//!
//! Key insight: the same vulnerability can be detected by multiple layers.
//! Without deduplication, users see duplicate findings for the same issue.
//!
//! Deduplication strategy:
//! 1. Canonical key = (rule_id_category, line, snippet_hash)
//!    - rule_id_category: strips numeric suffix so "SEC-001" and "RUST-SEC-001" don't conflict
//! 2. Severity merge: highest severity wins when duplicates exist
//! 3. Rule source tracking: keep track of all layers that detected this finding

use std::collections::HashMap;

use crate::scanner::taint::engine::TaintFinding;
use crate::scanner::taint::labels::TaintLabel;
use crate::ai_security::{AiFinding, AstAiFinding};

#[derive(Debug, Clone)]
pub struct UnifiedFinding {
    /// Primary rule ID (the one with highest severity/priority)
    pub primary_rule_id: String,
    /// All rule IDs that detected this same finding
    pub detected_by: Vec<String>,
    pub severity: String,
    pub line: usize,
    pub end_line: usize,
    pub column: usize,
    pub snippet: String,
    pub problem: String,
    pub fix_hint: String,
    pub can_auto_fix: bool,
    pub confidence: f32,
    pub cwe_id: Option<String>,
    pub cvss_score: Option<f32>,
    pub file_path: Option<String>,
    /// Taint labels associated with this finding
    pub taint_labels: Vec<String>,
    /// Whether this came from AST-aware analysis
    pub ast_aware: bool,
    /// Raw finding types that contributed
    pub sources: Vec<FindingSource>,
}

#[derive(Debug, Clone)]
pub enum FindingSource {
    Security(String),
    Taint(String),
    AiLegacy(String),
    AiAst(String),
    Enterprise(String),
}

impl UnifiedFinding {
    fn new(rule_id: &str, severity: &str, line: usize) -> Self {
        Self {
            primary_rule_id: rule_id.to_string(),
            detected_by: vec![rule_id.to_string()],
            severity: severity.to_string(),
            line,
            end_line: line,
            column: 0,
            snippet: String::new(),
            problem: String::new(),
            fix_hint: String::new(),
            can_auto_fix: false,
            confidence: 0.0,
            cwe_id: None,
            cvss_score: None,
            file_path: None,
            taint_labels: Vec::new(),
            ast_aware: false,
            sources: Vec::new(),
        }
    }

    /// Canonical key for deduplication: strips numeric suffix so
    /// "SEC-001" and "RUST-SEC-001" map to the same category
    fn category_key(rule_id: &str) -> String {
        // Strip common prefixes and numeric suffixes
        let lower = rule_id.to_lowercase();
        if lower.starts_with("ai-") {
            "ai".to_string()
        } else if lower.starts_with("taint-") {
            "taint".to_string()
        } else if lower.starts_with("sec-") || lower.starts_with("rust-sec-")
            || lower.starts_with("py-sec-") || lower.contains("injection")
            || lower.contains("xss") || lower.contains("sqli") || lower.contains("ssrf")
            || lower.contains("cmd") || lower.contains("path")
        {
            "security".to_string()
        } else if lower.starts_with("rust-") || lower.starts_with("py-") {
            rule_id.split('-').take(2).collect::<Vec<_>>().join("-")
        } else {
            rule_id.to_string()
        }
    }

    /// Build a deduplication key
    fn dedup_key(rule_id: &str, line: usize, snippet: &str) -> String {
        let cat = Self::category_key(rule_id);
        let snippet_hash = if snippet.is_empty() {
            "empty".to_string()
        } else {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            snippet.hash(&mut h);
            format!("{:016x}", h.finish())[..8].to_string()
        };
        format!("{}:{}:{}", cat, line, snippet_hash)
    }
}

// --------------------------------------------------------------------------
// Deduplicator
// --------------------------------------------------------------------------

pub struct FindingsDeduplicator {
    findings: Vec<UnifiedFinding>,
    seen_keys: HashMap<String, usize>,
}

impl Default for FindingsDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingsDeduplicator {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            seen_keys: HashMap::new(),
        }
    }

    /// Add a taint finding to the deduplicator
    pub fn add_taint(&mut self, f: &TaintFinding) {
        let key = UnifiedFinding::dedup_key(&f.rule_id, f.line, &f.snippet);
        self.merge_or_insert(key, f.rule_id.clone(), f.severity.clone(),
            f.line, f.snippet.clone(), f.problem.clone(), None,
            FindingSource::Taint(f.rule_id.clone()), Some(f.labels.clone()));
    }

    /// Add a legacy AI finding
    pub fn add_ai_legacy(&mut self, f: &AiFinding, _file_path: Option<String>) {
        let key = UnifiedFinding::dedup_key(&f.rule_id, f.line, &f.snippet);
        self.merge_or_insert(
            key, f.rule_id.clone(), f.severity.clone(),
            f.line, f.snippet.clone(), f.problem.clone(),
            Some(f.fix_hint.clone()),
            FindingSource::AiLegacy(f.rule_id.clone()), None
        );
    }

    /// Add an AST-aware AI finding
    pub fn add_ai_ast(&mut self, f: &AstAiFinding) {
        let key = UnifiedFinding::dedup_key(&f.rule_id, f.line, &f.snippet);
        let source = FindingSource::AiAst(f.rule_id.clone());
        self.merge_or_insert(
            key, f.rule_id.clone(), f.severity.clone(),
            f.line, f.snippet.clone(), f.problem.clone(),
            Some(f.fix_hint.clone()),
            source, None
        );
    }

    /// Add a security rule finding (generic)
    pub fn add_security(&mut self, rule_id: &str, severity: &str, line: usize,
                        snippet: &str, problem: &str, fix_hint: Option<&str>) {
        let key = UnifiedFinding::dedup_key(rule_id, line, snippet);
        self.merge_or_insert(
            key, rule_id.to_string(), severity.to_string(),
            line, snippet.to_string(), problem.to_string(),
            fix_hint.map(|s| s.to_string()),
            FindingSource::Security(rule_id.to_string()), None
        );
    }

    /// Add an enterprise compliance finding
    pub fn add_enterprise(&mut self, f: &crate::scanner::base::LangFinding) {
        let key = UnifiedFinding::dedup_key(&f.rule_id, f.line, &f.snippet);
        self.merge_or_insert(
            key, f.rule_id.clone(), f.severity.clone(),
            f.line, f.snippet.clone(), f.problem.clone(),
            Some(f.fix_hint.clone()),
            FindingSource::Enterprise(f.rule_id.clone()), None
        );
    }

    /// Merge into existing or insert new
    fn merge_or_insert(&mut self, key: String, rule_id: String, severity: String,
                       line: usize, snippet: String, problem: String,
                       fix_hint: Option<String>,
                       source: FindingSource,
                       taint_labels: Option<Vec<TaintLabel>>) {
        let sev_order = |s: &str| -> i32 {
            match s {
                "critical" => 5,
                "high" => 4,
                "medium" => 3,
                "low" => 2,
                _ => 1,
            }
        };

        if let Some(&idx) = self.seen_keys.get(&key) {
            // Merge: keep higher severity, accumulate detected_by
            let existing = &mut self.findings[idx];
            if sev_order(&severity) > sev_order(&existing.severity) {
                existing.severity = severity;
                existing.primary_rule_id = rule_id.clone();
            }
            if !existing.detected_by.contains(&rule_id) {
                existing.detected_by.push(rule_id);
            }
            if !snippet.is_empty() && existing.snippet.is_empty() {
                existing.snippet = snippet;
            }
            if !problem.is_empty() && existing.problem.is_empty() {
                existing.problem = problem;
            }
            existing.sources.push(source.clone());
        } else {
            let mut uf = UnifiedFinding::new(&rule_id, &severity, line);
            uf.snippet = snippet;
            uf.problem = problem;
            if let Some(hint) = fix_hint {
                uf.fix_hint = hint;
            }
            uf.ast_aware = matches!(source, FindingSource::AiAst(_));
            uf.sources.push(source);
            if let Some(labels) = taint_labels {
                uf.taint_labels = labels.iter().map(|l| l.to_string()).collect();
            }
            let idx = self.findings.len();
            self.findings.push(uf);
            self.seen_keys.insert(key, idx);
        }
    }

    pub fn into_findings(self) -> Vec<UnifiedFinding> {
        self.findings
    }

    pub fn len(&self) -> usize {
        self.findings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Merge multiple deduplicators
    pub fn merge(&mut self, other: FindingsDeduplicator) {
        for f in other.findings {
            let key = UnifiedFinding::dedup_key(&f.primary_rule_id, f.line, &f.snippet);
            let severity = f.severity.clone();
            let snippet = f.snippet.clone();
            let problem = f.problem.clone();
            let fix_hint = Some(f.fix_hint.clone());
            for source in f.sources.clone() {
                self.merge_or_insert(
                    key.clone(), f.primary_rule_id.clone(),
                    severity.clone(), f.line, snippet.clone(),
                    problem.clone(), fix_hint.clone(), source, None
                );
            }
        }
    }
}

// --------------------------------------------------------------------------
// Statistics
// --------------------------------------------------------------------------

impl UnifiedFinding {
    pub fn summary(&self) -> String {
        format!(
            "[{}] {}: {} (line {}, detected by {} layers)",
            self.severity.to_uppercase(),
            self.primary_rule_id,
            &self.problem[..self.problem.len().min(80)],
            self.line,
            self.detected_by.len()
        )
    }
}

pub fn print_dedup_summary(findings: &[UnifiedFinding]) {
    let mut by_severity = HashMap::new();
    for f in findings {
        by_severity
            .entry(f.severity.clone())
            .or_insert_with(Vec::new)
            .push(f);
    }

    let order = ["critical", "high", "medium", "low", "info"];
    for sev in order {
        if let Some(items) = by_severity.get(sev) {
            println!("\n{} ({} findings):", sev.to_uppercase(), items.len());
            for f in items {
                println!("  {}", f.summary());
            }
        }
    }

    let total_duplicates_avoided: usize = findings.iter()
        .map(|f| f.detected_by.len().saturating_sub(1))
        .sum();
    println!("\nTotal findings: {}", findings.len());
    println!("Duplicate findings avoided: {}", total_duplicates_avoided);
}
