//! PyNeat Rust Security Scanner
//!
//! High-performance security scanner for Python code written in Rust.
//! Uses tree-sitter for AST parsing and regex for pattern matching.

pub mod fixer;
pub mod rules;
pub mod scanner;

pub use rules::base::{Finding, Fix, Rule, Severity};
pub use rules::security::all_security_rules;
pub use rules::quality::all_quality_rules;
pub use scanner::tree_sitter::parse;

#[cfg(test)]
mod lib_tests;

use pyo3::prelude::*;
use serde_json::{json, Value};

/// Scan Python code for security vulnerabilities using tree-sitter AST + regex.
#[pyfunction]
fn scan_security(code: &str) -> PyResult<String> {
    // Parse the code into AST
    let tree = match parse(code) {
        Ok(t) => t,
        Err(_) => {
            // Fallback: return empty findings if parse fails
            return Ok("[]".to_string());
        }
    };

    let rules = all_security_rules();
    let mut findings: Vec<Value> = Vec::new();

    for rule in &rules {
        for finding in rule.detect(&tree, code) {
            findings.push(json!({
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "cwe_id": finding.cwe_id,
                "cvss_score": finding.cvss_score,
                "owasp_id": finding.owasp_id,
                "start": finding.start,
                "end": finding.end,
                "snippet": finding.snippet,
                "problem": finding.problem,
                "fix_hint": finding.fix_hint,
                "auto_fix_available": finding.auto_fix_available,
            }));
        }
    }

    // Sort by position
    findings.sort_by_key(|f| f["start"].as_u64().unwrap_or(0));

    serde_json::to_string(&findings)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Apply auto-fixes to code.
#[pyfunction]
fn apply_auto_fix(code: &str, finding_json: &str) -> PyResult<String> {
    // Parse the finding from JSON
    let finding: serde_json::Value = serde_json::from_str(finding_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let start = finding["start"].as_u64().unwrap_or(0) as usize;
    let end = finding["end"].as_u64().unwrap_or(0) as usize;
    let replacement = finding["replacement"].as_str().unwrap_or("");

    if start > end || end > code.len() {
        return Err(pyo3::exceptions::PyValueError::new_err("Invalid fix range"));
    }

    let mut result = code.to_string();
    result.replace_range(start..end, replacement);

    Ok(result)
}

/// Get scanner version info.
#[pyfunction]
fn version() -> String {
    format!("pyneat-rs v{}", env!("CARGO_PKG_VERSION"))
}

/// Get all available rules.
#[pyfunction]
fn get_rules() -> PyResult<String> {
    let rules = all_security_rules();
    let mut rules_json: Vec<Value> = Vec::new();

    for rule in &rules {
        rules_json.push(json!({
            "id": rule.id(),
            "name": rule.name(),
            "severity": rule.severity().as_str(),
            "auto_fix": rule.supports_auto_fix(),
        }));
    }

    serde_json::to_string(&rules_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Python module definition
#[pymodule]
fn pyneat_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_security, m)?)?;
    m.add_function(wrap_pyfunction!(apply_auto_fix, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(get_rules, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
