//! PyNeat Core - Open Source (AGPL)
//!
//! This is the open-source core of PyNEAT, licensed under AGPL-3.0.
//! It provides basic linting and scanning capabilities.

#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_assignments)]
#![allow(dead_code)]

pub mod fixer;
pub mod rules;
pub mod scanner;
pub mod sarif;
pub mod integrations;
pub mod lsp;

// Pro Engine integration
pub mod protocol;
pub mod pro_engine;

pub use lsp::{run_server, LspConfig};
pub use rules::base::{Finding, Fix, Rule, Severity};
pub use rules::security::all_security_rules;
pub use rules::quality::all_quality_rules;
pub use scanner::tree_sitter::parse;
pub use scanner::multilang::detect_language_from_extension;
pub use scanner::ln_ast_converter::LnAstConverter;
pub use scanner::{
    RustScanner, JavaScriptScanner, TypeScriptScanner,
    GoScanner, JavaScanner, CSharpScanner,
    PhpScanner, RubyScanner,
    LanguageScanner, LanguageRegistry, LangRule, LangFinding, Language,
};
pub use sarif::writer::SarifBuilder;

// Re-export Pro Engine types for convenience
pub use protocol::{ProEngineRequest, ProEngineResponse, ProEngineResult};
pub use pro_engine::{init_pro_engine, is_pro_engine_available, get_pro_engine_version};

use pyo3::prelude::*;

/// Scan Python code for security vulnerabilities using tree-sitter AST + regex.
#[pyfunction]
fn scan_security(code: &str) -> PyResult<String> {
    let tree = match parse(code) {
        Ok(t) => t,
        Err(_) => {
            return Ok("[]".to_string());
        }
    };

    let rules = all_security_rules();
    let mut findings: Vec<serde_json::Value> = Vec::new();

    for rule in &rules {
        for finding in rule.detect(&tree, code) {
            findings.push(serde_json::json!({
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

    findings.sort_by_key(|f| f["start"].as_u64().unwrap_or(0));

    serde_json::to_string(&findings)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Apply auto-fixes to code.
#[pyfunction]
fn apply_auto_fix(code: &str, finding_json: &str) -> PyResult<String> {
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
    format!("pyneat-core v{}", env!("CARGO_PKG_VERSION"))
}

/// Get all available rules.
#[pyfunction]
fn get_rules() -> PyResult<String> {
    let rules = all_security_rules();
    let mut rules_json: Vec<serde_json::Value> = Vec::new();

    for rule in &rules {
        rules_json.push(serde_json::json!({
            "id": rule.id(),
            "name": rule.name(),
            "severity": rule.severity().as_str(),
            "auto_fix": rule.supports_auto_fix(),
        }));
    }

    serde_json::to_string(&rules_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Parse source code into Language-Neutral AST (LN-AST) JSON.
/// Used for multi-language support in the Python engine.
#[pyfunction]
fn parse_ln_ast(code: &str, language: &str) -> PyResult<String> {
    match crate::scanner::multilang::parse_ln_ast(code, language) {
        Ok(ast) => Ok(ast.to_json()),
        Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e.to_string())),
    }
}

/// Detect language from file extension.
/// Returns language string like "python", "javascript", etc.
#[pyfunction]
fn detect_language(ext: &str) -> PyResult<Option<String>> {
    Ok(crate::scanner::multilang::detect_language_from_extension(ext))
}

/// Get list of supported languages.
#[pyfunction]
fn supported_languages() -> Vec<&'static str> {
    vec![
        "python", "javascript", "typescript",
        "go", "java", "rust", "csharp", "php", "ruby",
    ]
}

/// Check if Pro Engine is available
#[pyfunction]
fn is_pro_available() -> PyResult<bool> {
    Ok(pro_engine::is_pro_engine_available())
}

/// Get Pro Engine version if available
#[pyfunction]
fn pro_version() -> PyResult<Option<String>> {
    if pro_engine::is_pro_engine_available() {
        match pro_engine::get_pro_engine_version() {
            Ok(v) => Ok(Some(v)),
            Err(_) => Ok(None),
        }
    } else {
        Ok(None)
    }
}

/// Python module definition
#[pymodule]
fn pyneat_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_security, m)?)?;
    m.add_function(wrap_pyfunction!(apply_auto_fix, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(get_rules, m)?)?;
    m.add_function(wrap_pyfunction!(parse_ln_ast, m)?)?;
    m.add_function(wrap_pyfunction!(detect_language, m)?)?;
    m.add_function(wrap_pyfunction!(supported_languages, m)?)?;
    m.add_function(wrap_pyfunction!(is_pro_available, m)?)?;
    m.add_function(wrap_pyfunction!(pro_version, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
