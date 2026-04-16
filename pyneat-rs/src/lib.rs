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

#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_assignments)]
#![allow(dead_code)]

pub mod fixer;
pub mod rules;
pub mod scanner;
pub mod sarif;
pub mod integrations;
pub mod ai_security;
pub mod lsp;

pub use lsp::{run_server, LspConfig};
pub use rules::base::{Finding, Fix, Rule, Severity};
pub use rules::security::all_security_rules;
pub use rules::ast_rules::all_ast_rules;
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

#[cfg(test)]
mod lib_tests;

use pyo3::prelude::*;
use serde_json::{json, Value};

/// Scan Python code for security vulnerabilities using tree-sitter AST + regex + AST-based analysis.
#[pyfunction]
fn scan_security(code: &str) -> PyResult<String> {
    let tree = match parse(code) {
        Ok(t) => t,
        Err(_) => {
            return Ok("[]".to_string());
        }
    };

    // Run both regex-based and AST-based rules
    let security_rules = all_security_rules();
    let ast_rules = all_ast_rules();
    let all_rules: Vec<_> = security_rules.into_iter().chain(ast_rules.into_iter()).collect();
    let mut findings: Vec<Value> = Vec::new();

    for rule in &all_rules {
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

/// Python module definition
#[pymodule]
fn pyneat_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_security, m)?)?;
    m.add_function(wrap_pyfunction!(apply_auto_fix, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(get_rules, m)?)?;
    m.add_function(wrap_pyfunction!(parse_ln_ast, m)?)?;
    m.add_function(wrap_pyfunction!(detect_language, m)?)?;
    m.add_function(wrap_pyfunction!(supported_languages, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
