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

pub mod fixer;
pub mod rules;
use rules::security::looks_like_python;
pub mod scanner;
pub mod sarif;
pub mod integrations;
pub mod ai_security;
pub mod ai_analysis;
pub mod lsp;
pub mod findings_dedup;

pub use lsp::{run_server, LspConfig};
pub use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
pub struct LspArgs {
    /// Enable scan on file save
    #[arg(long)]
    pub scan_on_save: bool,

    /// Enable scan on type (real-time)
    #[arg(long)]
    pub scan_on_type: bool,

    /// Debounce delay in ms
    #[arg(long, default_value = "500")]
    pub debounce_ms: u64,

    /// Severity threshold
    #[arg(long, default_value = "medium")]
    pub severity: String,

    /// Enabled rule IDs (comma-separated)
    #[arg(long)]
    pub rules: Option<String>,

    /// Use stdio transport (for LSP, ignored as stdio is the default)
    #[arg(long, hide = true)]
    pub stdio: bool,
}

pub fn run_server_with_args(args: LspArgs) {
    let config = LspConfig {
        severity_threshold: args.severity,
        scan_on_save: args.scan_on_save,
        debounce_ms: args.debounce_ms,
        enable_real_time: true,
        enabled_rules: args.rules
            .map(|s| s.split(',').map(|v| v.trim().to_string()).collect())
            .unwrap_or_default(),
    };
    lsp::run_server_with_config(config);
}
pub use rules::base::{Finding, Fix, Rule, Severity};
pub use rules::security::all_security_rules;
pub use rules::ast_rules::all_ast_rules;
pub use rules::quality::all_quality_rules;
pub use rules::hackingtool_patterns::all_hackingtool_rules;
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
pub use scanner::ml::{AnomalyEngine, AnomalyFinding, CodeMetrics};
pub use ai_analysis::{LlmAnalyzer, LlmAnalysisResult, AiFix, has_api_key};

#[cfg(test)]
mod lib_tests;

use pyo3::prelude::*;
use rayon::prelude::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Instant;

use crate::scanner::supplychain::{
    discover_lock_files, parse_lock_file, Ecosystem, OsvClient,
};
use crate::ai_security::AiSecurityScanner;

/// Metadata about a scan result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    /// All findings from the scan.
    pub findings: Vec<Value>,
    /// Total lines of code scanned.
    pub total_lines: usize,
    /// Language of the scanned code.
    pub language: String,
    /// Optional file path associated with this scan.
    pub file_path: Option<String>,
    /// Time taken to scan in milliseconds.
    pub scan_time_ms: u64,
    /// Number of rules that were evaluated.
    pub rules_evaluated: usize,
    /// Severity breakdown.
    pub severity_counts: SeverityCounts,
    /// Dependency / supply chain findings (CVE, license, lock file issues).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependency_findings: Option<Vec<DependencyFinding>>,
    /// Discovered SBOM (JSON string) if requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sbom: Option<String>,
    /// Taint analysis findings if enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint_findings: Option<Vec<Value>>,
}

/// A finding from dependency / supply chain scanning.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DependencyFinding {
    /// The affected package name.
    pub package: String,
    /// The version string.
    pub version: String,
    /// Ecosystem (e.g., "PyPI", "npm", "Go").
    pub ecosystem: String,
    /// Type of finding.
    pub kind: String,
    /// Human-readable description.
    pub description: String,
    /// CVE ID if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    /// CVSS score if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f32>,
    /// Suggested fixed version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
    /// Path to the lock file where this was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_file: Option<String>,
}

/// Scan options controlling what to include in a full project scan.
#[pyo3::pyclass(from_py_object)]
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct ScanOptions {
    /// Scan lock files for dependency analysis.
    pub scan_deps: bool,
    /// Check packages against OSV.dev for CVEs.
    pub check_cve: bool,
    /// Check license compliance.
    pub check_license: bool,
    /// OSV.dev API key (optional).
    pub osv_api_key: Option<String>,
    /// Root directory to scan.
    pub root: Option<String>,
    /// Languages to scan (empty = all).
    pub languages: Vec<String>,
    /// Enable taint analysis.
    pub taint: bool,
    /// Enable interprocedural analysis.
    pub interproc: bool,
    /// Enable AI security scanner.
    pub ai_security: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

fn count_severities(findings: &[Value]) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for f in findings {
        match f["severity"].as_str().unwrap_or("info").to_lowercase().as_str() {
            "critical" => counts.critical += 1,
            "high" => counts.high += 1,
            "medium" => counts.medium += 1,
            "low" => counts.low += 1,
            _ => counts.info += 1,
        }
    }
    counts
}

fn apply_severity_filter(findings: Vec<Value>, severities: &[String]) -> Vec<Value> {
    if severities.is_empty() {
        return findings;
    }
    let sev_set: std::collections::HashSet<&str> =
        severities.iter().map(|s| s.as_str()).collect();
    findings
        .into_iter()
        .filter(|f| {
            sev_set.contains(f["severity"].as_str().unwrap_or("info").to_lowercase().as_str())
        })
        .collect()
}

#[allow(dead_code)]
fn apply_rule_filter(findings: Vec<Value>, rule_ids: &[String]) -> Vec<Value> {
    if rule_ids.is_empty() {
        return findings;
    }
    let rule_set: std::collections::HashSet<&str> =
        rule_ids.iter().map(|s| s.as_str()).collect();
    findings
        .into_iter()
        .filter(|f| rule_set.contains(f["rule_id"].as_str().unwrap_or("")))
        .collect()
}

fn findings_to_json(findings: Vec<Value>) -> Vec<Value> {
    findings
        .into_iter()
        .map(|f| {
            json!({
                "id": f.get("id"),
                "rule_id": f["rule_id"],
                "name": f.get("name"),
                "severity": f["severity"],
                "cwe_id": f["cwe_id"],
                "cvss_score": f["cvss_score"],
                "owasp_id": f["owasp_id"],
                "start": f["start"],
                "end": f["end"],
                "snippet": f["snippet"],
                "problem": f["problem"],
                "fix_hint": f["fix_hint"],
                "auto_fix_available": f.get("auto_fix_available"),
                "replacement": f.get("replacement"),
            })
        })
        .collect()
}

/// Scan Python code for security vulnerabilities using tree-sitter AST + regex + AST-based analysis.
#[pyfunction]
fn scan_security(code: &str) -> PyResult<String> {
    let result = scan_security_internal(code, None, &[], &[], None, None);
    serde_json::to_string(&result.findings)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Scan code with full configuration options.
#[pyfunction]
fn scan_security_configured(
    code: &str,
    language: Option<&str>,
    rule_ids: Vec<String>,
    severities: Vec<String>,
    ignore_paths: Vec<String>,
    file_path: Option<&str>,
) -> PyResult<String> {
    let lang_arg = language.map(|s| s.to_string());
    let fp_arg = file_path.map(|s| s.to_string());

    let result = scan_security_internal(
        code, lang_arg.as_deref(),
        &rule_ids, &severities,
        if ignore_paths.is_empty() { None } else { Some(ignore_paths.as_slice()) },
        fp_arg.as_deref(),
    );

    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Internal scan implementation shared by both public functions.
fn scan_security_internal(
    code: &str,
    language: Option<&str>,
    rule_ids: &[String],
    severities: &[String],
    ignore_paths: Option<&[String]>,
    file_path: Option<&str>,
) -> ScanResult {
    let start = Instant::now();

    let lang = language.unwrap_or("python");
    let tree = match crate::scanner::tree_sitter::parse(code) {
        Ok(t) => t,
        Err(_) => {
            return ScanResult {
                findings: vec![],
                total_lines: code.lines().count(),
                language: lang.to_string(),
                file_path: file_path.map(String::from),
                scan_time_ms: start.elapsed().as_millis() as u64,
                rules_evaluated: 0,
                severity_counts: SeverityCounts::default(),
                dependency_findings: None,
                sbom: None,
                taint_findings: None,
            };
        }
    };

    let security_rules = all_security_rules();
    let ast_rules = all_ast_rules();
    let all_rules: Vec<_> = security_rules.into_iter().chain(ast_rules.into_iter()).collect();
    let rules_evaluated = all_rules.len();

    let rule_ids_owned: Vec<String> = rule_ids.iter().cloned().collect();

    let mut raw_findings: Vec<Value> = all_rules
        .par_iter()
        .filter(|rule| {
            let langs = rule.supported_languages();
            let lang_match = langs.map_or(true, |ls| ls.iter().any(|l| l.to_lowercase() == lang.to_lowercase()));
            let id_match = rule_ids_owned.is_empty() || rule_ids_owned.iter().any(|id| id == rule.id());
            lang_match && id_match
        })
        .flat_map(|rule| {
            rule.detect(&tree, code)
                .into_iter()
                .map(|finding| {
                    let replacement = if finding.auto_fix_available {
                        rule.fix(&finding, code).map(|f| f.replacement).unwrap_or_default()
                    } else {
                        String::new()
                    };
                    json!({
                        "id": rule.id(),
                        "rule_id": finding.rule_id,
                        "name": rule.name(),
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
                        "replacement": replacement,
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();

    // Severity filter
    if !severities.is_empty() {
        raw_findings = apply_severity_filter(raw_findings, severities);
    }

    // Ignore paths filter (by byte offset approximation)
    if let Some(paths) = ignore_paths {
        if !paths.is_empty() && file_path.is_some() {
            let fp = file_path.unwrap();
            if paths.iter().any(|p| fp.contains(p)) {
                raw_findings.clear();
            }
        }
    }

    raw_findings.sort_by_key(|f| f["start"].as_u64().unwrap_or(0));
    let findings = findings_to_json(raw_findings.clone());
    let severity_counts = count_severities(&findings);

    ScanResult {
        findings,
        total_lines: code.lines().count(),
        language: lang.to_string(),
        file_path: file_path.map(String::from),
        scan_time_ms: start.elapsed().as_millis() as u64,
        rules_evaluated,
        severity_counts,
        dependency_findings: None,
        sbom: None,
        taint_findings: None,
    }
}

/// Run taint analysis on source code and convert findings to Value array.
fn run_taint_analysis_internal(code: &str, language: &str) -> Result<Vec<serde_json::Value>, String> {
    let ast_json = crate::scanner::multilang::parse_ln_ast(code, language);

    let ast: LnAst = serde_json::from_str(&ast_json.to_json())
        .map_err(|e| e.to_string())?;

    let rules = all_taint_rules();
    let mut engine = TaintEngine::new(code);

    for rule in rules {
        engine.add_rule(rule);
    }

    engine.analyze_with_ast(&ast);
    let findings = engine.findings();

    let output: Vec<serde_json::Value> = findings.iter().map(|f| {
        serde_json::json!({
            "rule_id": f.rule_id,
            "severity": f.severity,
            "line": f.line,
            "column": f.column,
            "start_byte": f.start_byte,
            "end_byte": f.end_byte,
            "snippet": f.snippet,
            "problem": f.problem,
            "labels": f.labels.iter().map(|l| format!("{:?}", l)).collect::<Vec<_>>(),
            "trace": f.trace.iter().map(|n| serde_json::json!({
                "kind": format!("{:?}", n.kind),
                "description": n.description,
                "line": n.line,
                "column": n.column,
                "snippet": n.snippet,
            })).collect::<Vec<_>>(),
        })
    }).collect();

    Ok(output)
}

/// Apply a single auto-fix to code.
#[pyfunction]
fn apply_auto_fix(code: &str, finding_json: &str) -> PyResult<String> {
    let finding: serde_json::Value = serde_json::from_str(finding_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let byte_start = finding["start"].as_u64().unwrap_or(0) as usize;
    let byte_end = finding["end"].as_u64().unwrap_or(0) as usize;

    // For lang scanners that set byte offsets to 0, fall back to line-based extraction.
    // They set start_byte=0, end_byte=0 but provide a "line" field.
    let (fix_start, fix_end, original_snippet) = if byte_start == 0 && byte_end == 0 {
        if let Some(line) = finding["line"].as_u64() {
            let line_idx = line.saturating_sub(1) as usize;
            if let Some(line_text) = code.lines().nth(line_idx) {
                let trimmed = line_text.trim();
                let trim_start = line_text.len() - trimmed.len();
                let trim_end = trim_start + trimmed.len();
                (trim_start, trim_end, trimmed)
            } else {
                return Err(pyo3::exceptions::PyValueError::new_err("Invalid fix range"));
            }
        } else {
            return Err(pyo3::exceptions::PyValueError::new_err("Invalid fix range"));
        }
    } else {
        if byte_start > byte_end || byte_end > code.len() {
            return Err(pyo3::exceptions::PyValueError::new_err("Invalid fix range"));
        }
        (byte_start, byte_end, &code[byte_start..byte_end])
    };

    // Use pre-computed replacement from scan result if available
    let replacement = finding["replacement"].as_str().unwrap_or("");
    let replacement = if !replacement.is_empty() {
        replacement.to_string()
    } else {
        // Fallback: compute replacement from known fix patterns
        let rule_id = finding["rule_id"].as_str().unwrap_or("");
        let _language = finding["language"].as_str().unwrap_or("python");
        match rule_id {
            // SEC-014: yaml.load -> yaml.safe_load (Python)
            "SEC-014" if original_snippet.contains("yaml.load") => {
                original_snippet.replace("yaml.load(", "yaml.safe_load(")
            }
            // JAVA-SEC-035 / JAVA-SEC-052 / JAVA-SEC-066: new Random() -> new SecureRandom()
            "JAVA-SEC-035" | "JAVA-SEC-052" | "JAVA-SEC-066"
                if original_snippet.contains("new Random()") || original_snippet.contains("java.util.Random") =>
            {
                if original_snippet.contains("new Random()") {
                    original_snippet.replace("new Random()", "new SecureRandom()")
                } else {
                    original_snippet.replace("java.util.Random", "java.security.SecureRandom")
                }
            }
            // JS-SEC-003: Math.random() — suggest crypto.getRandomValues
            "JS-SEC-003" | "RUST-SEC-003"
                if original_snippet.contains("Math.random()") || original_snippet.contains("rand::ThreadRng") =>
            {
                if original_snippet.contains("Math.random()") {
                    "// TODO: Use crypto.getRandomValues() for secure random numbers".to_string()
                } else {
                    "// TODO: Use rand::CryptoRng for secure random numbers".to_string()
                }
            }
            // GO-SEC-006: rand.Seed -> rand.Read (secure seeding)
            "GO-SEC-006" if original_snippet.contains("rand.Seed") => {
                original_snippet.replace("rand.Seed", "rand.Read")
            }
            // PHP-SEC-003: rand/mt_rand -> random_bytes
            "PHP-SEC-003" if original_snippet.contains("rand(") || original_snippet.contains("mt_rand(") => {
                if original_snippet.contains("rand(") {
                    original_snippet.replace("rand(", "random_int(")
                } else {
                    original_snippet.replace("mt_rand(", "random_int(")
                }
            }
            // C# insecure random: Random -> RandomNumberGenerator
            "CSHARP-SEC-009" | "CSHARP-SEC-023"
                if original_snippet.contains("new Random()") =>
            {
                original_snippet.replace(
                    "new Random()",
                    "RandomNumberGenerator.Create()",
                )
            }
            // SEC-003: eval -> ast.literal_eval (Python only)
            "SEC-003" if original_snippet.contains("eval(") && !original_snippet.contains("ast.literal_eval") => {
                if looks_like_python(code) {
                    original_snippet.replace("eval(", "ast.literal_eval(")
                } else {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "No auto-fix available for SEC-003 in non-Python code",
                    ));
                }
            }
            // JS-005: eval/Function/setTimeout/setInterval — comment with warning
            "JS-005" => {
                let trimmed = original_snippet.trim();
                let indent_len = original_snippet.len() - trimmed.len();
                let indent = &original_snippet[..indent_len];
                if original_snippet.contains("eval(") {
                    format!("{}// Evaluate if this can be replaced with JSON.parse() or a safer alternative: {}", indent, trimmed)
                } else {
                    format!("{}// Consider using a safer alternative to this dynamic code execution: {}", indent, trimmed)
                }
            }
            _ => {
                let msg = if rule_id.is_empty() {
                    "No rule_id provided in finding data".to_string()
                } else {
                    format!("No auto-fix available for rule: {}", rule_id)
                };
                return Err(pyo3::exceptions::PyValueError::new_err(msg));
            }
        }
    };

    let mut result = code.to_string();
    result.replace_range(fix_start..fix_end, &replacement);

    Ok(result)
}

/// Apply multiple auto-fixes to code with conflict resolution.
#[pyfunction]
fn apply_fixes_batch(code: &str, fixes_json: &str) -> PyResult<String> {
    let fixes: Vec<serde_json::Value> = serde_json::from_str(fixes_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    use crate::fixer::apply_fix::{FixRange, apply_fixes_with_validation};

    let fix_ranges: Vec<FixRange> = fixes
        .into_iter()
        .filter_map(|f| {
            let start = f["start"].as_u64()? as usize;
            let end = f["end"].as_u64()? as usize;
            let replacement = f["replacement"].as_str()?.to_string();
            let rule_id = f["rule_id"].as_str().unwrap_or("unknown").to_string();
            Some(FixRange::new(start, end, replacement, rule_id))
        })
        .collect();

    let result = apply_fixes_with_validation(code, &fix_ranges, true);

    #[derive(serde::Serialize)]
    struct BatchResult<'a> {
        code: &'a str,
        applied: &'a [String],
        conflicts: usize,
        errors: &'a [String],
    }

    let batch_result = BatchResult {
        code: &result.code,
        applied: &result.applied,
        conflicts: result.conflicts.len(),
        errors: &result.errors,
    };

    serde_json::to_string(&batch_result)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Get scanner version info.
#[pyfunction]
fn version() -> String {
    format!("pyneat-rs v{}", env!("CARGO_PKG_VERSION"))
}

/// Get all available rules from both security and AST rule sets.
#[pyfunction]
fn get_rules() -> PyResult<String> {
    let security_rules = all_security_rules();
    let ast_rules = all_ast_rules();
    let all_rules: Vec<_> = security_rules.into_iter().chain(ast_rules.into_iter()).collect();
    let mut rules_json: Vec<Value> = Vec::new();

    for rule in &all_rules {
        let langs = rule.supported_languages();
        rules_json.push(json!({
            "id": rule.id(),
            "name": rule.name(),
            "severity": rule.severity().as_str(),
            "auto_fix_available": rule.supports_auto_fix(),
            "supported_languages": langs,
            "category": "security",
        }));
    }

    serde_json::to_string(&rules_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Get the scanner version string.
#[pyfunction]
fn get_scanner_version() -> String {
    format!("pyneat-rs v{}", env!("CARGO_PKG_VERSION"))
}

/// Parse source code into Language-Neutral AST (LN-AST) JSON.
/// Used for multi-language support in the Python engine.
#[pyfunction]
fn parse_ln_ast(code: &str, language: &str) -> PyResult<String> {
    let ast = crate::scanner::multilang::parse_ln_ast(code, language);
    Ok(ast.to_json())
}

/// Detect language from file extension.
/// Returns language string like "python", "javascript", etc.
#[pyfunction]
fn detect_language(ext: &str) -> PyResult<Option<String>> {
    let ext = std::path::Path::new(ext)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or(ext);
    Ok(crate::scanner::multilang::detect_language_from_extension(ext))
}

/// Scan code for any language (JS, TS, Go, Java, Rust, C#, PHP, Ruby).
/// Dispatches to the appropriate language-specific scanner.
/// Returns a JSON array of findings.
#[pyfunction]
fn scan_multilang(code: &str, language: &str) -> PyResult<String> {
    use crate::scanner::{
        JavaScriptScanner, TypeScriptScanner, GoScanner,
        JavaScanner, CSharpScanner, PhpScanner, RubyScanner,
        RustScanner as LangRustScanner,
    };

    let lang = language.to_lowercase();
    let ast = crate::scanner::multilang::parse_ln_ast(code, &lang);
    let findings: Vec<serde_json::Value> = match lang.as_str() {
        "javascript" | "js" | "jsx" | "mjs" | "cjs" => {
            let scanner = JavaScriptScanner::new();
            scanner.detect(&ast, code)
                .into_iter()
                .map(|f| {
                    json!({
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "line": f.line,
                        "column": f.column,
                        "start": f.start_byte,
                        "end": f.end_byte,
                        "snippet": f.snippet,
                        "problem": f.problem,
                        "fix_hint": f.fix_hint,
                        "auto_fix_available": f.auto_fix_available,
                        "replacement": f.replacement,
                        "language": "javascript",
                    })
                })
                .collect()
        }
        "typescript" | "ts" | "tsx" => {
            let scanner = TypeScriptScanner::new();
            scanner.detect(&ast, code)
                .into_iter()
                .map(|f| {
                    json!({
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "line": f.line,
                        "column": f.column,
                        "start": f.start_byte,
                        "end": f.end_byte,
                        "snippet": f.snippet,
                        "problem": f.problem,
                        "fix_hint": f.fix_hint,
                        "auto_fix_available": f.auto_fix_available,
                        "replacement": f.replacement,
                        "language": "typescript",
                    })
                })
                .collect()
        }
        "go" | "golang" => {
            let scanner = GoScanner::new();
            scanner.detect(&ast, code)
                .into_iter()
                .map(|f| {
                    json!({
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "line": f.line,
                        "column": f.column,
                        "start": f.start_byte,
                        "end": f.end_byte,
                        "snippet": f.snippet,
                        "problem": f.problem,
                        "fix_hint": f.fix_hint,
                        "auto_fix_available": f.auto_fix_available,
                        "replacement": f.replacement,
                        "language": "go",
                    })
                })
                .collect()
        }
        "java" => {
            let scanner = JavaScanner::new();
            scanner.detect(&ast, code)
                .into_iter()
                .map(|f| {
                    json!({
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "line": f.line,
                        "column": f.column,
                        "start": f.start_byte,
                        "end": f.end_byte,
                        "snippet": f.snippet,
                        "problem": f.problem,
                        "fix_hint": f.fix_hint,
                        "auto_fix_available": f.auto_fix_available,
                        "replacement": f.replacement,
                        "language": "java",
                    })
                })
                .collect()
        }
        "rust" | "rs" => {
            let scanner = LangRustScanner::new();
            scanner.detect(&ast, code)
                .into_iter()
                .map(|f| {
                    json!({
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "line": f.line,
                        "column": f.column,
                        "start": f.start_byte,
                        "end": f.end_byte,
                        "snippet": f.snippet,
                        "problem": f.problem,
                        "fix_hint": f.fix_hint,
                        "auto_fix_available": f.auto_fix_available,
                        "replacement": f.replacement,
                        "language": "rust",
                    })
                })
                .collect()
        }
        "csharp" | "cs" | "c#" => {
            let scanner = CSharpScanner::new();
            scanner.detect(&ast, code)
                .into_iter()
                .map(|f| {
                    json!({
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "line": f.line,
                        "column": f.column,
                        "start": f.start_byte,
                        "end": f.end_byte,
                        "snippet": f.snippet,
                        "problem": f.problem,
                        "fix_hint": f.fix_hint,
                        "auto_fix_available": f.auto_fix_available,
                        "replacement": f.replacement,
                        "language": "csharp",
                    })
                })
                .collect()
        }
        "php" => {
            let scanner = PhpScanner::new();
            scanner.detect(&ast, code)
                .into_iter()
                .map(|f| {
                    json!({
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "line": f.line,
                        "column": f.column,
                        "start": f.start_byte,
                        "end": f.end_byte,
                        "snippet": f.snippet,
                        "problem": f.problem,
                        "fix_hint": f.fix_hint,
                        "auto_fix_available": f.auto_fix_available,
                        "replacement": f.replacement,
                        "language": "php",
                    })
                })
                .collect()
        }
        "ruby" | "rb" => {
            let scanner = RubyScanner::new();
            scanner.detect(&ast, code)
                .into_iter()
                .map(|f| {
                    json!({
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "line": f.line,
                        "column": f.column,
                        "start": f.start_byte,
                        "end": f.end_byte,
                        "snippet": f.snippet,
                        "problem": f.problem,
                        "fix_hint": f.fix_hint,
                        "auto_fix_available": f.auto_fix_available,
                        "replacement": f.replacement,
                        "language": "ruby",
                    })
                })
                .collect()
        }
        _ => vec![],
    };

    serde_json::to_string(&findings)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Get list of supported languages.
#[pyfunction]
fn supported_languages() -> Vec<&'static str> {
    vec![
        "python", "javascript", "typescript",
        "go", "java", "rust", "csharp", "php", "ruby",
    ]
}

/// Get the configuration schema for a specific rule as JSON schema string.
#[pyfunction]
fn get_rule_config_schema(rule_id: &str) -> PyResult<Option<String>> {
    

    // Built-in schemas for known rules
    let schemas: HashMap<&str, &str> = [
        ("SEC-010", r#"{"type":"object","properties":{"min_entropy":{"type":"number","default":4.0,"description":"Minimum entropy for secret detection"},"skip_patterns":{"type":"array","items":{"type":"string"},"default":[],"description":"Regex patterns to skip"},"include_patterns":{"type":"array","items":{"type":"string"},"default":[]}}}"#),
        ("SEC-011", r#"{"type":"object","properties":{"min_hash_bits":{"type":"integer","default":256,"description":"Minimum hash bit length"}}}"#),
        ("SEC-076", r#"{"type":"object","properties":{"min_hash_bits":{"type":"integer","default":256,"description":"Minimum hash bit length for cryptographic algorithms"}}}"#),
        ("SEC-097", r#"{"type":"object","properties":{"max_complexity":{"type":"integer","default":10,"description":"Maximum regex complexity score"}}}"#),
        ("SEC-019", r#"{"type":"object","properties":{"whitelist":{"type":"array","items":{"type":"string"},"default":[],"description":"Functions to skip (whitelist)"}}}"#),
    ].into_iter().collect();

    if let Some(schema) = schemas.get(rule_id) {
        Ok(Some(schema.to_string()))
    } else {
        Ok(None)
    }
}

// ============================================================================
// Supply Chain: OSV / CVE Checking
// ============================================================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CveCheckResult {
    pub package: String,
    pub version: String,
    pub ecosystem: String,
    pub vulnerabilities: Vec<CveEntry>,
    pub checked_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub summary: String,
    pub severity: Option<String>,
    pub cwe_ids: Vec<String>,
    pub aliases: Vec<String>,
}

/// Check a single package for CVEs via OSV.dev.
#[pyfunction]
fn cve_check_package(package_name: &str, version: &str, ecosystem: &str) -> PyResult<String> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

    let mut client = OsvClient::new();
    let ecosystem = Ecosystem::from_pkg_manager(ecosystem);

    let result = runtime.block_on(client.query_package(package_name, version, ecosystem));

    let cwe_re = regex::Regex::new(r"CWE-\d+").unwrap();

    let vulns: Vec<CveEntry> = match result {
        Ok(vulns) => vulns.into_iter().map(|v: crate::scanner::supplychain::vuln_db::Vulnerability| {
            let details_str = v.details.as_deref().unwrap_or("");
            let cwe_ids = cwe_re.find_iter(details_str)
                .map(|m| m.as_str().to_string())
                .collect::<Vec<_>>();
            CveEntry {
                id: v.id,
                summary: v.summary.unwrap_or_default(),
                severity: v.severity,
                cwe_ids,
                aliases: vec![],
            }
        }).collect(),
        Err(_) => vec![],
    };

    let now = chrono_lite_now();
    let check_result = CveCheckResult {
        package: package_name.to_string(),
        version: version.to_string(),
        ecosystem: ecosystem.as_str().to_string(),
        vulnerabilities: vulns,
        checked_at: now,
    };

    serde_json::to_string(&check_result)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Check multiple packages for CVEs via OSV.dev (batch).
#[pyfunction]
fn cve_check_batch(packages_json: &str) -> PyResult<String> {
    #[derive(serde::Deserialize)]
    struct PkgInput { name: String, version: String, ecosystem: String }

    let inputs: Vec<PkgInput> = serde_json::from_str(packages_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid JSON: {}", e)))?;

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

    let mut client = OsvClient::new();

    let tuples: Vec<_> = inputs.iter()
        .map(|p| (p.name.clone(), p.version.clone(), Ecosystem::from_pkg_manager(&p.ecosystem)))
        .collect();

    let batch_results = runtime.block_on(client.query_batch(tuples));

    let cwe_re = regex::Regex::new(r"CWE-\d+").unwrap();
    let now = chrono_lite_now();

    let results: Vec<CveCheckResult> = inputs.into_iter().zip(batch_results.unwrap_or_default()).map(|(input, vulns): (_, Vec<_>)| {
        let vulns_out: Vec<CveEntry> = vulns.into_iter().map(|v| {
            let details_str = v.details.as_deref().unwrap_or("");
            let cwe_ids = cwe_re.find_iter(details_str)
                .map(|m| m.as_str().to_string())
                .collect();
            CveEntry {
                id: v.id,
                summary: v.summary.unwrap_or_default(),
                severity: v.severity,
                cwe_ids,
                aliases: vec![],
            }
        }).collect();

        CveCheckResult {
            package: input.name,
            version: input.version,
            ecosystem: input.ecosystem,
            vulnerabilities: vulns_out,
            checked_at: now.clone(),
        }
    }).collect();

    serde_json::to_string(&results)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

// ============================================================================
// Supply Chain: Lock File Parsing
// ============================================================================

use crate::scanner::supplychain::lock_parser::{
    parse_package_lock, check_go_sum, check_requirements_hash_mode, parse_cargo_lock,
    LockPackage,
};

/// Parse a package-lock.json file and check integrity.
#[pyfunction]
fn parse_npm_lock(content: &str) -> PyResult<String> {
    let packages = parse_package_lock(content)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let results: Vec<serde_json::Value> = packages.into_iter().map(|p: LockPackage| {
        serde_json::json!({
            "name": p.name,
            "version": p.version,
            "has_integrity": p.integrity_hash.is_some(),
            "integrity_hash": p.integrity_hash,
            "has_git_source": p.has_git_source,
            "has_http_source": p.has_http_source,
            "resolved_url": p.resolved_url,
        })
    }).collect();

    serde_json::to_string(&results)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Check go.sum for missing integrity hashes.
#[pyfunction]
fn check_go_sum_integrity(content: &str) -> PyResult<String> {
    let results = check_go_sum(content);
    let output: Vec<serde_json::Value> = results.into_iter().map(|r| {
        serde_json::json!({
            "package": r.package,
            "status": format!("{:?}", r.status),
            "message": r.message,
        })
    }).collect();
    serde_json::to_string(&output)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Check requirements.txt for missing --hash= entries.
#[pyfunction]
fn check_requirements_integrity(content: &str) -> PyResult<String> {
    let results = check_requirements_hash_mode(content);
    let output: Vec<serde_json::Value> = results.into_iter().map(|r| {
        serde_json::json!({
            "package": r.package,
            "status": format!("{:?}", r.status),
            "message": r.message,
        })
    }).collect();
    serde_json::to_string(&output)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Parse Cargo.lock and extract packages with licenses.
#[pyfunction]
fn parse_cargo_lock_packages(content: &str) -> PyResult<String> {
    let packages = parse_cargo_lock(content);
    let output: Vec<serde_json::Value> = packages.into_iter().map(|p: LockPackage| {
        serde_json::json!({
            "name": p.name,
            "version": p.version,
            "integrity_hash": p.integrity_hash,
            "resolved_url": p.resolved_url,
        })
    }).collect();
    serde_json::to_string(&output)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

// ============================================================================
// Supply Chain: SBOM Generation
// ============================================================================

use crate::scanner::supplychain::license::{
    generate_spdx_from_packages, generate_cyclonedx_from_packages,
    detect_from_license_file, detect_from_package_json, detect_from_cargo_toml, DetectedLicense,
};

/// Generate SPDX SBOM from npm package-lock.json content.
#[pyfunction]
fn generate_spdx_sbom(lock_content: &str, project_name: &str) -> PyResult<String> {
    let packages = parse_package_lock(lock_content)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let sbom = generate_spdx_from_packages(&packages, project_name);
    serde_json::to_string_pretty(&sbom)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Generate CycloneDX SBOM from npm package-lock.json content.
#[pyfunction]
fn generate_cyclonedx_sbom(lock_content: &str, project_name: &str) -> PyResult<String> {
    let packages = parse_package_lock(lock_content)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let sbom = generate_cyclonedx_from_packages(&packages, project_name);
    serde_json::to_string_pretty(&sbom)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Detect licenses from LICENSE file content.
#[pyfunction]
fn detect_licenses_from_file(content: &str) -> PyResult<String> {
    let licenses = detect_from_license_file(content);
    let output: Vec<serde_json::Value> = licenses.into_iter().map(|l: DetectedLicense| {
        let source = match l.source {
            crate::scanner::supplychain::license::LicenseSource::File { path } => {
                serde_json::json!({ "type": "file", "path": path })
            }
            crate::scanner::supplychain::license::LicenseSource::PackageManifest => {
                serde_json::json!({ "type": "package_manifest" })
            }
            crate::scanner::supplychain::license::LicenseSource::LockFile => {
                serde_json::json!({ "type": "lock_file" })
            }
            crate::scanner::supplychain::license::LicenseSource::CargoLock => {
                serde_json::json!({ "type": "cargo_lock" })
            }
        };
        serde_json::json!({
            "spdx_id": l.spdx_id,
            "source": source,
            "package": l.package,
        })
    }).collect();
    serde_json::to_string(&output)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Detect licenses from package.json content.
#[pyfunction]
fn detect_licenses_package_json(content: &str) -> PyResult<String> {
    let licenses = detect_from_package_json(content);
    let output: Vec<serde_json::Value> = licenses.into_iter().map(|l: DetectedLicense| {
        serde_json::json!({
            "spdx_id": l.spdx_id,
            "source": "package_manifest",
            "package": l.package,
        })
    }).collect();
    serde_json::to_string(&output)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Detect licenses from Cargo.toml content.
#[pyfunction]
fn detect_licenses_cargo_toml(content: &str) -> PyResult<String> {
    let licenses = detect_from_cargo_toml(content);
    let output: Vec<serde_json::Value> = licenses.into_iter().map(|l: DetectedLicense| {
        serde_json::json!({
            "spdx_id": l.spdx_id,
            "source": "cargo_toml",
            "package": l.package,
        })
    }).collect();
    serde_json::to_string(&output)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

// ============================================================================
// Supply Chain: Dependency Scanning Pipeline
// ============================================================================

/// Scan a project directory for dependency vulnerabilities.
///
/// Discovers lock files, optionally checks them against OSV.dev for CVEs,
/// and optionally checks license compliance. Returns a JSON string.
#[pyfunction]
fn scan_dependencies(root: &str, check_cve: bool, check_license: bool) -> PyResult<String> {
    let root_path = std::path::Path::new(root);
    if !root_path.exists() {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Path does not exist: {}", root
        )));
    }

    let lock_files = discover_lock_files(root_path);
    let mut all_findings: Vec<DependencyFinding> = Vec::new();

    for lf in &lock_files {
        let Some(packages) = parse_lock_file(&lf.path) else {
            continue;
        };

        let Some(pkg_json) = lf.path.file_name().and_then(|n| n.to_str()) else {
            continue
        };

        // License compliance check
        if check_license {
            for pkg in &packages {
                if let Ok(content) = std::fs::read_to_string(&lf.path) {
                    let licenses = crate::scanner::supplychain::license::detect_from_license_file(&content);
                    for lic in licenses {
                        all_findings.push(DependencyFinding {
                            package: pkg.name.clone(),
                            version: pkg.version.clone(),
                            ecosystem: lf.ecosystem_label().to_string(),
                            kind: "license".to_string(),
                            description: format!("License: {}", lic.spdx_id),
                            cve_id: None,
                            cvss_score: None,
                            fixed_version: None,
                            lock_file: Some(pkg_json.to_string()),
                        });
                    }
                }
            }
        }

        // CVE check via OSV.dev (batch API)
        if check_cve && !packages.is_empty() {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

            let mut osv = OsvClient::new();

            // Collect packages with versions for batch query
            let query_pkgs: Vec<_> = packages.iter()
                .filter(|p| !p.version.is_empty())
                .map(|p| (p.name.clone(), p.version.clone(), lf.ecosystem))
                .collect();

            // Process in batches of up to 1000 (OSV API limit)
            let batch_size = 1000;
            for chunk in query_pkgs.chunks(batch_size) {
                match rt.block_on(osv.query_batch(chunk.to_vec())) {
                    Ok(results) => {
                        let osv_results: Vec<Vec<_>> = results;
                        for (vulns, pkg) in osv_results.into_iter().zip(chunk.iter()) {
                            for v in vulns {
                                all_findings.push(DependencyFinding {
                                    package: pkg.0.clone(),
                                    version: pkg.1.clone(),
                                    ecosystem: lf.ecosystem_label().to_string(),
                                    kind: "cve".to_string(),
                                    description: v.summary.unwrap_or_else(|| v.id.clone()),
                                    cve_id: Some(v.id),
                                    cvss_score: v.cvss_score,
                                    fixed_version: v.fixed_version,
                                    lock_file: Some(pkg_json.to_string()),
                                });
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("OSV batch query failed: {}", e);
                    }
                }
            }
        }
    }

    let result = ScanResult {
        findings: vec![],
        total_lines: 0,
        language: String::new(),
        file_path: None,
        scan_time_ms: 0,
        rules_evaluated: 0,
        severity_counts: SeverityCounts::default(),
        dependency_findings: Some(all_findings),
        sbom: None,
        taint_findings: None,
    };

    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Discover lock files in a project directory and return as JSON.
#[pyfunction]
fn discover_lockfiles(root: &str) -> PyResult<String> {
    let root_path = std::path::Path::new(root);
    if !root_path.exists() {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Path does not exist: {}", root
        )));
    }

    let files = discover_lock_files(root_path);
    let output: Vec<serde_json::Value> = files
        .into_iter()
        .map(|f| {
            serde_json::json!({
                "path": f.path.to_string_lossy(),
                "ecosystem": f.ecosystem_label(),
                "file_name": f.file_name,
            })
        })
        .collect();

    serde_json::to_string(&output)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

// ============================================================================
// Taint Analysis (Python API)
// ============================================================================

use crate::scanner::taint::engine::TaintEngine;
use crate::scanner::taint::rules::all_taint_rules;
use crate::scanner::ln_ast::LnAst;

/// Run taint analysis on source code.
#[pyfunction]
fn run_taint_analysis(code: &str, language: &str) -> PyResult<String> {
    let output = run_taint_analysis_internal(code, language)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;

    serde_json::to_string(&output)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Scan code with security rules and optional taint analysis.
#[pyfunction]
fn scan_security_with_taint(code: &str, language: &str, enable_taint: bool) -> PyResult<String> {
    let lang = if language.is_empty() { "python" } else { language };
    let start = Instant::now();

    // Parse AST
    let tree = match crate::scanner::tree_sitter::parse(code) {
        Ok(t) => t,
        Err(_) => {
            let result = ScanResult {
                findings: vec![],
                total_lines: code.lines().count(),
                language: lang.to_string(),
                file_path: None,
                scan_time_ms: start.elapsed().as_millis() as u64,
                rules_evaluated: 0,
                severity_counts: SeverityCounts::default(),
                dependency_findings: None,
                sbom: None,
                taint_findings: None,
            };
            return serde_json::to_string(&result)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()));
        }
    };

    // Security rules
    let security_rules = all_security_rules();
    let ast_rules = all_ast_rules();
    let all_rules: Vec<_> = security_rules.into_iter().chain(ast_rules.into_iter()).collect();
    let rules_evaluated = all_rules.len();

    let mut raw_findings: Vec<Value> = all_rules
        .par_iter()
        .flat_map(|rule| {
            rule.detect(&tree, code)
                .into_iter()
                .map(|finding| {
                    let replacement = if finding.auto_fix_available {
                        rule.fix(&finding, code).map(|f| f.replacement).unwrap_or_default()
                    } else {
                        String::new()
                    };
                    json!({
                        "id": rule.id(),
                        "rule_id": finding.rule_id,
                        "name": rule.name(),
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
                        "replacement": replacement,
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();

    raw_findings.sort_by_key(|f| f["start"].as_u64().unwrap_or(0));
    let findings = findings_to_json(raw_findings.clone());
    let severity_counts = count_severities(&findings);

    // Taint analysis if enabled
    let taint_findings: Option<Vec<Value>> = if enable_taint {
        match run_taint_analysis_internal(code, lang) {
            Ok(findings) => Some(findings),
            Err(e) => {
                eprintln!("Taint analysis failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    let result = ScanResult {
        findings,
        total_lines: code.lines().count(),
        language: lang.to_string(),
        file_path: None,
        scan_time_ms: start.elapsed().as_millis() as u64,
        rules_evaluated,
        severity_counts,
        dependency_findings: None,
        sbom: None,
        taint_findings,
    };

    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Scan code with security rules and optional AI security analysis.
#[pyfunction]
fn scan_security_with_ai(code: &str, language: &str, options_json: Option<&str>) -> PyResult<String> {
    let options: ScanOptions = match options_json {
        Some(json_str) => serde_json::from_str(json_str)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?,
        None => ScanOptions::default(),
    };
    let lang = if language.is_empty() { "python" } else { language };
    let start = Instant::now();

    // Parse AST
    let tree = match crate::scanner::tree_sitter::parse(code) {
        Ok(t) => t,
        Err(_) => {
            let result = ScanResult {
                findings: vec![],
                total_lines: code.lines().count(),
                language: lang.to_string(),
                file_path: None,
                scan_time_ms: start.elapsed().as_millis() as u64,
                rules_evaluated: 0,
                severity_counts: SeverityCounts::default(),
                dependency_findings: None,
                sbom: None,
                taint_findings: None,
            };
            return serde_json::to_string(&result)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()));
        }
    };

    // Security rules
    let security_rules = all_security_rules();
    let ast_rules = all_ast_rules();
    let all_rules: Vec<_> = security_rules.into_iter().chain(ast_rules.into_iter()).collect();
    let rules_evaluated = all_rules.len();

    let mut raw_findings: Vec<Value> = all_rules
        .par_iter()
        .flat_map(|rule| {
            rule.detect(&tree, code)
                .into_iter()
                .map(|finding| {
                    let replacement = if finding.auto_fix_available {
                        rule.fix(&finding, code).map(|f| f.replacement).unwrap_or_default()
                    } else {
                        String::new()
                    };
                    json!({
                        "id": rule.id(),
                        "rule_id": finding.rule_id,
                        "name": rule.name(),
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
                        "replacement": replacement,
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();

    raw_findings.sort_by_key(|f| f["start"].as_u64().unwrap_or(0));
    let findings = findings_to_json(raw_findings.clone());
    let severity_counts = count_severities(&findings);

    // AI security analysis if enabled
    let ai_findings: Option<Vec<Value>> = if options.ai_security {
        let scanner = AiSecurityScanner::new();
        let ai_results = scanner.scan(code, lang);
        Some(ai_results.iter().map(|f| {
            json!({
                "rule_id": f.rule_id,
                "severity": f.severity,
                "vulnerability_type": f.vulnerability_type.as_str(),
                "problem": f.problem,
                "line": f.line,
                "column": f.column,
                "snippet": f.snippet,
                "fix_hint": f.fix_hint,
                "auto_fix_available": f.auto_fix_available,
                "confidence": f.confidence,
                "attack_vector": f.attack_vector,
            })
        }).collect())
    } else {
        None
    };

    // Merge AI findings into main findings if present
    let final_findings = if let Some(ai) = ai_findings {
        let mut combined = findings;
        combined.extend(ai);
        combined
    } else {
        findings
    };

    let result = ScanResult {
        findings: final_findings,
        total_lines: code.lines().count(),
        language: lang.to_string(),
        file_path: None,
        scan_time_ms: start.elapsed().as_millis() as u64,
        rules_evaluated,
        severity_counts,
        dependency_findings: None,
        sbom: None,
        taint_findings: None,
    };

    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Scan a file with full options including taint and interprocedural analysis.
#[pyfunction]
fn scan_file_with_options(path: &str, options: ScanOptions) -> PyResult<String> {
    use std::fs;

    let code = fs::read_to_string(path)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!(
            "Failed to read file {}: {}", path, e
        )))?;

    let start = Instant::now();

    // Detect language from extension
    let path_obj = std::path::Path::new(path);
    let ext = path_obj
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let language = crate::scanner::multilang::detect_language_from_extension(ext)
        .unwrap_or_else(|| "python".to_string());

    // Parse AST
    let tree = match crate::scanner::tree_sitter::parse(&code) {
        Ok(t) => t,
        Err(_) => {
            let result = ScanResult {
                findings: vec![],
                total_lines: code.lines().count(),
                language: language.clone(),
                file_path: Some(path.to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                rules_evaluated: 0,
                severity_counts: SeverityCounts::default(),
                dependency_findings: None,
                sbom: None,
                taint_findings: None,
            };
            return serde_json::to_string(&result)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()));
        }
    };

    // Security rules
    let security_rules = all_security_rules();
    let ast_rules = all_ast_rules();
    let all_rules: Vec<_> = security_rules.into_iter().chain(ast_rules.into_iter()).collect();
    let rules_evaluated = all_rules.len();

    let mut raw_findings: Vec<Value> = all_rules
        .par_iter()
        .flat_map(|rule| {
            rule.detect(&tree, &code)
                .into_iter()
                .map(|finding| {
                    let replacement = if finding.auto_fix_available {
                        rule.fix(&finding, &code).map(|f| f.replacement).unwrap_or_default()
                    } else {
                        String::new()
                    };
                    json!({
                        "id": rule.id(),
                        "rule_id": finding.rule_id,
                        "name": rule.name(),
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
                        "replacement": replacement,
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();

    raw_findings.sort_by_key(|f| f["start"].as_u64().unwrap_or(0));
    let findings = findings_to_json(raw_findings.clone());
    let severity_counts = count_severities(&findings);

    // Taint analysis if enabled
    let taint_findings: Option<Vec<Value>> = if options.taint {
        match run_taint_analysis_internal(&code, &language) {
            Ok(findings) => Some(findings),
            Err(e) => {
                eprintln!("Taint analysis failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    let result = ScanResult {
        findings,
        total_lines: code.lines().count(),
        language,
        file_path: Some(path.to_string()),
        scan_time_ms: start.elapsed().as_millis() as u64,
        rules_evaluated,
        severity_counts,
        dependency_findings: None,
        sbom: None,
        taint_findings,
    };

    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

// ============================================================================
// AI Security Scanner (Python API)
// ============================================================================

/// Get all available AI security rules.
/// Returns a JSON array of AI rule metadata.
#[pyfunction]
fn get_ai_rules() -> PyResult<String> {
    let scanner = AiSecurityScanner::new();
    let rules: Vec<serde_json::Value> = scanner.rules.iter().map(|rule| {
        serde_json::json!({
            "id": rule.id(),
            "name": rule.name(),
            "vulnerability_type": rule.vulnerability_type().as_str(),
            "description": rule.description(),
            "severity": rule.severity(),
            "confidence": rule.confidence(),
            "category": "ai_security",
        })
    }).collect();

    serde_json::to_string(&rules)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Scan code for AI-specific security vulnerabilities including MCP rules.
#[pyfunction]
fn scan_ai_security(code: &str, language: &str) -> PyResult<String> {
    let scanner = AiSecurityScanner::new();
    let findings = scanner.scan(code, language);

    let output: Vec<serde_json::Value> = findings.iter().map(|f| {
        serde_json::json!({
            "rule_id": f.rule_id,
            "severity": f.severity,
            "vulnerability_type": f.vulnerability_type.as_str(),
            "problem": f.problem,
            "line": f.line,
            "column": f.column,
            "snippet": f.snippet,
            "fix_hint": f.fix_hint,
            "auto_fix_available": f.auto_fix_available,
            "confidence": f.confidence,
            "attack_vector": f.attack_vector,
        })
    }).collect();

    serde_json::to_string(&output)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

// ============================================================================
// Utility
// ============================================================================

fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    let secs = now.as_secs();
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let mins = (remaining % 3600) / 60;
    let seconds = remaining % 60;
    let year = 1970 + days / 365;
    let day_of_year = days % 365;
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days: [u64; 12] = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1;
    let mut day_rem = day_of_year;
    for (i, &md) in month_days.iter().enumerate() {
        if day_rem < md {
            month = i + 1;
            break;
        }
        day_rem -= md;
    }
    let day = day_rem + 1;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hours, mins, seconds)
}

/// Python module definition
#[pymodule]
fn pyneat_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_security, m)?)?;
    m.add_function(wrap_pyfunction!(scan_security_configured, m)?)?;
    m.add_function(wrap_pyfunction!(apply_auto_fix, m)?)?;
    m.add_function(wrap_pyfunction!(apply_fixes_batch, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(get_scanner_version, m)?)?;
    m.add_function(wrap_pyfunction!(get_rules, m)?)?;
    m.add_function(wrap_pyfunction!(parse_ln_ast, m)?)?;
    m.add_function(wrap_pyfunction!(detect_language, m)?)?;
    m.add_function(wrap_pyfunction!(supported_languages, m)?)?;
    m.add_function(wrap_pyfunction!(scan_multilang, m)?)?;

    // Supply chain: CVE / OSV
    m.add_function(wrap_pyfunction!(cve_check_package, m)?)?;
    m.add_function(wrap_pyfunction!(cve_check_batch, m)?)?;

    // Supply chain: Lock file parsing
    m.add_function(wrap_pyfunction!(parse_npm_lock, m)?)?;
    m.add_function(wrap_pyfunction!(check_go_sum_integrity, m)?)?;
    m.add_function(wrap_pyfunction!(check_requirements_integrity, m)?)?;
    m.add_function(wrap_pyfunction!(parse_cargo_lock_packages, m)?)?;

    // Supply chain: SBOM
    m.add_function(wrap_pyfunction!(generate_spdx_sbom, m)?)?;
    m.add_function(wrap_pyfunction!(generate_cyclonedx_sbom, m)?)?;

    // Supply chain: License detection
    m.add_function(wrap_pyfunction!(detect_licenses_from_file, m)?)?;
    m.add_function(wrap_pyfunction!(detect_licenses_package_json, m)?)?;
    m.add_function(wrap_pyfunction!(detect_licenses_cargo_toml, m)?)?;

    // Supply chain: Dependency scanning pipeline
    m.add_function(wrap_pyfunction!(scan_dependencies, m)?)?;
    m.add_function(wrap_pyfunction!(discover_lockfiles, m)?)?;

    // Taint analysis
    m.add_function(wrap_pyfunction!(run_taint_analysis, m)?)?;
    m.add_function(wrap_pyfunction!(scan_security_with_taint, m)?)?;
    m.add_function(wrap_pyfunction!(scan_file_with_options, m)?)?;

    // AI security
    m.add_function(wrap_pyfunction!(get_ai_rules, m)?)?;
    m.add_function(wrap_pyfunction!(scan_ai_security, m)?)?;
    m.add_function(wrap_pyfunction!(scan_security_with_ai, m)?)?;

    // LSP server
    m.add_function(wrap_pyfunction!(run_lsp_server, m)?)?;

    // Rule configuration
    m.add_function(wrap_pyfunction!(get_rule_config_schema, m)?)?;

    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

/// Run the LSP server with Python-provided configuration.
#[pyfunction]
fn run_lsp_server(
    scan_on_save: bool,
    scan_on_type: bool,
    debounce_ms: u64,
    severity: &str,
    rules: Option<String>,
) -> PyResult<()> {
    let config = LspConfig {
        severity_threshold: severity.to_string(),
        scan_on_save,
        debounce_ms,
        enable_real_time: scan_on_type,
        enabled_rules: rules
            .map(|s| s.split(',').map(|v| v.trim().to_string()).collect())
            .unwrap_or_default(),
    };
    lsp::run_server_with_config(config);
    Ok(())
}
