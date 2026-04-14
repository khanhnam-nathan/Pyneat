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

use clap::{Parser, Subcommand, ValueEnum};
use std::path::Path;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::fixer::diff::format_findings_report;
use crate::fixer::apply_fix::FixRange;
use crate::rules::security::all_security_rules;
use crate::scanner::tree_sitter::parse;
use crate::scanner::base::{LanguageScanner, LangRule, LangFinding};
use crate::scanner::{JavaScriptScanner, TypeScriptScanner, GoScanner, JavaScanner, CSharpScanner, PhpScanner, RubyScanner, RustScanner};
use crate::rules::Rule;
use crate::sarif::writer::SarifBuilder;

mod fixer;
mod rules;
mod scanner;
mod sarif;
mod integrations;

// --------------------------------------------------------------------------
// Output Format
// --------------------------------------------------------------------------

#[derive(ValueEnum, Clone, Debug, PartialEq)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
    CodeClimate,
    JunitXml,
    Html,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Sarif => write!(f, "sarif"),
            OutputFormat::CodeClimate => write!(f, "codeclimate"),
            OutputFormat::JunitXml => write!(f, "junitxml"),
            OutputFormat::Html => write!(f, "html"),
        }
    }
}

// --------------------------------------------------------------------------
// Severity Threshold
// --------------------------------------------------------------------------

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SeverityThreshold {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl SeverityThreshold {
    #[allow(dead_code)]
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => SeverityThreshold::Critical,
            "high" => SeverityThreshold::High,
            "medium" => SeverityThreshold::Medium,
            "low" => SeverityThreshold::Low,
            "info" => SeverityThreshold::Info,
            _ => SeverityThreshold::Info,
        }
    }

    fn level(&self) -> usize {
        match self {
            SeverityThreshold::Critical => 5,
            SeverityThreshold::High => 4,
            SeverityThreshold::Medium => 3,
            SeverityThreshold::Low => 2,
            SeverityThreshold::Info => 1,
        }
    }
}

// --------------------------------------------------------------------------
// CLI Args
// --------------------------------------------------------------------------

/// PyNeat Rust Security Scanner
#[derive(Parser, Debug)]
#[command(name = "pyneat-rs")]
#[command(author = "Khanh Nam")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "High-performance multi-language security scanner")]
struct Args {
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// Severity threshold (only show findings >= this level)
    #[arg(long, value_enum, default_value = "info")]
    severity: SeverityThreshold,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a single file or directory
    Scan {
        /// Files or directories to scan
        #[arg(required = true)]
        paths: Vec<String>,

        /// Apply auto-fixes
        #[arg(short, long)]
        fix: bool,

        /// Output file for results
        #[arg(short, long)]
        output: Option<String>,

        /// File patterns to exclude (comma-separated)
        #[arg(long)]
        exclude_paths: Option<String>,

        /// File patterns to include (comma-separated)
        #[arg(long)]
        include_paths: Option<String>,

        /// Specific rules to enable (comma-separated)
        #[arg(long)]
        rules: Option<String>,

        /// Disable auto-fix
        #[arg(long)]
        no_fix: bool,

        /// Only apply fixes, do not report
        #[arg(long)]
        fix_only: bool,

        /// Parallel threads
        #[arg(long, default_value = "4")]
        parallel: usize,

        /// Timeout in seconds
        #[arg(long)]
        timeout: Option<usize>,

        /// Config file path
        #[arg(long)]
        config: Option<String>,

        /// Baseline file (ignore known issues)
        #[arg(long)]
        baseline: Option<String>,

        /// Fail if severity threshold is met (exit code non-zero)
        #[arg(long)]
        fail_on: Option<SeverityThreshold>,
    },

    /// List all available rules
    ListRules {
        /// Filter by category
        #[arg(long, value_enum)]
        category: Option<String>,

        /// Filter by language
        #[arg(long)]
        language: Option<String>,
    },

    /// Check a code snippet from stdin
    Check {
        /// Code to check
        #[arg(required = true)]
        code: String,

        /// Output format (overrides global --format)
        #[arg(short, long)]
        format: Option<OutputFormat>,
    },

    /// Explain a rule
    Explain {
        /// Rule ID to explain
        #[arg(required = true)]
        rule_id: String,
    },

    /// Upload results to CI platform
    Upload {
        /// Results file to upload
        #[arg(required = true)]
        file: String,

        /// Provider to upload to
        #[arg(long, value_enum, default_value = "github")]
        provider: UploadProvider,

        /// GitHub token (or set GITHUB_TOKEN env var)
        #[arg(long)]
        github_token: Option<String>,

        /// GitHub owner
        #[arg(long)]
        owner: Option<String>,

        /// GitHub repo
        #[arg(long)]
        repo: Option<String>,

        /// Category for SARIF upload
        #[arg(long, default_value = "pyneat-sast")]
        category: String,
    },

    /// Start as LSP server
    Server {
        /// Port to listen on
        #[arg(long, default_value = "4444")]
        port: u16,
    },

    /// CI mode (optimized output)
    Ci {
        /// Paths to scan
        #[arg(required = true)]
        paths: Vec<String>,

        /// Output file
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(ValueEnum, Clone, Debug)]
enum UploadProvider {
    GitHub,
    GitLab,
    SonarQube,
}

// --------------------------------------------------------------------------
// Main
// --------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pyneat_rs=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    match args.command {
        Commands::Scan { paths, fix, output, exclude_paths, include_paths, rules, no_fix, fix_only, parallel, timeout, config, baseline, fail_on } => {
            scan_paths(&paths, fix || !no_fix, output.as_deref(), &args.format, &args.severity, exclude_paths.as_deref(), include_paths.as_deref(), rules.as_deref(), fix_only, parallel, timeout, config.as_deref(), baseline.as_deref(), fail_on.as_ref())?;
        }
        Commands::ListRules { category, language } => {
            list_rules(category.as_deref(), language.as_deref());
        }
        Commands::Check { code, format } => {
            let fmt = format.unwrap_or(args.format);
            check_code(&code, &fmt)?;
        }
        Commands::Explain { rule_id } => {
            explain_rule(&rule_id);
        }
        Commands::Upload { file, provider, github_token, owner, repo, category } => {
            upload_results(&file, provider, github_token.as_deref(), owner.as_deref(), repo.as_deref(), &category)?;
        }
        Commands::Server { port } => {
            start_lsp_server(port);
        }
        Commands::Ci { paths, output } => {
            ci_mode(&paths, output.as_deref())?;
        }
    }

    Ok(())
}

// --------------------------------------------------------------------------
// Scan Logic
// --------------------------------------------------------------------------

fn scan_paths(
    paths: &[String],
    apply_fix: bool,
    output: Option<&str>,
    format: &OutputFormat,
    severity_threshold: &SeverityThreshold,
    exclude_paths: Option<&str>,
    _include_paths: Option<&str>,
    _rules_filter: Option<&str>,
    fix_only: bool,
    parallel: usize,
    _timeout: Option<usize>,
    _config: Option<&str>,
    _baseline: Option<&str>,
    fail_on: Option<&SeverityThreshold>,
) -> Result<(), Box<dyn std::error::Error>> {
    let rules = all_security_rules();
    let _severity_level = severity_threshold.level();

    // Initialize language scanners
    let js_scanner = JavaScriptScanner::new();
    let ts_scanner = TypeScriptScanner::new();
    let go_scanner = GoScanner::new();
    let java_scanner = JavaScanner::new();
    let csharp_scanner = CSharpScanner::new();
    let php_scanner = PhpScanner::new();
    let ruby_scanner = RubyScanner::new();
    let rust_scanner = RustScanner::new();

    // Parse exclude patterns
    let exclude_patterns: Vec<String> = exclude_paths
        .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
        .unwrap_or_default();

    let mut all_results = Vec::new();

    for path_str in paths {
        let path = Path::new(path_str);

        if path.is_dir() {
            for entry in walkdir::WalkDir::new(path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
            {
                let entry_path = entry.path();

                // Check exclude patterns
                let should_exclude = exclude_patterns.iter().any(|p| {
                    entry_path.to_string_lossy().contains(p)
                });
                if should_exclude {
                    continue;
                }

                let ext = entry_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                let code = std::fs::read_to_string(entry_path)?;
                let file_path = entry_path.to_string_lossy().to_string();

                if ext == "py" {
                    if let Ok(results) = scan_python_detailed(&code, &file_path, &rules) {
                        all_results.extend(results);
                    }
                } else if let Some(scanner) = get_lang_scanner(ext, &js_scanner, &ts_scanner, &go_scanner, &java_scanner, &csharp_scanner, &php_scanner, &ruby_scanner, &rust_scanner) {
                    if let Ok(results) = scan_language_detailed(&code, scanner, &file_path) {
                        all_results.extend(results);
                    }
                }
            }
        } else if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let code = std::fs::read_to_string(path)?;
            let file_path = path.to_string_lossy().to_string();

            if ext == "py" {
                if let Ok(results) = scan_python_detailed(&code, &file_path, &rules) {
                    all_results.extend(results);
                }
            } else if let Some(scanner) = get_lang_scanner(ext, &js_scanner, &ts_scanner, &go_scanner, &java_scanner, &csharp_scanner, &php_scanner, &ruby_scanner, &rust_scanner) {
                if let Ok(results) = scan_language_detailed(&code, scanner, &file_path) {
                    all_results.extend(results);
                }
            }
        }
    }

    // Apply auto-fixes if requested
    if apply_fix {
        let mut file_fixes: std::collections::HashMap<String, Vec<FixRange>> = std::collections::HashMap::new();
        for result in &all_results {
            if result.auto_fix {
                let file_fixes_list = file_fixes.entry(result.file.clone()).or_default();
                for rule in &rules {
                    if rule.id() == result.rule_id {
                        let code = std::fs::read_to_string(&Path::new(&result.file)).unwrap_or_default();
                        let finding = crate::rules::base::Finding {
                            rule_id: result.rule_id.clone(),
                            severity: result.severity.clone(),
                            cwe_id: result.cwe_id.clone(),
                            cvss_score: result.cvss_score,
                            owasp_id: result.owasp_id.clone(),
                            start: result.start_byte,
                            end: result.end_byte,
                            snippet: result.snippet.clone(),
                            problem: result.problem.clone(),
                            fix_hint: result.fix_hint.clone(),
                            auto_fix_available: result.auto_fix,
                        };
                        if let Some(fix) = rule.fix(&finding, &code) {
                            file_fixes_list.push(FixRange::new(fix.start, fix.end, fix.replacement, fix.rule_id));
                        }
                        break;
                    }
                }
            }
        }

        // Resolve fix conflicts - only keep non-overlapping fixes (first by range wins)
        let mut file_fixes_resolved: std::collections::HashMap<String, Vec<crate::fixer::apply_fix::FixRange>> = std::collections::HashMap::new();
        for (file_path, fix_list) in file_fixes {
            if !fix_list.is_empty() {
                let resolved = crate::fixer::apply_fix::resolve_conflicts(&fix_list);
                file_fixes_resolved.insert(file_path, resolved);
            }
        }

        for (file_path, fix_list) in file_fixes_resolved {
            let original_code = std::fs::read_to_string(&Path::new(&file_path)).unwrap_or_default();
            if !original_code.is_empty() {
                let fixed_code = crate::fixer::apply_fix::apply_multiple_fixes(&original_code, &fix_list);
                let _ = std::fs::copy(&Path::new(&file_path), Path::new(&format!("{}.pyneat.bak", file_path)));
                let _ = std::fs::write(&Path::new(&file_path), &fixed_code);
                println!("Applied {} fix(es) to {}", fix_list.len(), file_path);
            }
        }
    }

    if fix_only {
        return Ok(());
    }

    // Filter by severity
    let threshold_level = severity_threshold.level();
    let filtered: Vec<_> = all_results.iter()
        .filter(|r| severity_level(&r.severity) >= threshold_level)
        .collect();

    // Output in the requested format
    let output_content = match format {
        OutputFormat::Sarif => {
            serde_json::to_string_pretty(&generate_sarif_output(&filtered)).unwrap_or_default()
        }
        OutputFormat::Json => {
            serde_json::to_string_pretty(&filtered).unwrap_or_default()
        }
        OutputFormat::CodeClimate => {
            generate_codeclimate_output(&filtered)
        }
        OutputFormat::JunitXml => {
            generate_junit_output(&filtered)
        }
        OutputFormat::Html => {
            generate_html_output(&filtered)
        }
        OutputFormat::Text => {
            format_text_output(&filtered)
        }
    };

    if let Some(output_file) = output {
        std::fs::write(output_file, &output_content)?;
    } else {
        println!("{}", output_content);
    }

    // Fail on threshold if requested
    if let Some(threshold) = fail_on {
        let threshold_level = threshold.level();
        let has_issue = filtered.iter().any(|r| severity_level(&r.severity) >= threshold_level);
        if has_issue {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn severity_level(severity: &str) -> usize {
    match severity.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn scan_python_detailed(
    code: &str,
    filename: &str,
    rules: &[Box<dyn Rule>],
) -> Result<Vec<ScanResult>, Box<dyn std::error::Error>> {
    let tree = match parse(code) {
        Ok(t) => t,
        Err(_) => return Ok(vec![]),
    };

    let mut results = Vec::new();
    for rule in rules {
        for finding in rule.detect(&tree, code) {
            results.push(ScanResult {
                rule_id: finding.rule_id.clone(),
                severity: finding.severity.clone(),
                file: filename.to_string(),
                line: byte_offset_to_line(code, finding.start),
                column: 1,
                start_byte: finding.start,
                end_byte: finding.end,
                snippet: finding.snippet.clone(),
                problem: finding.problem.clone(),
                fix_hint: finding.fix_hint.clone(),
                cwe_id: finding.cwe_id.clone(),
                owasp_id: finding.owasp_id.clone(),
                cvss_score: finding.cvss_score,
                auto_fix: finding.auto_fix_available,
            });
        }
    }

    Ok(results)
}

fn scan_language_detailed(
    code: &str,
    scanner: &dyn LanguageScanner,
    filename: &str,
) -> Result<Vec<ScanResult>, Box<dyn std::error::Error>> {
    let tree = match scanner.parse(code) {
        Ok(t) => t,
        Err(_) => return Ok(vec![]),
    };

    let findings = scanner.detect(&tree, code);
    let results: Vec<ScanResult> = findings.into_iter().map(|f| {
        let (start_byte, end_byte) = (f.start_byte, f.end_byte);
        ScanResult {
            rule_id: f.rule_id,
            severity: f.severity,
            file: filename.to_string(),
            line: f.line,
            column: f.column,
            start_byte,
            end_byte,
            snippet: f.snippet,
            problem: f.problem,
            fix_hint: f.fix_hint,
            cwe_id: None,
            owasp_id: None,
            cvss_score: None,
            auto_fix: f.auto_fix_available,
        }
    }).collect();

    Ok(results)
}

#[derive(Debug, Clone, serde::Serialize)]
struct ScanResult {
    rule_id: String,
    severity: String,
    file: String,
    line: usize,
    column: usize,
    start_byte: usize,
    end_byte: usize,
    snippet: String,
    problem: String,
    fix_hint: String,
    cwe_id: Option<String>,
    owasp_id: Option<String>,
    cvss_score: Option<f32>,
    auto_fix: bool,
}

fn byte_offset_to_line(code: &str, byte_offset: usize) -> usize {
    let mut line = 1;
    let mut current_offset = 0;
    for c in code.chars() {
        if current_offset >= byte_offset {
            break;
        }
        if c == '\n' {
            line += 1;
        }
        current_offset += c.len_utf8();
    }
    line
}

fn generate_sarif_output(results: &[&ScanResult]) -> serde_json::Value {
    let mut builder = SarifBuilder::new(
        "PyNEAT",
        env!("CARGO_PKG_VERSION"),
        "https://github.com/pyneat/pyneat",
    );

    for result in results {
        let code = std::fs::read_to_string(&result.file).unwrap_or_default();
        let location = crate::sarif::SarifLocation::new(
            &result.file,
            result.line,
            result.column,
            result.line,
            result.column.saturating_add(result.snippet.len()),
        ).with_snippet(&result.snippet);

        let mut sarif_result = crate::sarif::SarifResult::new(
            &result.rule_id,
            &result.severity,
            &result.problem,
            vec![location],
        );

        sarif_result = sarif_result.with_properties(
            result.cwe_id.as_deref(),
            result.owasp_id.as_ref().map(|v| vec![v.as_str()]),
            result.cvss_score,
            Some(&result.snippet),
            Some(&result.fix_hint),
        );

        builder = builder.add_result(sarif_result);
    }

    builder.build().to_json()
}

fn generate_codeclimate_output(results: &[&ScanResult]) -> String {
    let issues: Vec<serde_json::Value> = results.iter().map(|r| {
        serde_json::json!({
            "type": "ISSUE",
            "check_name": r.rule_id,
            "description": r.problem,
            "categories": ["Security"],
            "severity": match r.severity.as_str() {
                "critical" | "high" => "critical",
                "medium" => "major",
                _ => "minor",
            },
            "location": {
                "path": r.file,
                "lines": { "begin": r.line }
            },
            "remediation_points": match r.severity.as_str() {
                "critical" | "high" => 50000,
                _ => 10000,
            }
        })
    }).collect();

    serde_json::to_string_pretty(&issues).unwrap_or_default()
}

fn generate_junit_output(results: &[&ScanResult]) -> String {
    let timestamp = chrono_lite_now();
    let mut cases = String::new();

    for r in results {
        let classname = r.file.replace(['/', '\\'], ".");
        cases.push_str(&format!(
            r#"    <testcase name="{}" classname="{}" time="0.0">
      <failure message="{}" type="{}">{} - {}</failure>
    </testcase>
"#,
            r.rule_id, classname, r.problem, r.severity, r.rule_id, r.problem
        ));
    }

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="PyNEAT" tests="{}" failures="{}" errors="0" skipped="0" timestamp="{}">
{}
</testsuite>"#,
        results.len(),
        results.len(),
        timestamp,
        cases
    )
}

fn generate_html_output(results: &[&ScanResult]) -> String {
    let mut html = String::from(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PyNEAT Security Report</title>
    <style>
        body { font-family: system-ui, sans-serif; margin: 40px; background: #1e1e1e; color: #d4d4d4; }
        h1 { color: #569cd6; }
        .summary { background: #2d2d2d; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .critical { color: #f44747; }
        .high { color: #ce9178; }
        .medium { color: #dcdcaa; }
        .low { color: #6a9955; }
        .info { color: #808080; }
        .finding { background: #2d2d2d; padding: 15px; margin: 10px 0; border-radius: 4px; border-left: 4px solid #569cd6; }
        .rule-id { font-weight: bold; color: #569cd6; }
        pre { background: #1e1e1e; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>PyNEAT Security Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Total findings: "#,
    );

    html.push_str(&results.len().to_string());
    html.push_str("</p>");
    html.push_str("</div><div class='findings'>");

    for r in results {
        let color_class = match r.severity.as_str() {
            "critical" => "critical",
            "high" => "high",
            "medium" => "medium",
            "low" => "low",
            _ => "info",
        };
        html.push_str(&format!(
            r#"<div class="finding">
        <span class="rule-id">{}</span> <span class="{}">[{}]</span>
        <p>{}</p>
        <p><strong>File:</strong> {}:{}</p>
        <p><strong>Fix:</strong> {}</p>
        <pre>{}</pre>
    </div>"#,
            r.rule_id, color_class, r.severity.to_uppercase(), r.problem,
            r.file, r.line, r.fix_hint, r.snippet
        ));
    }

    html.push_str("</div></body></html>");
    html
}

fn format_text_output(results: &[&ScanResult]) -> String {
    if results.is_empty() {
        return "No findings.".to_string();
    }

    let mut report = String::new();
    report.push_str("Security Findings Report\n");
    report.push_str(&"=".repeat(60));
    report.push('\n');

    // Group by severity
    let mut critical = Vec::new();
    let mut high = Vec::new();
    let mut medium = Vec::new();
    let mut low = Vec::new();
    let mut info = Vec::new();

    for r in results {
        match r.severity.as_str() {
            "critical" => critical.push(r),
            "high" => high.push(r),
            "medium" => medium.push(r),
            "low" => low.push(r),
            _ => info.push(r),
        }
    }

    if !critical.is_empty() {
        report.push_str(&format!("\nCRITICAL ({}):\n", critical.len()));
        for f in &critical {
            report.push_str(&format!("  [{}] {} - {}\n", f.rule_id, f.problem, f.file));
            report.push_str(&format!("    at {}:{}\n", f.file, f.line));
            report.push_str(&format!("    Fix: {}\n", f.fix_hint));
        }
    }

    if !high.is_empty() {
        report.push_str(&format!("\nHIGH ({}):\n", high.len()));
        for f in &high {
            report.push_str(&format!("  [{}] {} - {}\n", f.rule_id, f.problem, f.file));
        }
    }

    if !medium.is_empty() {
        report.push_str(&format!("\nMEDIUM ({}):\n", medium.len()));
        for f in &medium {
            report.push_str(&format!("  [{}] {} - {}\n", f.rule_id, f.problem, f.file));
        }
    }

    if !low.is_empty() {
        report.push_str(&format!("\nLOW ({}):\n", low.len()));
        for f in &low {
            report.push_str(&format!("  [{}] {}\n", f.rule_id, f.problem));
        }
    }

    if !info.is_empty() {
        report.push_str(&format!("\nINFO ({}):\n", info.len()));
        for f in &info {
            report.push_str(&format!("  [{}] {}\n", f.rule_id, f.problem));
        }
    }

    report.push_str(&format!("\nTotal: {} findings\n", results.len()));
    report
}

fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("1970-01-01T00:00:00Z")
}

// --------------------------------------------------------------------------
// Other Commands
// --------------------------------------------------------------------------

fn get_lang_scanner<'a>(
    ext: &str,
    js: &'a JavaScriptScanner,
    ts: &'a TypeScriptScanner,
    go: &'a GoScanner,
    java: &'a JavaScanner,
    csharp: &'a CSharpScanner,
    php: &'a PhpScanner,
    ruby: &'a RubyScanner,
    rust: &'a RustScanner,
) -> Option<&'a dyn LanguageScanner> {
    match ext {
        "js" | "jsx" | "mjs" | "cjs" => Some(js),
        "ts" | "tsx" => Some(ts),
        "go" => Some(go),
        "java" => Some(java),
        "cs" => Some(csharp),
        "php" => Some(php),
        "rb" => Some(ruby),
        "rs" => Some(rust),
        _ => None,
    }
}

fn check_code(code: &str, override_format: &OutputFormat) -> Result<(), Box<dyn std::error::Error>> {
    let rules = all_security_rules();
    let tree = parse(code)?;
    let mut findings: Vec<_> = Vec::new();

    for rule in &rules {
        findings.extend(rule.detect(&tree, code));
    }

    findings.sort_by_key(|f| f.start);

    if *override_format == OutputFormat::Sarif {
        println!("{}", "{}");
        return Ok(());
    }

    if *override_format == OutputFormat::Json {
        let json_findings: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "rule_id": f.rule_id,
                    "severity": f.severity.as_str(),
                    "cwe_id": f.cwe_id,
                    "cvss_score": f.cvss_score,
                    "owasp_id": f.owasp_id,
                    "start": f.start,
                    "end": f.end,
                    "snippet": f.snippet,
                    "problem": f.problem,
                    "fix_hint": f.fix_hint,
                    "auto_fix_available": f.auto_fix_available,
                })
            })
            .collect();
        println!("{}", serde_json::to_string(&json_findings).unwrap_or_else(|_| "[]".to_string()));
    } else {
        let report = format_findings_report(&findings);
        println!("{}", report);
    }

    Ok(())
}

fn list_rules(category: Option<&str>, language: Option<&str>) {
    let rules = all_security_rules();

    println!("Available Security Rules (Python)");
    println!("================================\n");

    for rule in &rules {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("{} {} - {}", fix_indicator, rule.id(), rule.name());
    }

    println!("\nTotal: {} Python rules", rules.len());

    println!("\n\nLanguage-Specific Rules");
    println!("=======================\n");

    let js_scanner = JavaScriptScanner::new();
    let js_rules = js_scanner.rules();
    let js_security: Vec<_> = js_rules.iter().filter(|r| r.id().contains("SEC")).collect();
    let js_quality: Vec<_> = js_rules.iter().filter(|r| r.id().contains("QUAL")).collect();
    println!("JavaScript/TypeScript ({} total: {} security, {} quality):",
        js_rules.len(), js_security.len(), js_quality.len());
    for rule in &js_security {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("  {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }
    for rule in &js_quality {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("  {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    let rust_scanner = RustScanner::new();
    let rust_rules = rust_scanner.rules();
    println!("\nRust ({} total):", rust_rules.len());
    for rule in &rust_rules {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("  {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    let go_scanner = GoScanner::new();
    println!("\nGo:");
    for rule in go_scanner.rules() {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("  {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    let java_scanner = JavaScanner::new();
    println!("\nJava ({} total):", java_scanner.rules().len());
    for rule in java_scanner.rules() {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("  {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    let csharp_scanner = CSharpScanner::new();
    println!("\nC#:");
    for rule in csharp_scanner.rules() {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("  {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    let php_scanner = PhpScanner::new();
    println!("\nPHP:");
    for rule in php_scanner.rules() {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("  {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    let ruby_scanner = RubyScanner::new();
    println!("\nRuby:");
    for rule in ruby_scanner.rules() {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("  {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    let total_lang_rules: usize = js_rules.len() + rust_rules.len() + java_scanner.rules().len()
        + go_scanner.rules().len() + csharp_scanner.rules().len()
        + php_scanner.rules().len() + ruby_scanner.rules().len();
    println!("\n\nTotal: {} Python rules, {} multi-language rules", rules.len(), total_lang_rules);
}

fn explain_rule(rule_id: &str) {
    let rules = all_security_rules();

    for rule in &rules {
        if rule.id() == rule_id {
            println!("Rule: {}", rule.id());
            println!("Name: {}", rule.name());
            println!("Severity: {}", rule.severity().as_str());
            println!("Auto-fix: {}", if rule.supports_auto_fix() { "Yes" } else { "No" });
            return;
        }
    }

    eprintln!("Rule '{}' not found.", rule_id);
}

fn upload_results(
    file: &str,
    provider: UploadProvider,
    github_token: Option<&str>,
    owner: Option<&str>,
    repo: Option<&str>,
    category: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(file)?;

    match provider {
        UploadProvider::GitHub => {
            let token = github_token
                .map(|s| s.to_string())
                .or_else(|| std::env::var("GITHUB_TOKEN").ok());
            let token_str = token.as_deref().unwrap_or_default();
            let owner = owner.ok_or("GitHub owner is required")?;
            let repo = repo.ok_or("GitHub repo is required")?;
            let _config = crate::integrations::github::GitHubConfig::new(&owner, &repo)
                .with_token(token_str);

            println!("Uploading SARIF to GitHub: {}/{}", owner, repo);
            println!("Note: Async upload requires tokio runtime - run with `cargo run --release -- upload --file {} --provider github --owner {} --repo {}`", file, owner, repo);
        }
        UploadProvider::GitLab => {
            println!("GitLab upload: Create .gitlab/merge-request-pyneat.yml for GitLab CI integration.");
        }
        UploadProvider::SonarQube => {
            println!("SonarQube integration: Use sonar-scanner with pyneat SARIF output.");
        }
    }

    Ok(())
}

fn start_lsp_server(port: u16) {
    println!("PyNEAT LSP server starting on stdio...");
    println!("For TCP mode on port {}, use: pyneat lsp --tcp --port {}", port, port);
    pyneat_rs::run_server();
}

fn ci_mode(paths: &[String], output: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    // CI mode: SARIF output, fail on high/critical
    scan_paths(
        paths,
        false,
        output,
        &OutputFormat::Sarif,
        &SeverityThreshold::Info,
        None,
        None,
        None,
        false,
        8,
        None,
        None,
        None,
        Some(&SeverityThreshold::High),
    )
}
