//! PyNeat Core Binary
//!
//! This binary provides basic CLI access to pyneat-core features.
//! For advanced features, use pyneat-pro-engine separately.

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
mod lsp;

// Pro Engine integration
mod protocol;
mod pro_engine;

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

/// PyNeat Core - Open Source Security Scanner
#[derive(Parser, Debug)]
#[command(name = "pyneat-core")]
#[command(author = "Khanh Nam")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Open source multi-language security scanner (AGPL)")]
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
    },

    /// List all available rules
    ListRules,

    /// Check a code snippet
    Check {
        /// Code to check
        #[arg(required = true)]
        code: String,
    },

    /// Explain a rule
    Explain {
        /// Rule ID to explain
        #[arg(required = true)]
        rule_id: String,
    },

    /// Start as LSP server
    Server {
        /// Port to listen on
        #[arg(long, default_value = "4444")]
        port: u16,
    },

    /// Check Pro Engine availability
    ProStatus,
}

// --------------------------------------------------------------------------
// Main
// --------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pyneat_core=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    match args.command {
        Commands::Scan { paths, fix, output, exclude_paths } => {
            scan_paths(&paths, fix, output.as_deref(), &args.format, &args.severity, exclude_paths.as_deref())?;
        }
        Commands::ListRules => {
            list_rules();
        }
        Commands::Check { code } => {
            check_code(&code)?;
        }
        Commands::Explain { rule_id } => {
            explain_rule(&rule_id);
        }
        Commands::Server { port } => {
            start_lsp_server(port);
        }
        Commands::ProStatus => {
            pro_status();
        }
    }

    Ok(())
}

// --------------------------------------------------------------------------
// Pro Engine Status
// --------------------------------------------------------------------------

fn pro_status() {
    if pro_engine::is_pro_engine_available() {
        match pro_engine::get_pro_engine_version() {
            Ok(version) => {
                println!("Pro Engine: Available (v{})", version);
                println!("Advanced features: Enabled");
                println!("  - Semantic analysis");
                println!("  - Type validation");
                println!("  - AI bug detection");
                println!("  - Dependency scanning");
                println!("  - CVE/GHSA integration");
            }
            Err(_) => {
                println!("Pro Engine: Error checking version");
            }
        }
    } else {
        println!("Pro Engine: Not available");
        println!("Advanced features: Disabled");
        println!("");
        println!("To enable Pro Engine:");
        println!("  1. Obtain pyneat-pro-engine license");
        println!("  2. Install pyneat-pro-engine binary");
        println!("  3. Run: pyneat-core pro-status");
    }
}

// --------------------------------------------------------------------------
// Scan Logic (simplified for core)
// --------------------------------------------------------------------------

fn scan_paths(
    paths: &[String],
    apply_fix: bool,
    output: Option<&str>,
    format: &OutputFormat,
    severity_threshold: &SeverityThreshold,
    exclude_paths: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let rules = all_security_rules();

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
                if entry_path.extension().and_then(|e| e.to_str()) == Some("py") {
                    let code = std::fs::read_to_string(entry_path)?;
                    let file_path = entry_path.to_string_lossy().to_string();
                    if let Ok(results) = scan_python_detailed(&code, &file_path, &rules) {
                        all_results.extend(results);
                    }
                }
            }
        } else if path.is_file() {
            let code = std::fs::read_to_string(path)?;
            let file_path = path.to_string_lossy().to_string();
            if let Ok(results) = scan_python_detailed(&code, &file_path, &rules) {
                all_results.extend(results);
            }
        }
    }

    // Filter by severity
    let threshold_level = severity_threshold.level();
    let filtered: Vec<_> = all_results.iter()
        .filter(|r| severity_level(&r.severity) >= threshold_level)
        .collect();

    // Output
    let output_content = match format {
        OutputFormat::Sarif => {
            serde_json::to_string_pretty(&generate_sarif_output(&filtered)).unwrap_or_default()
        }
        OutputFormat::Json => {
            serde_json::to_string_pretty(&filtered).unwrap_or_default()
        }
        OutputFormat::Text => {
            format_text_output(&filtered)
        }
        _ => {
            serde_json::to_string_pretty(&filtered).unwrap_or_default()
        }
    };

    if let Some(output_file) = output {
        std::fs::write(output_file, &output_content)?;
    } else {
        println!("{}", output_content);
    }

    Ok(())
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
                snippet: finding.snippet.clone(),
                problem: finding.problem.clone(),
            });
        }
    }

    Ok(results)
}

#[derive(Debug, Clone, serde::Serialize)]
struct ScanResult {
    rule_id: String,
    severity: String,
    file: String,
    line: usize,
    column: usize,
    snippet: String,
    problem: String,
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

fn severity_level(severity: &str) -> usize {
    match severity.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

fn generate_sarif_output(results: &[&ScanResult]) -> serde_json::Value {
    let mut builder = SarifBuilder::new(
        "PyNEAT Core",
        env!("CARGO_PKG_VERSION"),
        "https://github.com/pyneat/pyneat",
    );

    for result in results {
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

        builder = builder.add_result(sarif_result);
    }

    builder.build().to_json()
}

fn format_text_output(results: &[&ScanResult]) -> String {
    if results.is_empty() {
        return "No findings.".to_string();
    }

    let mut report = String::new();
    report.push_str("Security Findings Report\n");
    report.push_str(&"=".repeat(60));
    report.push('\n');

    for r in results {
        report.push_str(&format!("\n[{}] {}\n", r.rule_id, r.severity.to_uppercase()));
        report.push_str(&format!("{}:{}\n", r.file, r.line));
        report.push_str(&format!("{}\n", r.problem));
    }

    report.push_str(&format!("\nTotal: {} findings\n", results.len()));
    report
}

fn list_rules() {
    let rules = all_security_rules();
    println!("Available Security Rules (Core - Open Source)");
    println!("========================================\n");

    for rule in &rules {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("{} {} - {}", fix_indicator, rule.id(), rule.name());
    }

    println!("\nTotal: {} core rules", rules.len());
    println!("\nNote: For advanced rules (200+), use pyneat-pro-engine");
}

fn check_code(code: &str) -> Result<(), Box<dyn std::error::Error>> {
    let rules = all_security_rules();
    let tree = parse(code)?;
    let mut findings: Vec<_> = Vec::new();

    for rule in &rules {
        findings.extend(rule.detect(&tree, code));
    }

    findings.sort_by_key(|f| f.start);

    let json_findings: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "rule_id": f.rule_id,
                "severity": f.severity.as_str(),
                "start": f.start,
                "end": f.end,
                "snippet": f.snippet,
                "problem": f.problem,
            })
        })
        .collect();
    println!("{}", serde_json::to_string(&json_findings).unwrap_or_else(|_| "[]".to_string()));

    Ok(())
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

fn start_lsp_server(port: u16) {
    println!("PyNEAT Core LSP server starting on stdio...");
    println!("For TCP mode on port {}, use: pyneat-core lsp --tcp --port {}", port, port);
    pyneat_core::run_server();
}
