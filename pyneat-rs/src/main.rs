//! PyNeat Rust CLI
//!
//! Command-line interface for the PyNeat security scanner.

use clap::{Parser, Subcommand};
use std::path::Path;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::fixer::diff::{format_findings_report, generate_diff};
use crate::rules::security::all_security_rules;
use crate::scanner::tree_sitter::parse;
use crate::rules::Rule;

mod fixer;
mod rules;
mod scanner;

/// PyNeat Rust Security Scanner
#[derive(Parser, Debug)]
#[command(name = "pyneat-rs")]
#[command(author = "Khanh Nam")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "High-performance security scanner for Python code")]
struct Args {
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: String,

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
    },

    /// List all available rules
    ListRules,

    /// Check a code snippet from stdin
    Check {
        /// Code to check
        #[arg(required = true)]
        code: String,

        /// Output format (overrides global --format)
        #[arg(short, long)]
        format: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pyneat_rs=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    match args.command {
        Commands::Scan { paths, fix: _, output } => {
            scan_paths(&paths, output.as_deref())?;
        }
        Commands::ListRules => {
            list_rules();
        }
        Commands::Check { code, format } => {
            // Prefer local --format if provided, otherwise use global --format
            let fmt = format.as_deref().or(
                if args.format != "text" { Some(args.format.as_str()) } else { None }
            );
            check_code(&code, fmt)?;
        }
    }

    Ok(())
}

fn scan_paths(paths: &[String], output: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let rules = all_security_rules();

    for path_str in paths {
        let path = Path::new(path_str);

        if path.is_dir() {
            // Scan all .py files in the directory
            for entry in walkdir::WalkDir::new(path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "py"))
            {
                let code = std::fs::read_to_string(entry.path())?;
                let file_path = entry.path();

                if let Ok(report) = scan_code(&code, file_path.to_string_lossy().as_ref(), &rules) {
                    if !report.is_empty() {
                        println!("{}", report);
                    }
                }
            }
        } else if path.is_file() && path.extension().map_or(false, |ext| ext == "py") {
            let code = std::fs::read_to_string(path)?;
            let file_path = path.to_string_lossy();

            if let Ok(report) = scan_code(&code, file_path.as_ref(), &rules) {
                if !report.is_empty() {
                    println!("{}", report);
                }
            }
        }
    }

    let _ = output; // Suppress unused warning

    Ok(())
}

fn scan_code(code: &str, filename: &str, rules: &[Box<dyn Rule>]) -> Result<String, Box<dyn std::error::Error>> {
    // Parse the code
    let tree = match parse(code) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to parse {}: {}", filename, e);
            return Ok(String::new());
        }
    };

    // Detect findings
    let mut all_findings: Vec<_> = Vec::new();

    for rule in rules {
        let findings = rule.detect(&tree, code);
        all_findings.extend(findings);
    }

    // Sort by position
    all_findings.sort_by_key(|f| f.start);

    // Generate report
    let report = format_findings_report(&all_findings);

    Ok(report)
}

fn list_rules() {
    let rules = all_security_rules();

    println!("Available Security Rules");
    println!("========================\n");

    for rule in &rules {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("{} {} - {}", fix_indicator, rule.id(), rule.name());
    }

    println!("\nTotal: {} rules", rules.len());
}

fn check_code(code: &str, override_format: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let rules = all_security_rules();
    let tree = parse(code)?;
    let mut findings: Vec<_> = Vec::new();

    for rule in &rules {
        findings.extend(rule.detect(&tree, code));
    }

    findings.sort_by_key(|f| f.start);

    // Use override format if provided, otherwise default to text
    let fmt = override_format.unwrap_or("text");

    if fmt == "json" {
        // Output as JSON for Python integration
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
