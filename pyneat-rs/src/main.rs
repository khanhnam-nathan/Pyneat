//! PyNeat Rust CLI
//!
//! Command-line interface for the PyNeat security scanner.

#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_assignments)]

use clap::{Parser, Subcommand};
use std::path::Path;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::fixer::diff::format_findings_report;
use crate::fixer::apply_fix::FixRange;
use crate::rules::security::all_security_rules;
use crate::scanner::tree_sitter::parse;
use crate::scanner::base::{LanguageScanner, LangRule, LangFinding};
use crate::scanner::{JavaScriptScanner, TypeScriptScanner, GoScanner, JavaScanner, CSharpScanner, PhpScanner, RubyScanner, RustScanner};
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
        Commands::Scan { paths, fix, output } => {
            scan_paths(&paths, fix, output.as_deref())?;
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

fn scan_paths(paths: &[String], apply_fix: bool, output: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let rules = all_security_rules();

    // Initialize language scanners
    let js_scanner = JavaScriptScanner::new();
    let ts_scanner = TypeScriptScanner::new();
    let go_scanner = GoScanner::new();
    let java_scanner = JavaScanner::new();
    let csharp_scanner = CSharpScanner::new();
    let php_scanner = PhpScanner::new();
    let ruby_scanner = RubyScanner::new();
    let rust_scanner = RustScanner::new();

    for path_str in paths {
        let path = Path::new(path_str);

        if path.is_dir() {
            // Scan all files in the directory
            for entry in walkdir::WalkDir::new(path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
            {
                let ext = entry.path().extension().and_then(|e| e.to_str()).unwrap_or("");
                let code = std::fs::read_to_string(entry.path())?;
                let file_path = entry.path();

                if ext == "py" {
                    // Python scanning
                    if let Ok(report) = scan_python(&code, file_path.to_string_lossy().as_ref(), &rules) {
                        if !report.is_empty() {
                            println!("{}", report);
                        }
                    }
                } else if let Some(scanner) = get_lang_scanner(ext, &js_scanner, &ts_scanner, &go_scanner, &java_scanner, &csharp_scanner, &php_scanner, &ruby_scanner, &rust_scanner) {
                    // Multi-language scanning
                    if let Ok(report) = scan_language(&code, scanner, file_path.to_string_lossy().as_ref()) {
                        if !report.is_empty() {
                            println!("{}", report);
                        }
                        // Apply fixes if requested
                        if apply_fix {
                            apply_language_fixes(entry.path(), &code, scanner);
                        }
                    }
                }
            }
        } else if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let code = std::fs::read_to_string(path)?;
            let file_path = path.to_string_lossy();

            if ext == "py" {
                if let Ok(report) = scan_python(&code, file_path.as_ref(), &rules) {
                    if !report.is_empty() {
                        println!("{}", report);
                    }
                }
            } else if let Some(scanner) = get_lang_scanner(ext, &js_scanner, &ts_scanner, &go_scanner, &java_scanner, &csharp_scanner, &php_scanner, &ruby_scanner, &rust_scanner) {
                if let Ok(report) = scan_language(&code, scanner, file_path.as_ref()) {
                    if !report.is_empty() {
                        println!("{}", report);
                    }
                    if apply_fix {
                        apply_language_fixes(path, &code, scanner);
                    }
                }
            }
        }
    }

    let _ = output; // Suppress unused warning

    Ok(())
}

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

fn scan_python(code: &str, filename: &str, rules: &[Box<dyn Rule>]) -> Result<String, Box<dyn std::error::Error>> {
    let tree = match parse(code) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to parse {}: {}", filename, e);
            return Ok(String::new());
        }
    };

    let mut all_findings: Vec<_> = Vec::new();
    for rule in rules {
        let findings = rule.detect(&tree, code);
        all_findings.extend(findings);
    }

    all_findings.sort_by_key(|f| f.start);
    let report = format_findings_report(&all_findings);
    Ok(report)
}

fn scan_language(code: &str, scanner: &dyn LanguageScanner, filename: &str) -> Result<String, Box<dyn std::error::Error>> {
    let tree = match scanner.parse(code) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to parse {}: {}", filename, e);
            return Ok(String::new());
        }
    };

    let findings = scanner.detect(&tree, code);

    if findings.is_empty() {
        return Ok(String::new());
    }

    // Generate report
    let lang = scanner.language();
    let mut report = format!("\n[{}] {}\n", lang, filename);
    report.push_str(&"=".repeat(60));
    report.push('\n');

    let mut by_severity: std::collections::HashMap<&str, Vec<&LangFinding>> = std::collections::HashMap::new();
    for f in &findings {
        by_severity.entry(f.severity.as_str()).or_default().push(f);
    }

    for sev in ["critical", "high", "medium", "low", "info"] {
        if let Some(items) = by_severity.get(sev) {
            let sev_upper = sev.to_uppercase();
            report.push_str(&format!("\n{} ({}):\n", sev_upper, items.len()));
            for f in items {
                let fix_marker = if f.auto_fix_available { "[FIX]" } else { "    " };
                report.push_str(&format!("  {} {} - {}\n", fix_marker, f.rule_id, f.problem));
                report.push_str(&format!("    at {}:{}\n", filename, f.line));
                report.push_str(&format!("    Fix: {}\n", f.fix_hint));
            }
        }
    }

    report.push_str(&format!("\nTotal: {} findings ({} with auto-fix)\n",
        findings.len(),
        findings.iter().filter(|f| f.auto_fix_available).count()
    ));

    Ok(report)
}

fn apply_language_fixes(path: &Path, original_code: &str, scanner: &dyn LanguageScanner) {
    let tree = match scanner.parse(original_code) {
        Ok(t) => t,
        Err(_) => return,
    };

    let findings = scanner.detect(&tree, original_code);
    let mut fixes: Vec<FixRange> = Vec::new();

    for rule in scanner.rules() {
        let rule_id = rule.id();
        for finding in &findings {
            if rule_id == finding.rule_id && finding.auto_fix_available {
                if let Some(fix) = rule.fix(finding, original_code) {
                    fixes.push(FixRange::new(
                        fix.start_byte,
                        fix.end_byte,
                        fix.replacement,
                        fix.rule_id,
                    ));
                }
            }
        }
    }

    if fixes.is_empty() {
        return;
    }

    // Apply fixes
    let mut code = original_code.to_string();
    // Sort by start position descending to apply from end to start
    fixes.sort_by(|a, b| b.start.cmp(&a.start));

    // Deduplicate: keep only the first (last-applied) fix for each unique range
    let mut seen_ranges: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    let mut applied_count = 0;

    for fix in &fixes {
        let range = (fix.start, fix.end);
        if seen_ranges.contains(&range) {
            continue;
        }
        seen_ranges.insert(range);

        if fix.start <= fix.end && fix.end <= code.len() {
            code.replace_range(fix.start..fix.end, &fix.replacement);
            println!("Applied fix: {} at line {}", fix.rule_id, line_from_byte(original_code, fix.start));
            applied_count += 1;
        }
    }

    // Write fixed code back
    if let Err(e) = std::fs::write(path, &code) {
        eprintln!("Failed to write fixed file {}: {}", path.display(), e);
    } else {
        println!("Fixed: {} ({} fixes applied)", path.display(), applied_count);
    }
}

fn line_from_byte(code: &str, byte: usize) -> usize {
    let mut line = 1;
    for (i, c) in code.char_indices() {
        if i >= byte {
            break;
        }
        if c == '\n' {
            line += 1;
        }
    }
    line
}

fn list_rules() {
    let rules = all_security_rules();

    println!("Available Security Rules (Python)");
    println!("================================\n");

    for rule in &rules {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("{} {} - {}", fix_indicator, rule.id(), rule.name());
    }

    println!("\nTotal: {} Python rules", rules.len());

    // List language-specific rules
    println!("\n\nLanguage-Specific Rules");
    println!("=======================\n");

    // JavaScript/TypeScript
    let js_scanner = JavaScriptScanner::new();
    let js_rules = js_scanner.rules();
    let js_security: Vec<_> = js_rules.iter().filter(|r| r.id().contains("SEC")).collect();
    let js_quality: Vec<_> = js_rules.iter().filter(|r| r.id().contains("QUAL")).collect();
    println!("JavaScript/TypeScript ({} total: {} security, {} quality):",
        js_rules.len(), js_security.len(), js_quality.len());
    println!("  Security rules:");
    for rule in &js_security {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("    {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }
    println!("  Quality rules:");
    for rule in &js_quality {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("    {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    // Rust
    let rust_scanner = RustScanner::new();
    let rust_rules = rust_scanner.rules();
    let rust_security: Vec<_> = rust_rules.iter().filter(|r| r.id().contains("SEC")).collect();
    let rust_quality: Vec<_> = rust_rules.iter().filter(|r| r.id().contains("QUAL")).collect();
    println!("\nRust ({} total: {} security, {} quality):",
        rust_rules.len(), rust_security.len(), rust_quality.len());
    println!("  Security rules:");
    for rule in &rust_security {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("    {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }
    println!("  Quality rules:");
    for rule in &rust_quality {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("    {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    // Go
    let go_scanner = GoScanner::new();
    println!("\nGo:");
    for rule in go_scanner.rules() {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("  {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    // Java
    let java_scanner = JavaScanner::new();
    let java_rules = java_scanner.rules();
    let java_security: Vec<_> = java_rules.iter().filter(|r| r.id().contains("SEC") || r.id().contains("AI-")).collect();
    let java_quality: Vec<_> = java_rules.iter().filter(|r| r.id().contains("QUAL")).collect();
    println!("\nJava ({} total: {} security, {} quality):",
        java_rules.len(), java_security.len(), java_quality.len());
    println!("  Security rules:");
    for rule in &java_security {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("    {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }
    println!("  Quality rules:");
    for rule in &java_quality {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("    {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    // C#
    let csharp_scanner = CSharpScanner::new();
    println!("\nC#:");
    for rule in csharp_scanner.rules() {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("  {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    // PHP
    let php_scanner = PhpScanner::new();
    println!("\nPHP:");
    for rule in php_scanner.rules() {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("  {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    // Ruby
    let ruby_scanner = RubyScanner::new();
    println!("\nRuby:");
    for rule in ruby_scanner.rules() {
        let fix_indicator = if rule.supports_auto_fix() { "[FIX]" } else { "    " };
        println!("  {} {} - {} ({})", fix_indicator, rule.id(), rule.name(), rule.severity());
    }

    // Summary
    let total_lang_rules: usize = js_rules.len() + rust_rules.len() + java_rules.len()
        + go_scanner.rules().len() + csharp_scanner.rules().len()
        + php_scanner.rules().len() + ruby_scanner.rules().len();
    println!("\n\nTotal: {} Python rules, {} multi-language rules", rules.len(), total_lang_rules);
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
