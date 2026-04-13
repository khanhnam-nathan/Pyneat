//! Rust-specific rules.
//!
//! Rules for detecting common Rust issues like debug macros,
//! unsafe blocks, unwrap usage, etc.

use std::collections::HashSet;
use regex::Regex;

use super::super::ln_ast::LnAst;
use super::super::base::{LangRule, LangFinding};

/// Helper to get line byte offsets
fn get_line_offsets(code: &str, line: usize) -> (usize, usize) {
    let mut current_line = 1;
    let mut line_start = 0;
    for (i, c) in code.char_indices() {
        if current_line == line {
            line_start = i;
            break;
        }
        if c == '\n' {
            current_line += 1;
        }
    }
    let mut line_end = line_start;
    for (i, c) in code[line_start..].char_indices() {
        if c == '\n' {
            line_end = line_start + i + 1;
            break;
        }
    }
    if line_end == line_start {
        line_end = code.len();
    }
    (line_start, line_end)
}

/// Detect debug macros like println!, eprintln!, dbg!, etc.
pub struct RustDebugMacros;

impl LangRule for RustDebugMacros {
    fn id(&self) -> &str {
        "RUST-001"
    }

    fn name(&self) -> &str {
        "Debug Macro Usage"
    }

    fn severity(&self) -> &'static str {
        "info"
    }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let debug_macros: HashSet<&str> = [
            "println!", "eprintln!", "print!", "dbg!", "format!",
            "panic!", "unimplemented!", "todo!", "todo",
        ].into_iter().collect();

        let mut findings = vec![];

        for call in &tree.calls {
            let callee = call.callee.trim_end_matches('!');
            if debug_macros.contains(callee) || callee == "panic" {
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: call.callee.clone(),
                    problem: format!(
                        "Debug macro '{}' found. Remove or replace with proper error handling.",
                        call.callee
                    ),
                    fix_hint: "Remove this debug output or replace with proper logging.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings
    }
}

/// Detect unwrap() and expect() usage - potential panics.
pub struct RustUnwrapUsage;

impl LangRule for RustUnwrapUsage {
    fn id(&self) -> &str {
        "RUST-002"
    }

    fn name(&self) -> &str {
        "Unwrap/Expect Usage"
    }

    fn severity(&self) -> &'static str {
        "medium"
    }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let re = Regex::new(r"\.(unwrap|expect|unwrap_err|unwrap_or|unwrap_or_else)\s*\(").unwrap();

        for call in &tree.calls {
            let callee_lower = call.callee.to_lowercase();
            if callee_lower.contains("unwrap") || callee_lower.contains("expect") {
                if re.is_match(&call.callee) {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: call.callee.clone(),
                        problem: format!(
                            "Potential panic: '{}' can panic if the value is None or Err.",
                            call.callee
                        ),
                        fix_hint: "Consider using 'if let' or 'match' for proper error handling.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings
    }
}

/// Detect unsafe blocks.
pub struct RustUnsafeBlocks;

impl LangRule for RustUnsafeBlocks {
    fn id(&self) -> &str {
        "RUST-003"
    }

    fn name(&self) -> &str {
        "Unsafe Block Usage"
    }

    fn severity(&self) -> &'static str {
        "high"
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for (i, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("unsafe") {
                if trimmed == "unsafe" || trimmed.starts_with("unsafe ") || trimmed.starts_with("unsafe{") {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.to_string(),
                        problem: "Unsafe block detected. This bypasses Rust's memory safety guarantees.".to_string(),
                        fix_hint: "Ensure all unsafe operations are documented and necessary.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings
    }
}

/// Detect TODO/FIXME comments that should be addressed.
pub struct RustTodoComments;

impl LangRule for RustTodoComments {
    fn id(&self) -> &str {
        "RUST-004"
    }

    fn name(&self) -> &str {
        "TODO/FIXME Comments"
    }

    fn severity(&self) -> &'static str {
        "info"
    }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for todo in &tree.todos {
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: todo.start_line,
                column: 0,
                start_byte: 0,
                end_byte: 0,
                snippet: todo.text.clone(),
                problem: format!(
                    "Unresolved {} marker: {}",
                    todo.marker,
                    todo.description
                ),
                fix_hint: "Address the TODO or provide a timeline for resolution.".to_string(),
                auto_fix_available: false,
            });
        }

        findings
    }
}

/// Detect allow(lint) attributes that suppress warnings.
pub struct RustAllowLints;

impl LangRule for RustAllowLints {
    fn id(&self) -> &str {
        "RUST-005"
    }

    fn name(&self) -> &str {
        "Allow Lint Attributes"
    }

    fn severity(&self) -> &'static str {
        "low"
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let re = Regex::new(r"#\[allow\s*\(([^)]+)\)\]").unwrap();

        for (i, line) in code.lines().enumerate() {
            if let Some(caps) = re.captures(line) {
                let lint_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let (start, end) = get_line_offsets(code, i + 1);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: i + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: caps.get(0).map(|m| m.as_str().to_string()).unwrap_or_default(),
                    problem: format!(
                        "Lint suppression: #[allow({})]. This may hide important warnings.",
                        lint_name
                    ),
                    fix_hint: "Consider fixing the lint instead of suppressing it.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings
    }
}

/// Get all Rust-specific rules.
pub fn rust_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(RustDebugMacros),
        Box::new(RustUnwrapUsage),
        Box::new(RustUnsafeBlocks),
        Box::new(RustTodoComments),
        Box::new(RustAllowLints),
    ]
}
