//! Rust-specific quality rules for pyneat-rs.
//!
//! Implements RUST-QUAL-001 through RUST-QUAL-008 for code quality issues
//! in AI-generated Rust code.

use std::collections::HashSet;

use regex::Regex;

use super::super::ln_ast::LnAst;
use super::super::base::{LangRule, LangFinding, LangFix};

/// Helper: get line byte offsets (0-indexed lines).
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

/// Helper: get full line text from line number (1-indexed)
fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|s| s.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-001: Debug Macro Usage
// Severity: info
// AI commonly leaves debug macros like println!, dbg! in production code
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustDebugMacroUsage;

impl LangRule for RustDebugMacroUsage {
    fn id(&self) -> &str { "RUST-QUAL-001" }
    fn name(&self) -> &str { "Debug Macro Usage" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let debug_macros: HashSet<&str> = [
            "println!", "eprintln!", "print!", "dbg!", "format!",
        ].into_iter().collect();

        let mut findings = vec![];

        for call in &tree.calls {
            let callee = call.callee.trim_end_matches('!');
            if debug_macros.contains(callee) {
                let (start, end) = get_line_offsets(_code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: format!(
                        "Debug macro '{}' found in code. Remove or replace with proper logging.",
                        call.callee
                    ),
                    fix_hint: "Use a proper logging crate (tracing, log, env_logger) or \
                        a structured logging framework. Remove println!/dbg! before production.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> {
        None
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-002: Unwrap/Expect Usage (Potential Panic)
// Severity: medium
// AI generates unwrap/expect without proper error handling
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustUnwrapExpectUsage;

impl LangRule for RustUnwrapExpectUsage {
    fn id(&self) -> &str { "RUST-QUAL-002" }
    fn name(&self) -> &str { "Unwrap/Expect Usage (Potential Panic)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let unwrap_pattern = Regex::new(
            r"\.(unwrap|expect|unwrap_err|unwrap_or_default|unwrap_unchecked)\s*\("
        ).unwrap();

        for call in &tree.calls {
            if unwrap_pattern.is_match(&call.callee) {
                let (start, end) = get_line_offsets(code, call.start_line);
                let line_text = get_line_text(code, call.start_line)
                    .unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!(
                        "Potential panic: '{}' can panic if the value is None or Err. \
                        CWE-755: This can lead to denial of service.",
                        call.callee
                    ),
                    fix_hint: "Use proper error handling with '?'. If you must use unwrap, \
                        document why it's safe. Consider: if let Some(v) = opt { ... } \
                        or match opt { Some(v) => ..., None => ... }.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-003: Dead Code (Unused Functions/Variables)
// Severity: info
// AI often generates unused helper functions
// Auto-fix: comment out unused code
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustDeadCode;

impl LangRule for RustDeadCode {
    fn id(&self) -> &str { "RUST-QUAL-003" }
    fn name(&self) -> &str { "Dead Code / Unused Code" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Collect all function names defined in the file
        let _defined_functions: HashSet<String> = tree.functions.iter()
            .map(|f| f.name.clone())
            .collect();

        // Check if functions are called anywhere in the code
        let called_functions: HashSet<String> = tree.calls.iter()
            .map(|c| c.callee.trim_start_matches("self.").to_string())
            .filter(|name| !name.is_empty() && !name.contains('.'))
            .collect();

        // Find unused functions (not called anywhere)
        for func in &tree.functions {
            if !called_functions.contains(&func.name)
                && !func.name.starts_with("main")
                && !func.name.starts_with('_')
            {
                let (start, end) = get_line_offsets(code, func.start_line);
                let line_text = get_line_text(code, func.start_line)
                    .unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: func.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!(
                        "Function '{}' is defined but never called. This is dead code.",
                        func.name
                    ),
                    fix_hint: "Either use the function, remove it, or prefix with '_' \
                        if it's intentionally public for external use.".to_string(),
                    auto_fix_available: true,
                });
            }
        }

        // Check for unused variables (assigned but never used in calls)
        let assigned_vars: HashSet<String> = tree.assignments.iter()
            .map(|a| a.name.clone())
            .collect();
        let mut used_vars: HashSet<String> = HashSet::new();

        for call in &tree.calls {
            for arg in &call.arguments {
                let words: Vec<&str> = arg.split(|c: char| !c.is_alphanumeric() && c != '_').collect();
                for word in words {
                    if assigned_vars.contains(word) {
                        used_vars.insert(word.to_string());
                    }
                }
            }
        }

        for assignment in &tree.assignments {
            if !used_vars.contains(&assignment.name)
                && !assignment.name.starts_with('_')
                && !assignment.name.to_uppercase().eq(&assignment.name)
            {
                let (start, end) = get_line_offsets(code, assignment.start_line);
                let line_text = get_line_text(code, assignment.start_line)
                    .unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: assignment.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!(
                        "Variable '{}' is assigned but never used.",
                        assignment.name
                    ),
                    fix_hint: "Remove the unused variable assignment or prefix it with '_' \
                        to indicate intentionally unused.".to_string(),
                    auto_fix_available: true,
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = get_line_text(code, finding.line)?;
        let trimmed = line_text.trim();

        // Comment out the line
        if trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ") {
            let indent = &line_text[..line_text.len() - line_text.trim_start().len()];
            let commented = format!("{}// DEAD: {}", indent, trimmed);
            Some(LangFix {
                rule_id: self.id().to_string(),
                original: line_text,
                replacement: commented,
                start_byte: finding.start_byte,
                end_byte: finding.end_byte,
                description: "Comment out unused function".to_string(),
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-004: Clone on Copy Types
// Severity: low
// AI clones types that implement Copy (unnecessary)
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustCloneOnCopyTypes;

impl LangRule for RustCloneOnCopyTypes {
    fn id(&self) -> &str { "RUST-QUAL-004" }
    fn name(&self) -> &str { "Unnecessary Clone on Copy Types" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let clone_pattern = Regex::new(r"\.clone\(\)").unwrap();

        // Known Copy types
        let _copy_types: HashSet<&str> = [
            "i8", "i16", "i32", "i64", "i128", "isize",
            "u8", "u16", "u32", "u64", "u128", "usize",
            "f32", "f64", "bool", "char", "str",
        ].into_iter().collect();

        for call in &tree.calls {
            if clone_pattern.is_match(&call.callee) {
                // Check if it's a clone on a literal or simple copy type
                if call.arguments.is_empty() {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = get_line_text(code, call.start_line)
                        .unwrap_or_default();

                    // Simple heuristic: if the clone is on a simple expression
                    let callee_base = call.callee.replace(".clone()", "");
                    if callee_base.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                        && !callee_base.contains('.')
                    {
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.trim().to_string(),
                            problem: format!(
                                "Unnecessary clone() on likely Copy type: '{}'. \
                                Types like integers, booleans, and chars implement Copy \
                                and don't need cloning.",
                                callee_base
                            ),
                            fix_hint: "Remove .clone() since the type implements Copy. \
                                Cloning Copy types is redundant and wastes memory.".to_string(),
                            auto_fix_available: true,
                        });
                    }
                }
            }
        }

        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = get_line_text(code, finding.line)?;
        let fixed = line_text.replace(".clone()", "");
        Some(LangFix {
            rule_id: self.id().to_string(),
            original: line_text.clone(),
            replacement: fixed,
            start_byte: finding.start_byte,
            end_byte: finding.end_byte,
            description: "Remove unnecessary .clone()".to_string(),
        })
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-005: Redundant/Unused Import
// Severity: info
// AI generates unused 'use' statements
// Auto-fix: remove unused imports
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustRedundantImport;

impl LangRule for RustRedundantImport {
    fn id(&self) -> &str { "RUST-QUAL-005" }
    fn name(&self) -> &str { "Unused Import / Redundant Use Statement" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Collect all imported names
        let imported_names: Vec<(String, usize, usize, String)> = tree.imports.iter()
            .map(|imp| {
                let name = if imp.alias.is_some() {
                    imp.alias.clone().unwrap()
                } else {
                    imp.name.clone()
                };
                let full_path = imp.module.clone();
                (name, imp.start_line, 0, full_path)
            })
            .collect();

        // Collect all used names from calls and assignments
        let mut used_names: HashSet<String> = HashSet::new();

        for call in &tree.calls {
            let callee = call.callee.clone();
            // Extract base name (before first .)
            if let Some(base) = callee.split('.').next() {
                used_names.insert(base.to_string());
            }
            // Add all arguments
            for arg in &call.arguments {
                for word in arg.split(|c: char| !c.is_alphanumeric() && c != '_') {
                    if word.len() > 1 {
                        used_names.insert(word.to_string());
                    }
                }
            }
        }

        for assignment in &tree.assignments {
            used_names.insert(assignment.name.clone());
        }

        for (name, line, _col, full_path) in &imported_names {
            if !used_names.contains(name) && !full_path.contains("self") {
                let (start, end) = get_line_offsets(code, *line);
                let line_text = get_line_text(code, *line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: *line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!(
                        "Import '{}' from '{}' appears to be unused.",
                        name, full_path
                    ),
                    fix_hint: "Remove the unused import statement to clean up the code. \
                        Unused imports increase compilation time slightly.".to_string(),
                    auto_fix_available: true,
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = get_line_text(code, finding.line)?;
        let trimmed = line_text.trim();

        if trimmed.starts_with("use ") {
            let indent = &line_text[..line_text.len() - line_text.trim_start().len()];
            let commented = format!("{}// UNUSED: {}", indent, trimmed);
            Some(LangFix {
                rule_id: self.id().to_string(),
                original: line_text,
                replacement: commented,
                start_byte: finding.start_byte,
                end_byte: finding.end_byte,
                description: "Comment out unused import".to_string(),
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-006: Unsafe Block Audit Required
// Severity: high
// AI generates unsafe blocks without proper documentation
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustUnsafeBlockAudit;

impl LangRule for RustUnsafeBlockAudit {
    fn id(&self) -> &str { "RUST-QUAL-006" }
    fn name(&self) -> &str { "Unsafe Block Without Documentation" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Parse code line by line to find unsafe blocks
        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            let line_num = line_idx + 1;

            if trimmed.starts_with("unsafe")
                && (trimmed == "unsafe"
                    || trimmed.starts_with("unsafe ")
                    || trimmed.starts_with("unsafe{")
                    || trimmed.starts_with("unsafe {"))
            {
                // Check if the next few lines have documentation
                let lines_after: Vec<&str> = code.lines()
                    .skip(line_idx)
                    .take(5)
                    .collect();

                let has_comment = lines_after.iter()
                    .skip(1)
                    .take(3)
                    .any(|l| l.trim().starts_with("//") || l.trim().starts_with("/*"));

                if !has_comment {
                    let (start, end) = get_line_offsets(code, line_num);

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: line_num,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.to_string(),
                        problem: "Unsafe block detected without documented safety justification. \
                            Unsafe code bypasses Rust's memory safety guarantees.".to_string(),
                        fix_hint: "Add a safety comment explaining WHY the unsafe block is safe. \
                            Document invariants that must be maintained. Example: \
                            // SAFETY: pointer is valid and aligned for 'T'. \
                            unsafe { ... }".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-007: Panic in Production Code
// Severity: high
// AI uses panic!, unimplemented!, todo! in non-test code
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustPanicInProduction;

impl LangRule for RustPanicInProduction {
    fn id(&self) -> &str { "RUST-QUAL-007" }
    fn name(&self) -> &str { "Panic/Unimplemented/Todo in Production Code" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let panic_macros: HashSet<&str> = [
            "panic!", "unimplemented!", "todo!", "unreachable!",
        ].into_iter().collect();

        let abort_pattern = Regex::new(r"\bfail!\b|\babort!\b").unwrap();

        for call in &tree.calls {
            let callee = call.callee.trim_end_matches('!');
            if panic_macros.contains(callee) {
                let (start, end) = get_line_offsets(code, call.start_line);
                let line_text = get_line_text(code, call.start_line)
                    .unwrap_or_default();

                let problem_type = match callee {
                    "panic!" => "panic! causes thread abort",
                    "unimplemented!" => "unimplemented! indicates incomplete code",
                    "todo!" => "todo! indicates unfinished implementation",
                    "unreachable!" => "unreachable! indicates flawed logic",
                    _ => "this macro causes runtime failure",
                };

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!(
                        "{} in production code: '{}'. \
                        CWE-755: This can lead to denial of service.",
                        problem_type, call.callee
                    ),
                    fix_hint: "Replace panic/unimplemented with proper error handling. \
                        Return Result<T, E> or Option<T> and handle the error case. \
                        Only use panic! in truly unrecoverable situations.".to_string(),
                    auto_fix_available: false,
                });
            }

            if abort_pattern.is_match(&call.callee) {
                let (start, end) = get_line_offsets(code, call.start_line);
                let line_text = get_line_text(code, call.start_line)
                    .unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: "critical".to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: "abort! macro causes immediate process termination. \
                        This is extremely dangerous in production.".to_string(),
                    fix_hint: "Replace abort! with proper error handling. \
                        Return an error to the caller instead of killing the process.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-008: Mutable Reference Sharing Violation
// Severity: medium
// AI may create multiple mutable references to the same data
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustMutableRefSharing;

impl LangRule for RustMutableRefSharing {
    fn id(&self) -> &str { "RUST-QUAL-008" }
    fn name(&self) -> &str { "Mutable Reference Sharing Violation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Look for patterns like &mut var &mut var (simultaneous borrows)
        let mut_ref_pattern = Regex::new(r"&mut\s+\w+.*&mut\s+\w+").unwrap();
        let chained_mut_pattern = Regex::new(r"&\s*\([^)]*&mut\s+\w+[^)]*\)").unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            let line_num = line_idx + 1;

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            // Check for multiple mutable references
            if mut_ref_pattern.is_match(trimmed) || chained_mut_pattern.is_match(trimmed) {
                // Heuristic: if it looks like a function call with multiple &mut
                if trimmed.contains('(') && trimmed.contains('&') {
                    let (start, end) = get_line_offsets(code, line_num);

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: line_num,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: trimmed.to_string(),
                        problem: "Multiple mutable references passed simultaneously. \
                            This pattern may violate Rust's borrowing rules.".to_string(),
                        fix_hint: "Review this code for borrow checker violations. \
                            Ensure each mutable reference has exclusive access. \
                            Consider restructuring or using interior mutability (Cell, RefCell) \
                            if you need shared mutation.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry function
// ─────────────────────────────────────────────────────────────────────────────

/// All Rust quality rules.
pub fn rust_quality_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(RustDebugMacroUsage),
        Box::new(RustUnwrapExpectUsage),
        Box::new(RustDeadCode),
        Box::new(RustCloneOnCopyTypes),
        Box::new(RustRedundantImport),
        Box::new(RustUnsafeBlockAudit),
        Box::new(RustPanicInProduction),
        Box::new(RustMutableRefSharing),
    ]
}
