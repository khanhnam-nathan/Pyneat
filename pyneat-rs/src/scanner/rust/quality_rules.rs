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
                        replacement: String::new(),
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
                        replacement: String::new(),
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
                        replacement: String::new(),
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
                        replacement: String::new(),
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
                        replacement: String::new(),
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
                        replacement: String::new(),
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
                        replacement: String::new(),
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
                        replacement: String::new(),
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
                        replacement: String::new(),
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
                        replacement: String::new(),
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
// RUST-AI-001: AI generates unwrap() panic in production code
// Severity: medium | AI Bug Pattern
// unwrap() and expect() in non-test code without proper error handling
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustAiUnwrapPanic;

impl LangRule for RustAiUnwrapPanic {
    fn id(&self) -> &str { "RUST-AI-001" }
    fn name(&self) -> &str { "AI: unwrap() / expect() Causing Panic in Production" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let panic_methods = ["unwrap", "expect", "unwrap_err", "expect_err", "unwrap_unchecked"];

        // Skip test files
        if code.contains("#[test]") || code.contains("#[cfg(test)]") {
            return findings;
        }

        for (i, line) in code.lines().enumerate() {
            if line.trim().starts_with("//") || line.trim().starts_with("/*") {
                continue;
            }
            for method in &panic_methods {
                let re = Regex::new(&format!(r"\b{}\s*\(", method)).unwrap();
                if re.is_match(line) {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: "RUST-AI-001".to_string(),
                        severity: "medium".to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.to_string(),
                        problem: format!("AI pattern detected: {}(), which panics on None/Err. AI often generates unwrap() in production code, causing unexpected crashes.", method),
                        fix_hint: "Replace with proper error handling: unwrap_or(), unwrap_or_else(), or ? operator. Return Result/Option and let the caller handle errors. For truly impossible cases, use unreachable!() or debug_assert!().".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                    break;
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-AI-002: AI generates unsafe blocks without safety docs
// Severity: high | AI Bug Pattern
// unsafe without # Safety: comment (Rust's own convention)
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustAiUnsafeNoDocs;

impl LangRule for RustAiUnsafeNoDocs {
    fn id(&self) -> &str { "RUST-AI-002" }
    fn name(&self) -> &str { "AI: unsafe Block Without Safety Documentation" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let unsafe_re = Regex::new(r"\bunsafe\s*\{").unwrap();
        let safety_re = Regex::new(r"(?i)#\s*Safety\s*:").unwrap();

        for (i, line) in code.lines().enumerate() {
            if unsafe_re.is_match(line) {
                // Check next 5 lines for safety documentation
                let next_lines: String = code.lines().skip(i + 1).take(5).collect::<Vec<_>>().join("\n");
                if !safety_re.is_match(&next_lines) {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: "RUST-AI-002".to_string(),
                        severity: "high".to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.to_string(),
                        problem: "AI-generated unsafe block without safety documentation. AI often skips the # Safety: comment that Rust conventions require.".to_string(),
                        fix_hint: "Add a # Safety: comment before or inside the unsafe block explaining: 1) Invariants the caller must uphold, 2) Why this unsafe block is necessary, 3) What undefined behavior could occur if violated.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-AI-003: AI generates Rc<RefCell<T>> instead of Arc<Mutex<T>>
// Severity: high | AI Bug Pattern
// Thread-unsafe interior mutability in async/multi-threaded code
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustAiWrongSyncPrimitive;

impl LangRule for RustAiWrongSyncPrimitive {
    fn id(&self) -> &str { "RUST-AI-003" }
    fn name(&self) -> &str { "AI: Incorrect Sync Primitive (Rc<RefCell> in Threaded Context)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Rc<RefCell<T>> is NOT thread-safe
        let rc_refcell_re = Regex::new(r"Rc\s*<\s*RefCell\s*<").unwrap();
        // Cell<T> is also not thread-safe
        let cell_re = Regex::new(r"\bCell\s*<").unwrap();
        // UnsafeCell is inherently unsafe
        let unsafe_cell_re = Regex::new(r"\bUnsafeCell\s*<").unwrap();

        // Check if code is async (more likely to be used in threaded context)
        let is_async = code.contains("async fn") || code.contains(".await")
            || code.contains("tokio::spawn") || code.contains("std::thread");

        for (i, line) in code.lines().enumerate() {
            if line.trim().starts_with("//") || line.trim().starts_with("/*") {
                continue;
            }

            if rc_refcell_re.is_match(line) {
                let (start, end) = get_line_offsets(code, i + 1);
                let (arc_line, arc_hint) = if is_async {
                    ("async/multi-threaded".to_string(),
                     "Use Arc<Mutex<T>> or Arc<RwLock<T>> for thread-safe shared state in async code.".to_string())
                } else {
                    ("potentially multi-threaded".to_string(),
                     "Consider Arc<Mutex<T>> or Arc<RwLock<T>> if this code will be shared across threads.".to_string())
                };

                findings.push(LangFinding {
                    rule_id: "RUST-AI-003".to_string(),
                    severity: "high".to_string(),
                    line: i + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.to_string(),
                    problem: format!("AI pattern: Rc<RefCell<T>> in {} code. Rc is not Send/Sync, so it can't be shared across threads. RefCell provides runtime borrow checking which is not thread-safe.", arc_line),
                    fix_hint: arc_hint,
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }

            if cell_re.is_match(line) && is_async {
                let (start, end) = get_line_offsets(code, i + 1);
                findings.push(LangFinding {
                    rule_id: "RUST-AI-003".to_string(),
                    severity: "high".to_string(),
                    line: i + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.to_string(),
                    problem: "Cell<T> used in async/threaded context. Cell is not thread-safe. Use AtomicPtr, Mutex, or RwLock instead.".to_string(),
                    fix_hint: "Use std::sync::Mutex<T> or std::sync::RwLock<T> for shared state across threads.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }

            if unsafe_cell_re.is_match(line) {
                let (start, end) = get_line_offsets(code, i + 1);
                findings.push(LangFinding {
                    rule_id: "RUST-AI-003".to_string(),
                    severity: "high".to_string(),
                    line: i + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.to_string(),
                    problem: "UnsafeCell<T> used directly. UnsafeCell is the building block for interior mutability but requires careful unsafe handling.".to_string(),
                    fix_hint: "Prefer safe wrappers like Mutex, RwLock, or OnceCell. Only use UnsafeCell when absolutely necessary and always document safety invariants.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-009: Unused mut Keyword
// Severity: info
// Detects: let mut x = value where x is never reassigned
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustUnusedMut;

impl LangRule for RustUnusedMut {
    fn id(&self) -> &str { "RUST-QUAL-009" }
    fn name(&self) -> &str { "Unused mut Keyword" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let mut_re = Regex::new(r"\blet\s+mut\s+(\w+)\s*=").unwrap();
        let mut mut_vars: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for caps in mut_re.captures_iter(code) {
            if let Some(var) = caps.get(1) {
                let var_str = var.as_str().to_string();
                let line = code[..caps.get(0).unwrap().start()].matches('\n').count() + 1;
                mut_vars.insert(var_str, line);
            }
        }

        if mut_vars.is_empty() {
            return findings;
        }

        let assignment_re = Regex::new(r"(?m)^\s*(\w+)\s*=").unwrap();
        let assigned: std::collections::HashSet<String> = assignment_re
            .captures_iter(code)
            .filter_map(|c| c.get(1).map(|x| x.as_str().to_string()))
            .collect();

        for (var, line) in &mut_vars {
            if !assigned.contains(var) {
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
                    problem: format!("Variable '{}' is declared with 'mut' but never reassigned. The 'mut' keyword is unnecessary.", var),
                    fix_hint: "Remove 'mut' if the variable is not reassigned: change 'let mut x' to 'let x'.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-010: Cloning in Tight Loop
// Severity: medium
// Detects: .clone() calls inside for/while loops
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustCloneInLoop;

impl LangRule for RustCloneInLoop {
    fn id(&self) -> &str { "RUST-QUAL-010" }
    fn name(&self) -> &str { "Clone in Tight Loop" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let clone_re = Regex::new(r"\.clone\(\)").unwrap();
        let loop_re = Regex::new(r"(?m)^\s*(for|while)\s*\(").unwrap();

        let loop_lines: std::collections::HashSet<usize> = loop_re
            .find_iter(code)
            .map(|m| code[..m.start()].matches('\n').count() + 1)
            .collect();

        for m in clone_re.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            if loop_lines.contains(&line) {
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: ".clone() called inside a loop. This creates a new allocation on every iteration which is expensive.".to_string(),
                    fix_hint: "Consider using a reference ('&') or borrowing instead of cloning. If cloning is necessary, move the object outside the loop.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-011: Unnecessary Box<T> Allocation
// Severity: low
// Detects: Box::new() for types that don't need heap allocation
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustUnnecessaryBox;

impl LangRule for RustUnnecessaryBox {
    fn id(&self) -> &str { "RUST-QUAL-011" }
    fn name(&self) -> &str { "Unnecessary Box<T> Allocation" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let box_patterns = [
            (r"Box::new\s*\(\s*(?:true|false|0|[1-9]\d*)\s*\)", "Box around primitive literal"),
            (r##"Box::new\s*\(\s*"[^"]*"\s*\)"##, "Box around string literal"),
            (r"Box::new\s*\(\s*'[^']*'\s*\)", "Box around char literal"),
        ];

        for (pat, desc) in &box_patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("Unnecessary Box<T> allocation: {}. Box is for heap allocation of large data or trait objects.", desc),
                        fix_hint: "Use the value directly without Box::new(). Only use Box<T> for: large structs on the stack, trait objects (dyn Trait), recursive types, or when ownership transfer is needed.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-012: TODO/FIXME Comments
// Severity: info | CWE-546
// Detects: TODO, FIXME, HACK, XXX markers in comments
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustTodoComments;

impl LangRule for RustTodoComments {
    fn id(&self) -> &str { "RUST-QUAL-012" }
    fn name(&self) -> &str { "TODO / FIXME Comments" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r"(?i)TODO", "TODO marker"),
            (r"(?i)FIXME", "FIXME marker"),
            (r"(?i)HACK", "HACK marker"),
            (r"(?i)XXX", "XXX marker"),
        ];

        for (pat, label) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("{}: Unresolved marker found in code.", label),
                        fix_hint: "Resolve the TODO/FIXME or add a tracking issue.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-013: Dead Code - Unreachable Statements
// Severity: info | CWE-561
// Detects: return statements followed by more code
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustDeadCodeAfterReturn;

impl LangRule for RustDeadCodeAfterReturn {
    fn id(&self) -> &str { "RUST-QUAL-013" }
    fn name(&self) -> &str { "Dead Code (Unreachable Statements)" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let return_re = Regex::new(r"(?m)^\s*return\s*;").unwrap();
        let unreachable_re = Regex::new(r"(?m)^\s*(let|if|for|while|loop|match|break|continue)\b").unwrap();

        let mut prev_returned = false;
        for (i, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }
            if return_re.is_match(line) {
                prev_returned = true;
                continue;
            }
            if prev_returned && unreachable_re.is_match(line) {
                let (start, end) = get_line_offsets(code, i + 1);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: i + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: trimmed.to_string(),
                    problem: "Code after return statement is unreachable (dead code).".to_string(),
                    fix_hint: "Remove unreachable code or restructure the control flow.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
            if !trimmed.is_empty() && !trimmed.starts_with('}') {
                prev_returned = false;
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-014: Missing derive(Debug) on Error Types
// Severity: low
// Detects: struct/enum implementing std::error::Error without derive(Debug)
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustMissingDebugDerive;

impl LangRule for RustMissingDebugDerive {
    fn id(&self) -> &str { "RUST-QUAL-014" }
    fn name(&self) -> &str { "Missing Debug Derive on Error Types" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let impl_error_re = Regex::new(r"impl\s+(?:\w+\s+)?(?:\w+\s+)?std::error::Error\s+for\s+(\w+)").unwrap();
        let struct_re = Regex::new(r"(?m)^#\[derive\([^\]]*\)\]\s*\n\s*(?:pub\s+)?(?:enum|struct)\s+(\w+)").unwrap();

        let error_types: std::collections::HashSet<&str> = impl_error_re
            .captures_iter(code)
            .filter_map(|c| c.get(1).map(|x| x.as_str()))
            .collect();

        if error_types.is_empty() {
            return findings;
        }

        for m in struct_re.captures_iter(code) {
            let type_name = m.get(1).map(|x| x.as_str()).unwrap_or("");
            if error_types.contains(type_name) {
                let derive_match = m.get(0).unwrap();
                let derive_start = derive_match.start();
                let derive_line = code[..derive_start].matches('\n').count() + 1;
                let derive_text = &code[derive_start..derive_match.end()];

                if !derive_text.contains("Debug") {
                    let (start, end) = get_line_offsets(code, derive_line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: derive_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: derive_text.trim().to_string(),
                        problem: format!("Error type '{}' implements std::error::Error but is missing derive(Debug). This prevents proper error formatting.", type_name),
                        fix_hint: "Add Debug to derive: #[derive(Debug)] or #[derive(Debug, Display)].".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-QUAL-015: Empty Match Arm
// Severity: info | CWE-835
// Detects: match arms that do nothing (empty block or just semicolon)
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustEmptyMatchArm;

impl LangRule for RustEmptyMatchArm {
    fn id(&self) -> &str { "RUST-QUAL-015" }
    fn name(&self) -> &str { "Empty Match Arm" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let empty_arm_re = Regex::new(r"(?m)^\s*_\s*=>\s*\{\s*\},\s*$").unwrap();
        let empty_arm_short_re = Regex::new(r"(?m)^\s*_\s*=>\s*,\s*$").unwrap();

        for m in empty_arm_re.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let (start, end) = get_line_offsets(code, line);
            let line_text = get_line_text(code, line).unwrap_or_default();
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: line_text.trim().to_string(),
                problem: "Empty match arm '_ => {}' found. The wildcard arm does nothing.".to_string(),
                fix_hint: "Handle the case explicitly or use debug_assert! to catch unexpected values. Consider logging or returning a Result.".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        for m in empty_arm_short_re.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            if !findings.iter().any(|f: &LangFinding| f.line == line) {
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: "Empty match arm '_ => ,' found. The wildcard arm silently ignores the value.".to_string(),
                    fix_hint: "Handle the case explicitly or add debug_assert! to catch unexpected values.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-AI-004: AI Hardcoded Secrets
// Severity: high | CWE-798
// AI generates code with hardcoded API keys, passwords, tokens
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustAiHardcodedSecrets;

impl LangRule for RustAiHardcodedSecrets {
    fn id(&self) -> &str { "RUST-AI-004" }
    fn name(&self) -> &str { "AI: Hardcoded Secrets in Code" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:api[_-]?key|secret|password|passwd|token|auth|credential)\s*[=:]\s*["'][^'"]{4,}["']"##, "Hardcoded secret"),
            (r##"(?i)password\s*=\s*["'][^'"]{4,}["']"##, "Hardcoded password"),
            (r##"(?i)api[_-]?key\s*[=:]\s*["'][A-Za-z0-9_\-]{10,}["']"##, "Hardcoded API key"),
            (r##"AKIA[0-9A-Z]{16}"##, "AWS Access Key ID"),
            (r##"(?i)bearer\s+[A-Za-z0-9_\-\.]+"##, "Hardcoded Bearer token"),
        ];

        for (pat, desc) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("AI-generated code contains hardcoded {}: may expose credentials in source code.", desc),
                        fix_hint: "Move secrets to environment variables: let key = env::var(\"API_KEY\").expect(\"API_KEY must be set\"); or use a secrets manager.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-AI-005: AI Integer Overflow in Production
// Severity: high | CWE-190
// AI generates arithmetic without checked operations
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustAiIntegerOverflow;

impl LangRule for RustAiIntegerOverflow {
    fn id(&self) -> &str { "RUST-AI-005" }
    fn name(&self) -> &str { "AI: Integer Overflow Risk in Production" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let overflow_risks = [
            (r"\b\d+\s*[\+\-\*\/]\s*\d+", "Arithmetic operation without bounds check"),
            (r"\b(?:usize|u8|u16|u32|u64|i8|i16|i32|i64)\s*::\s*MAX\b", "Using MAX constant without overflow check"),
        ];

        for (pat, desc) in &overflow_risks {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();

                    if line_text.trim().starts_with("//") || line_text.trim().starts_with("/*") {
                        continue;
                    }

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("AI-generated arithmetic '{}' may overflow in production. Default Rust integer arithmetic panics on overflow in debug mode.", m.as_str()),
                        fix_hint: "Use checked arithmetic (checked_add, checked_sub, checked_mul) or wrapping arithmetic (wrapping_add, etc.) depending on your needs. For user-facing code, prefer checked arithmetic with proper error handling.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-AI-006: AI Panic in Library Public API
// Severity: medium | CWE-248
// AI generates pub fn with unwrap/expect without #[track_caller]
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustAiPanicInLibrary;

impl LangRule for RustAiPanicInLibrary {
    fn id(&self) -> &str { "RUST-AI-006" }
    fn name(&self) -> &str { "AI: Panic Risk in Library Public API" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let func_re = Regex::new(r"(?m)^#\[(?:doc\s*)?\]?\s*\n\s*(?:pub\s+)+fn\s+(\w+)").unwrap();
        let panic_re = Regex::new(r"\b(unwrap|expect|unwrap_err|expect_err)\s*\(").unwrap();

        for caps in func_re.captures_iter(code) {
            let func_name = caps.get(1).map(|x| x.as_str()).unwrap_or("");
            let func_start = caps.get(0).unwrap().end();
            let func_line = code[..caps.get(0).unwrap().start()].matches('\n').count() + 1;

            let after_func = &code[func_start..];
            let next_100 = after_func.lines().take(100).collect::<String>();
            let brace_count = next_100.matches('{').count().saturating_sub(next_100.matches('}').count());
            if brace_count == 0 {
                continue;
            }

            let func_body_end = after_func.find(|c: char| c == '}').map(|p| func_start + p).unwrap_or(code.len());
            let func_body = &code[func_start..func_body_end];

            let has_track_caller = func_body.contains("#[track_caller]");
            let has_panic = panic_re.is_match(func_body);

            if has_panic && !has_track_caller {
                let (start, end) = get_line_offsets(code, func_line);
                let line_text = get_line_text(code, func_line).unwrap_or_default();

                let panic_matches: Vec<&str> = panic_re
                    .captures_iter(func_body)
                    .filter_map(|caps| caps.get(1).map(|m| m.as_str()))
                    .collect();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: func_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Public library function '{}' uses {:?} which can panic. This creates a denial-of-service risk for callers.", func_name, panic_matches),
                    fix_hint: "Return a Result or Option instead of panicking. If panicking is acceptable, add #[track_caller] for better stack traces. Consider using unwrap_or, unwrap_or_else, or ? operator.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUST-AI-007: AI Incorrect Lifetime Annotation
// Severity: medium | CWE-561
// AI generates incorrect or unnecessary lifetime annotations
// ─────────────────────────────────────────────────────────────────────────────
pub struct RustAiLifetimeIssues;

impl LangRule for RustAiLifetimeIssues {
    fn id(&self) -> &str { "RUST-AI-007" }
    fn name(&self) -> &str { "AI: Lifetime Annotation Issues" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let single_lifetime_re = Regex::new(r"fn\s+\w+<'a>\s*\([^)]*\)\s*->\s*[^&]*<'a>").unwrap();
        let unnecessary_lifetime_re = Regex::new(r"fn\s+\w+<'a>\s*\([^)]*&'a\s+\w+[^)]*\)\s*->\s*&'a\s+\w+").unwrap();
        let static_lifetime_re = Regex::new(r###"(?i)"static['"`]|Lifetime::static"###).unwrap();

        for m in single_lifetime_re.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let (start, end) = get_line_offsets(code, line);
            let line_text = get_line_text(code, line).unwrap_or_default();
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: line_text.trim().to_string(),
                problem: "Single lifetime 'a used in return type but function doesn't borrow any references with that lifetime. The lifetime annotation may be unnecessary.".to_string(),
                fix_hint: "Remove the unnecessary lifetime annotation: fn foo(x: &str) -> &str instead of fn foo<'a>(x: &'a str) -> &'a str.".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        for m in unnecessary_lifetime_re.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let (start, end) = get_line_offsets(code, line);
            let line_text = get_line_text(code, line).unwrap_or_default();
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: line_text.trim().to_string(),
                problem: "Lifetime 'a is used for both input and output references but doesn't constrain the output. The lifetime may be unnecessary or incorrectly inferred.".to_string(),
                fix_hint: "Remove the lifetime if it's only used once: fn foo(x: &str) -> &str. Or ensure the lifetime properly connects input and output references.".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        for m in static_lifetime_re.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let (start, end) = get_line_offsets(code, line);
            let line_text = get_line_text(code, line).unwrap_or_default();
            if !line_text.trim().starts_with("//") && !line_text.trim().starts_with("/*") {
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: "'static lifetime annotation may be too restrictive. The data may not actually live for the entire program duration.".to_string(),
                    fix_hint: "Only use 'static when the data truly lives for the entire program (e.g., string literals). For owned data, avoid 'static and let the compiler infer lifetimes.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

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
        Box::new(RustUnusedMut),
        Box::new(RustCloneInLoop),
        Box::new(RustUnnecessaryBox),
        Box::new(RustTodoComments),
        Box::new(RustDeadCodeAfterReturn),
        Box::new(RustMissingDebugDerive),
        Box::new(RustEmptyMatchArm),
        Box::new(RustAiUnwrapPanic),
        Box::new(RustAiUnsafeNoDocs),
        Box::new(RustAiWrongSyncPrimitive),
        Box::new(RustAiHardcodedSecrets),
        Box::new(RustAiIntegerOverflow),
        Box::new(RustAiPanicInLibrary),
        Box::new(RustAiLifetimeIssues),
    ]
}
