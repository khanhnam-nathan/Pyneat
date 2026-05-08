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
use super::super::base::{LangRule, LangFinding};

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

/// Helper: add a finding from a regex pattern
fn add_finding(
    findings: &mut Vec<LangFinding>,
    rule_id: &str,
    severity: &str,
    pattern: &str,
    problem: &str,
    fix_hint: &str,
    code: &str,
) {
    if let Ok(re) = Regex::new(pattern) {
        for m in re.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let (start, end) = get_line_offsets(code, line);
            let line_text = get_line_text(code, line).unwrap_or_default();

            findings.push(LangFinding {
                rule_id: rule_id.to_string(),
                severity: severity.to_string(),
                line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: line_text.trim().to_string(),
                problem: problem.to_string(),
                fix_hint: fix_hint.to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-QUAL-001: Empty Error Check
// Severity: medium | CWE-252
// Detects: ignoring errors with _ assignment or empty if blocks
// AI often ignores errors which leads to silent failures
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoEmptyErrorCheck;

impl LangRule for GoEmptyErrorCheck {
    fn id(&self) -> &str { "GO-QUAL-001" }
    fn name(&self) -> &str { "Empty Error Check (Ignored Error)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for call in &tree.calls {
            // Detect: _ = someFunc() or someVar, _ = someFunc()
            if call.callee.contains("Error()") || call.callee.contains("err") {
                if call.arguments.iter().any(|a| a.trim() == "_") {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: format!("{}()", call.callee),
                        problem: "Error return value is being ignored (assigned to _). This can lead to silent failures.".to_string(),
                        fix_hint: "Handle the error properly with if err != nil { ... }.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-QUAL-002: TODO / FIXME Comments
// Severity: info | CWE-546
// AI leaves TODO comments marking incomplete parts
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoTodoComments;

impl LangRule for GoTodoComments {
    fn id(&self) -> &str { "GO-QUAL-002" }
    fn name(&self) -> &str { "TODO / FIXME Comments" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r"(?i)TODO", "TODO marker"),
            (r"(?i)FIXME", "FIXME marker"),
            (r"(?i)HACK", "HACK marker"),
            (r"(?i)XXX", "XXX marker"),
            (r"(?i)DEPRECATED", "DEPRECATED marker"),
            (r"(?i)BUG", "BUG marker"),
        ];

        for comment in &tree.comments {
            for (pattern, label) in &patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(&comment.text) {
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: comment.start_line,
                            column: 0,
                            start_byte: 0,
                            end_byte: 0,
                            snippet: comment.text.clone(),
                            problem: format!("{}: Unresolved marker found in code.", label),
                            fix_hint: "Resolve the TODO/FIXME or add a tracking issue.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-QUAL-003: Magic Numbers
// Severity: info | CWE-184
// AI uses hardcoded magic numbers instead of named constants
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoMagicNumbers;

impl LangRule for GoMagicNumbers {
    fn id(&self) -> &str { "GO-QUAL-003" }
    fn name(&self) -> &str { "Magic Numbers" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Match multi-digit numeric literals (> 2 digits) excluding floats like 3.14
        let pattern = r"(?<![.\w])(\d{3,})(?![.\d])";
        if let Ok(re) = Regex::new(pattern) {
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                // Skip if it's in a string or comment
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
                    problem: format!("Magic number '{}' found. Use a named constant instead.", m.as_str()),
                    fix_hint: "Define a const (e.g., const MaxRetries = 500) instead of using raw numbers.".to_string(),
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
// GO-QUAL-004: Deep Nesting
// Severity: medium | CWE-510
// AI often generates deeply nested callback/helper functions
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoDeepNesting;

impl LangRule for GoDeepNesting {
    fn id(&self) -> &str { "GO-QUAL-004" }
    fn name(&self) -> &str { "Deep Nesting (> 4 levels)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let max_depth = 4;

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim_start();

            // Count nesting by leading whitespace (4 spaces = 1 level)
            let leading_spaces = line.len() - line.trim_start().len();
            let depth = leading_spaces / 4;

            if depth > max_depth && !trimmed.is_empty() && !trimmed.starts_with("//") {
                let (start, end) = get_line_offsets(code, line_idx + 1);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: trimmed.to_string(),
                    problem: format!("Deep nesting detected (depth {}). Consider extracting nested logic into separate functions.", depth),
                    fix_hint: "Extract deeply nested code into helper functions to improve readability.".to_string(),
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
// GO-QUAL-005: Unused Variables (Blank Identifier)
// Severity: info | CWE-563
// AI sometimes assigns to variables that are never used
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoUnusedVariables;

impl LangRule for GoUnusedVariables {
    fn id(&self) -> &str { "GO-QUAL-005" }
    fn name(&self) -> &str { "Unused Variable (Blank Identifier)" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Simple detection: any call returning multiple values assigned to blank
        for call in &tree.calls {
            let has_blank_in_args = call.arguments.iter().any(|a| a.trim() == "_");
            let has_blank_in_callee = call.callee.contains("_,");

            if has_blank_in_args || has_blank_in_callee {
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: format!("{}()", call.callee),
                    problem: "Multiple return values assigned with blank identifier (_). Ensure this is intentional.".to_string(),
                    fix_hint: "If ignoring an error, consider logging it: if err != nil { log.Printf(...) }. If ignoring a return value, ensure it's intentional.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-QUAL-006: Error Returned but Not Checked
// Severity: medium | CWE-252
// AI assigns error to variable but never checks it
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoUncheckedErrorReturn;

impl LangRule for GoUncheckedErrorReturn {
    fn id(&self) -> &str { "GO-QUAL-006" }
    fn name(&self) -> &str { "Error Assigned but Not Checked" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Pattern: err := someFunc() followed by code that doesn't check err
        // We detect: if err != nil is missing after err := assignment
        let err_assign_re = Regex::new(r"(?m)^\s*err\s*:?=\s*[\w.]+\([^)]*\)").unwrap();
        let err_check_re = Regex::new(r"(?m)^\s*if\s+err\s*!=\s*nil").unwrap();

        for m in err_assign_re.find_iter(code) {
            let assign_line = code[..m.start()].matches('\n').count() + 1;

            // Get next 10 lines to check for error handling
            let after = &code[m.end()..];
            let next_lines: String = after.lines().take(10).collect();
            let line_text = get_line_text(code, assign_line).unwrap_or_default();

            // Skip if it's already followed by an if err != nil check
            if err_check_re.is_match(&next_lines) {
                continue;
            }

            // Skip if it's in a deferred function where checking is optional
            if line_text.contains("defer") {
                continue;
            }

            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: assign_line,
                column: 0,
                start_byte: 0,
                end_byte: 0,
                snippet: line_text.trim().to_string(),
                problem: "Error return value is assigned but never checked. Unchecked errors can cause silent failures.".to_string(),
                fix_hint: "Add error handling: if err != nil { return err, ... } or log.Fatalf(...).".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-QUAL-007: Missing Context in Function Calls
// Severity: medium | CWE-400
// AI generates HTTP or DB calls without passing context
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoMissingContext;

impl LangRule for GoMissingContext {
    fn id(&self) -> &str { "GO-QUAL-007" }
    fn name(&self) -> &str { "Missing Context in Function Calls" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let context_funcs = [
            "http.DefaultClient.Do",
            "http.Get",
            "http.Post",
            "http.PostForm",
            "database/sql.Open",
            "db.Query",
            "db.QueryRow",
            "db.Exec",
        ];

        for call in &tree.calls {
            for target in &context_funcs {
                if call.callee.contains(target) {
                    // Check if context is passed (ctx, or context.*)
                    let has_context = call.arguments.iter().any(|a| {
                        a.contains("ctx") || a.contains("context")
                    });

                    if !has_context {
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: 0,
                            end_byte: 0,
                            snippet: format!("{}()", call.callee),
                            problem: format!("{}.__context__() called without context. This can cause request cancellation issues.", call.callee),
                            fix_hint: "Pass context as first argument: {}(ctx, ...) instead of {}(...).".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                    }
                }
            }
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-QUAL-008: Hardcoded String Literals (should be constants)
// Severity: low | CWE-547
// AI uses hardcoded strings instead of const declarations
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoHardcodedStrings;

impl LangRule for GoHardcodedStrings {
    fn id(&self) -> &str { "GO-QUAL-008" }
    fn name(&self) -> &str { "Hardcoded String Literals" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Match string literals that appear more than 3 times (likely should be constants)
        let string_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

        // Actually, just flag strings that are > 20 chars and appear to be config-like
        let pattern = r#""[^"]{20,}""#;
        if let Ok(re) = Regex::new(pattern) {
            let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();

            for m in re.find_iter(code) {
                let s = m.as_str();
                // Skip if it's a URL, path, or already flagged
                if s.contains("://") || s.contains("/") || seen.contains(s) {
                    continue;
                }
                seen.insert(s);

                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                // Skip imports and comments
                if line_text.trim().starts_with("import") || line_text.trim().starts_with("//") {
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
                    problem: format!("Long hardcoded string literal found. Consider using a named constant.", ),
                    fix_hint: "Define as const: const Name = \"value\" or use environment variables.".to_string(),
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
// GO-QUAL-009:.Printf / log.Printf without format arguments
// Severity: low | CWE-134
// AI sometimes uses incorrect format strings causing panics
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoPrintfIssues;

impl LangRule for GoPrintfIssues {
    fn id(&self) -> &str { "GO-QUAL-009" }
    fn name(&self) -> &str { "Printf / Log Issues" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns: Vec<(&str, &str, &str)> = vec![
            (r#"fmt\.Printf\s*\(\s*"[^"]*%[sdv]"[^"]*"\s*\)"#, "Printf with wrong format specifier count", "Check that the number of % specifiers matches the arguments."),
            (r#"fmt\.Println\s*\(\s*"[^"]*%[sdv]"#, "Println with format specifier", "Use fmt.Printf for formatted output, not Println."),
            (r#"fmt\.Sprintf\s*\([^,]+,\s*"[^"]*%[sdv]"[^"]*"\s*\)"#, "Sprintf with format issues", "Ensure format specifiers match argument count."),
        ];

        for (pat, label, hint) in &patterns {
            add_finding(
                &mut findings,
                self.id(),
                self.severity(),
                pat,
                label,
                hint,
                code,
            );
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-QUAL-010: Empty struct literal or empty map/slice initialization
// Severity: info | CWE-475
// AI sometimes initializes empty containers unnecessarily
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoEmptyInitializations;

impl LangRule for GoEmptyInitializations {
    fn id(&self) -> &str { "GO-QUAL-010" }
    fn name(&self) -> &str { "Empty Initialization Statements" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (
                r"(?m)^\s*_ = \{}",
                "Empty struct assigned to blank identifier",
                "Remove unnecessary empty struct literal or use it explicitly.",
            ),
            (
                r"(?m)^\s*var\s+[a-zA-Z_]+\s+=\s+\{\}",
                "Empty struct initialization",
                "Use struct literal only when needed.",
            ),
            (
                r"(?m)^\s*:\s*=\s*make\s*\(\s*(?:map|slice|chan)\s*,\s*0\s*\)",
                "make() with capacity 0 is unnecessary",
                "Omit the capacity argument: make(map[K]V) instead of make(map[K]V, 0).",
            ),
        ];

        for (pat, label, hint) in &patterns {
            add_finding(
                &mut findings,
                self.id(),
                self.severity(),
                pat,
                label,
                hint,
                code,
            );
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// All Go Quality Rules
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// GO-QUAL-011: Deep Nesting (> 4 levels)
// Severity: medium | CWE-510
// AI generates deeply nested callback/helper functions
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoDeepNestingQuality;

impl LangRule for GoDeepNestingQuality {
    fn id(&self) -> &str { "GO-QUAL-011" }
    fn name(&self) -> &str { "Deep Nesting (> 4 levels)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let max_depth = 4;

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            let leading_spaces = line.len() - line.trim_start().len();
            let depth = leading_spaces / 4;

            if depth > max_depth && !trimmed.is_empty() && !trimmed.starts_with("//") {
                let (start, end) = get_line_offsets(code, line_idx + 1);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: trimmed.to_string(),
                    problem: format!("Deep nesting detected (depth {}). Consider extracting nested logic into separate functions.", depth),
                    fix_hint: "Extract deeply nested code into helper functions to improve readability.".to_string(),
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
// GO-QUAL-012: Unused Variables
// Severity: info | CWE-563
// AI sometimes assigns to variables that are never used
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoUnusedVars;

impl LangRule for GoUnusedVars {
    fn id(&self) -> &str { "GO-QUAL-012" }
    fn name(&self) -> &str { "Unused Variable" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let assign_re = Regex::new(r"(?m)^\s*(\w+)\s*:?=\s*").unwrap();

        for caps in assign_re.captures_iter(code) {
            let var_name = caps.get(1).map(|x| x.as_str()).unwrap_or("");
            if var_name == "_" || var_name == "err" {
                continue;
            }
            let line = code[..caps.get(0).unwrap().start()].matches('\n').count() + 1;
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
                problem: format!("Variable '{}' is assigned but may not be used. Unused variables indicate incomplete AI-generated code.", var_name),
                fix_hint: "Use the variable or remove the assignment. If intentionally ignored, use _ to explicitly discard.".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-QUAL-013: TODO/FIXME Comments
// Severity: info | CWE-546
// AI leaves TODO comments marking incomplete parts
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoTodoCommentsQuality;

impl LangRule for GoTodoCommentsQuality {
    fn id(&self) -> &str { "GO-QUAL-013" }
    fn name(&self) -> &str { "TODO / FIXME Comments" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r"(?i)TODO", "TODO marker"),
            (r"(?i)FIXME", "FIXME marker"),
            (r"(?i)HACK", "HACK marker"),
            (r"(?i)XXX", "XXX marker"),
            (r"(?i)DEPRECATED", "DEPRECATED marker"),
        ];

        for comment in &tree.comments {
            for (pattern, label) in &patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(&comment.text) {
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: comment.start_line,
                            column: 0,
                            start_byte: 0,
                            end_byte: 0,
                            snippet: comment.text.clone(),
                            problem: format!("{}: Unresolved marker found in code.", label),
                            fix_hint: "Resolve the TODO/FIXME or add a tracking issue.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-QUAL-014: Empty String Slice Check
// Severity: info | CWE-252
// AI generates empty string checks that may not handle all cases
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoEmptyStringCheck;

impl LangRule for GoEmptyStringCheck {
    fn id(&self) -> &str { "GO-QUAL-014" }
    fn name(&self) -> &str { "Empty String Check" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"(?m)^\s*if\s+len\s*\(\s*\w+\s*\)\s*==\s*0"#, "len(x) == 0 check"),
            (r#"(?m)^\s*if\s+\w+\s*==\s*""#, "x == \"\" check"),
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
                        problem: format!("Empty string/length check detected: '{}'. Note: len(x) == 0 is correct but len(x) == 0 for nil slice returns true (which is correct).", label),
                        fix_hint: "Prefer len(x) == 0 over x == \"\" for consistency. For strings, also consider strings.TrimSpace(x) == \"\" to handle whitespace-only strings.".to_string(),
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
// GO-QUAL-015: Missing defer for Cleanup
// Severity: medium | CWE-460
// AI forgets to use defer for cleanup (close files, connections)
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoMissingDefer;

impl LangRule for GoMissingDefer {
    fn id(&self) -> &str { "GO-QUAL-015" }
    fn name(&self) -> &str { "Missing defer for Cleanup" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let cleanup_calls: HashSet<&str> = [
            "Close", "Finish", "Cleanup", "Shutdown", "Destroy", "Reset",
        ].into_iter().collect();

        for call in &tree.calls {
            let fn_name = call.callee.split('.').last().unwrap_or("");
            if cleanup_calls.contains(fn_name) {
                let line = code.lines().nth(call.start_line - 1).unwrap_or("");
                if !line.contains("defer") && !line.contains("go ") {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: format!("{}(...)", call.callee),
                        problem: format!("Cleanup method '{}' called without defer. If an error occurs before this call, cleanup may not run.", fn_name),
                        fix_hint: "Use defer to ensure cleanup: defer obj.Close(). This guarantees the cleanup runs even if the function returns early due to an error.".to_string(),
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
// GO-QUAL-016: Shadowing Variable Declaration
// Severity: low | CWE-478
// AI accidentally shadows outer variables with same name
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoVariableShadowing;

impl LangRule for GoVariableShadowing {
    fn id(&self) -> &str { "GO-QUAL-016" }
    fn name(&self) -> &str { "Variable Shadowing" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let shadow_re = Regex::new(r"(?m)^\s*(var\s+(\w+)\s*=|[A-Z]\w*\s*(\w+)\s*:=\s*)").unwrap();

        for caps in shadow_re.captures_iter(code) {
            let var_name = caps.get(2).or(caps.get(3)).map(|x| x.as_str()).unwrap_or("");
            if var_name.is_empty() {
                continue;
            }

            let line = code[..caps.get(0).unwrap().start()].matches('\n').count() + 1;
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
                problem: format!("Variable '{}' may shadow an outer variable with the same name. This can lead to subtle bugs.", var_name),
                fix_hint: "Use a different variable name or explicitly reference the outer variable with a package prefix.".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-QUAL-017: Empty Default in Switch
// Severity: info
// AI generates switch without default case
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoSwitchWithoutDefault;

impl LangRule for GoSwitchWithoutDefault {
    fn id(&self) -> &str { "GO-QUAL-017" }
    fn name(&self) -> &str { "Switch Without Default Case" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let switch_re = Regex::new(r"(?m)^\s*switch\s+").unwrap();
        let default_re = Regex::new(r"(?m)^\s*default\s*:").unwrap();

        let switch_lines: Vec<usize> = switch_re
            .find_iter(code)
            .map(|m| code[..m.start()].matches('\n').count() + 1)
            .collect();

        let default_lines: Vec<usize> = default_re
            .find_iter(code)
            .map(|m| code[..m.start()].matches('\n').count() + 1)
            .collect();

        for sw_line in &switch_lines {
            let has_default = default_lines.iter().any(|dl| *dl > *sw_line && *dl - sw_line < 100);
            if !has_default {
                let (start, end) = get_line_offsets(code, *sw_line);
                let line_text = get_line_text(code, *sw_line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: *sw_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: "Switch statement without default case. Unhandled cases may indicate bugs.".to_string(),
                    fix_hint: "Add a default case to handle unexpected values: default: return error or log the unexpected state.".to_string(),
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
// GO-QUAL-018: Unnecessary Make for Slices
// Severity: info
// AI uses make() for slices when simple literals suffice
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoUnnecessaryMake;

impl LangRule for GoUnnecessaryMake {
    fn id(&self) -> &str { "GO-QUAL-018" }
    fn name(&self) -> &str { "Unnecessary make() for Slices" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let make_pattern = Regex::new(r"make\s*\(\s*\[\]\w+\s*,\s*0\s*\)").unwrap();

        for m in make_pattern.find_iter(code) {
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
                problem: "make([]T, 0) is unnecessary. A nil slice is already an empty slice and can be appended to directly.".to_string(),
                fix_hint: "Use var slice []T instead of make([]T, 0) for empty slices that will be appended to.".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-QUAL-019: Error Not Handled After Assignment
// Severity: medium | CWE-252
// AI assigns error to variable but never checks it
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoErrorNotHandled;

impl LangRule for GoErrorNotHandled {
    fn id(&self) -> &str { "GO-QUAL-019" }
    fn name(&self) -> &str { "Error Assigned but Not Checked" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let err_assign_re = Regex::new(r"(?m)^\s*err\s*:?=\s*[\w.]+\([^)]*\)").unwrap();
        let err_check_re = Regex::new(r"(?m)^\s*if\s+err\s*!=\s*nil").unwrap();

        for m in err_assign_re.find_iter(code) {
            let assign_line = code[..m.start()].matches('\n').count() + 1;
            let after = &code[m.end()..];
            let next_lines: String = after.lines().take(10).collect();
            let line_text = get_line_text(code, assign_line).unwrap_or_default();

            if err_check_re.is_match(&next_lines) || line_text.contains("defer") {
                continue;
            }

            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: assign_line,
                column: 0,
                start_byte: 0,
                end_byte: 0,
                snippet: line_text.trim().to_string(),
                problem: "Error return value is assigned but never checked. Unchecked errors can cause silent failures.".to_string(),
                fix_hint: "Add error handling: if err != nil { return err, ... } or log.Fatalf(...).".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-QUAL-020: Hardcoded String Literals (should be constants)
// Severity: low | CWE-547
// AI uses hardcoded strings instead of const declarations
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoHardcodedStringsQuality;

impl LangRule for GoHardcodedStringsQuality {
    fn id(&self) -> &str { "GO-QUAL-020" }
    fn name(&self) -> &str { "Hardcoded String Literals" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let pattern = r#""[^"]{20,}""#;
        if let Ok(re) = Regex::new(pattern) {
            let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();

            for m in re.find_iter(code) {
                let s = m.as_str();
                if s.contains("://") || s.contains("/") || s.contains("\\") || seen.contains(s) {
                    continue;
                }
                seen.insert(s);

                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                if line_text.trim().starts_with("import") || line_text.trim().starts_with("//") {
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
                    problem: "Long hardcoded string literal found. Consider using a named constant.".to_string(),
                    fix_hint: "Define as const: const Name = \"value\" or use environment variables.".to_string(),
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
// All Go Quality Rules
// ─────────────────────────────────────────────────────────────────────────────

/// Get all Go quality rules.
pub fn go_quality_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(GoEmptyErrorCheck),
        Box::new(GoTodoComments),
        Box::new(GoMagicNumbers),
        Box::new(GoDeepNesting),
        Box::new(GoUnusedVariables),
        Box::new(GoUncheckedErrorReturn),
        Box::new(GoMissingContext),
        Box::new(GoHardcodedStrings),
        Box::new(GoPrintfIssues),
        Box::new(GoEmptyInitializations),
        Box::new(GoDeepNestingQuality),
        Box::new(GoUnusedVars),
        Box::new(GoTodoCommentsQuality),
        Box::new(GoEmptyStringCheck),
        Box::new(GoMissingDefer),
        Box::new(GoVariableShadowing),
        Box::new(GoSwitchWithoutDefault),
        Box::new(GoUnnecessaryMake),
        Box::new(GoErrorNotHandled),
        Box::new(GoHardcodedStringsQuality),
    ]
}
