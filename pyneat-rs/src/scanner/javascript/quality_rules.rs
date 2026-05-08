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
// JS-QUAL-001: Unused Variable
// Severity: info
// Auto-fix: remove unused variable declaration
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsUnusedVariable;

impl LangRule for JsUnusedVariable {
    fn id(&self) -> &str { "JS-QUAL-001" }
    fn name(&self) -> &str { "Unused Variable Declaration" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Collect assigned variables
        let assigned_vars: HashSet<String> = tree.assignments.iter()
            .map(|a| a.name.clone())
            .collect();

        // Collect used variables from calls and assignments
        let mut used_vars: HashSet<String> = HashSet::new();

        for call in &tree.calls {
            for arg in &call.arguments {
                let words: Vec<&str> = arg.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '.').collect();
                for word in words {
                    if assigned_vars.contains(word) {
                        used_vars.insert(word.to_string());
                    }
                }
            }
        }

        for assignment in &tree.assignments {
            // Variable is used on right side of another assignment
            for later in &tree.assignments {
                if later.start_line > assignment.start_line
                    && later.value.as_ref().map(|v| v.contains(&assignment.name)).unwrap_or(false)
                {
                    used_vars.insert(assignment.name.clone());
                }
            }
        }

        for assignment in &tree.assignments {
            if !used_vars.contains(&assignment.name)
                && !assignment.name.starts_with('_')
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
                    fix_hint: "Remove the unused variable declaration or prefix it with '_' \
                        to indicate it's intentionally unused.".to_string(),
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

        // Comment out the unused variable
        if trimmed.starts_with("const ") || trimmed.starts_with("let ") || trimmed.starts_with("var ") {
            let indent = &line_text[..line_text.len() - line_text.trim_start().len()];
            let commented = format!("{}// UNUSED: {}", indent, trimmed);
            Some(LangFix {
                rule_id: self.id().to_string(),
                original: line_text,
                replacement: commented,
                start_byte: finding.start_byte,
                end_byte: finding.end_byte,
                description: "Comment out unused variable".to_string(),
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-QUAL-002: Empty Block (if/else/try/catch)
// Severity: info
// Auto-fix: comment out empty blocks
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsEmptyBlock;

impl LangRule for JsEmptyBlock {
    fn id(&self) -> &str { "JS-QUAL-002" }
    fn name(&self) -> &str { "Empty Block Statement" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let empty_block_pattern = Regex::new(
            r"(?m)^\s*(if|else|for|while|switch|try|catch|finally)\s*\([^)]*\)\s*\{\s*\}"
        ).unwrap();

        let block_with_only_comment = Regex::new(
            r"(?m)^\s*(if|else|for|while|switch|try|catch|finally)\s*\([^)]*\)\s*\{\s*(?://.*)?\s*\}"
        ).unwrap();

        for m in empty_block_pattern.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let is_just_comment = block_with_only_comment.is_match(m.as_str());

            if !is_just_comment {
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
                    problem: "Empty block statement detected. Empty blocks do nothing and may indicate incomplete implementation.".to_string(),
                    fix_hint: "Either remove the empty block or add meaningful logic. \
                        For catch blocks, consider logging the error or re-throwing.".to_string(),
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
        let indent = &line_text[..line_text.len() - line_text.trim_start().len()];

        // Comment out the empty block
        let commented = format!("{}// FIXME: empty block - {}", indent, trimmed);
        Some(LangFix {
            rule_id: self.id().to_string(),
            original: line_text,
            replacement: commented,
            start_byte: finding.start_byte,
            end_byte: finding.end_byte,
            description: "Comment out empty block".to_string(),
        })
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-QUAL-003: Deep Nesting (Arrow Anti-pattern)
// Severity: medium
// AI generates deeply nested callbacks
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsDeepNesting;

impl LangRule for JsDeepNesting {
    fn id(&self) -> &str { "JS-QUAL-003" }
    fn name(&self) -> &str { "Deep Nesting (Arrow Anti-pattern)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check deep nesting from LnAst
        for dn in &tree.deep_nesting {
            if dn.depth >= 4 {
                let (start, end) = get_line_offsets(code, dn.line);
                let line_text = get_line_text(code, dn.line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: dn.line,
                    column: dn.column,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!(
                        "Deep nesting detected at depth {} (line {}{}). \
                        AI-generated code often has deeply nested callbacks (callback hell). \
                        This reduces readability and maintainability.",
                        dn.depth,
                        dn.line,
                        dn.column
                    ),
                    fix_hint: "Refactor using async/await, Promise chaining, or extract nested logic \
                        into separate functions. Consider using a state machine or event-driven approach \
                        instead of deeply nested callbacks.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        // Also detect .then().then().then() patterns
        let callback_chain = Regex::new(r"\)\s*\.\s*then\s*\(.*\)\s*\.\s*then\s*\(").unwrap();
        for m in callback_chain.find_iter(code) {
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
                    problem: "Promise .then() chain detected. Multiple .then() calls indicate callback nesting.".to_string(),
                    fix_hint: "Use async/await for cleaner, more readable asynchronous code. \
                        Example: const result = await fetchData(); process(result);".to_string(),
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
// JS-QUAL-004: Mutating Global State
// Severity: medium
// AI modifies global objects without warning
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsMutatingGlobalState;

impl LangRule for JsMutatingGlobalState {
    fn id(&self) -> &str { "JS-QUAL-004" }
    fn name(&self) -> &str { "Global State Mutation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let global_objects: HashSet<&str> = [
            "window", "document", "navigator", "localStorage",
            "sessionStorage", "global", "globalThis", "process",
            "Math", "JSON", "Array", "Object", "String", "Number",
        ].into_iter().collect();

        let mutation_pattern = Regex::new(r#"(window|document|global|navigator|localStorage|sessionStorage|globalThis)\.(\w+)\s*="#).unwrap();

        for call in &tree.calls {
            let parts: Vec<&str> = call.callee.split('.').collect();
            if parts.len() >= 2 {
                let obj = parts[0];
                let prop = parts[1];

                if global_objects.contains(obj) && !prop.starts_with('_') {
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
                            "Mutation of global object '{}': '{}.{}'. \
                            Modifying global state makes code harder to test and reason about.",
                            obj, obj, prop
                        ),
                        fix_hint: "Avoid modifying global objects. Use local variables, modules, \
                            or dependency injection. If you must modify window/document, document \
                            the side effects clearly.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        // Check for direct property assignment to globals
        for m in mutation_pattern.find_iter(code) {
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
                    problem: "Direct assignment to global object property detected.".to_string(),
                    fix_hint: "Consider encapsulating global modifications in modules or services. \
                        Document side effects and ensure proper cleanup.".to_string(),
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
// JS-QUAL-005: Complex Conditional Expression
// Severity: low
// AI generates overly complex boolean expressions
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsComplexCondition;

impl LangRule for JsComplexCondition {
    fn id(&self) -> &str { "JS-QUAL-005" }
    fn name(&self) -> &str { "Complex Conditional Expression" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Count && and || operators in expressions
        let _complex_pattern = Regex::new(r"&&|&{2}.*&&|&{2}.*\|\||\|\|.*\|\||\|\|.*&&").unwrap();

        // Also detect deeply nested ternary operators
        let nested_ternary = Regex::new(r"\?\s*[^:]*\?\s*[^:]*:").unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            // Check for complex conditionals
            let and_or_count = line.matches("&&").count() + line.matches("||").count();
            if and_or_count >= 4 {
                let (start, end) = get_line_offsets(code, line_num);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_num,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: trimmed.to_string(),
                    problem: format!(
                        "Complex conditional with {} &&/|| operators. \
                        AI-generated code often has overly complex boolean expressions.",
                        and_or_count
                    ),
                    fix_hint: "Extract complex conditions into well-named boolean variables or \
                        helper functions. Example: const isValid = hasName && hasEmail && hasPassword; \
                        if (isValid) { ... }".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }

            // Check for nested ternaries
            if nested_ternary.is_match(line) {
                let (start, end) = get_line_offsets(code, line_num);
                if !findings.iter().any(|f: &LangFinding| f.line == line_num) {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: line_num,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: trimmed.to_string(),
                        problem: "Nested ternary operator detected. Chained ternaries are hard to read.".to_string(),
                        fix_hint: "Replace nested ternaries with if/else statements or extract \
                            into helper functions for better readability.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-QUAL-006: Duplicate Import
// Severity: info
// AI sometimes generates duplicate import statements
// Auto-fix: remove duplicate imports
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsDuplicateImport;

impl LangRule for JsDuplicateImport {
    fn id(&self) -> &str { "JS-QUAL-006" }
    fn name(&self) -> &str { "Duplicate Import Statement" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Group imports by module
        let mut module_counts: std::collections::HashMap<String, Vec<usize>> = std::collections::HashMap::new();

        for imp in &tree.imports {
            let module_key = imp.module.clone();
            module_counts.entry(module_key).or_default().push(imp.start_line);
        }

        for (module, lines) in module_counts {
            if lines.len() > 1 {
                // First occurrence is fine, mark others as duplicates
                for &line in lines.iter().skip(1) {
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
                        problem: format!(
                            "Duplicate import of '{}'. This module is imported multiple times.",
                            module
                        ),
                        fix_hint: "Merge duplicate imports into a single statement. \
                            Example: import { a } from 'mod'; import { b } from 'mod'; \
                            -> import {{ a, b }} from 'mod';".to_string(),
                        auto_fix_available: true,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = get_line_text(code, finding.line)?;
        let trimmed = line_text.trim();
        let indent = &line_text[..line_text.len() - line_text.trim_start().len()];

        // Comment out duplicate import
        let commented = format!("{}// DUPLICATE: {}", indent, trimmed);
        Some(LangFix {
            rule_id: self.id().to_string(),
            original: line_text,
            replacement: commented,
            start_byte: finding.start_byte,
            end_byte: finding.end_byte,
            description: "Comment out duplicate import".to_string(),
        })
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-QUAL-007: Deep Nesting
// Severity: medium | CWE-510
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsDeepNestingQuality;

impl LangRule for JsDeepNestingQuality {
    fn id(&self) -> &str { "JS-QUAL-007" }
    fn name(&self) -> &str { "Deep Nesting (> 4 levels)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let max_depth = 4;
        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            let leading = line.len() - line.trim_start().len();
            let depth = leading / 4;
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
                    problem: format!("Deep nesting (depth {}).", depth),
                    fix_hint: "Extract nested logic into separate functions.".to_string(),
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
// JS-QUAL-008: Callback Hell
// Severity: medium
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsCallbackHell;

impl LangRule for JsCallbackHell {
    fn id(&self) -> &str { "JS-QUAL-008" }
    fn name(&self) -> &str { "Callback Hell (Nested Callbacks > 3)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let re = Regex::new(r"\.then\(|\.catch\(|\.finally\(").unwrap();
        let cb_count: Vec<(usize, usize)> = re.find_iter(code)
            .map(|m| {
                let line = code[..m.start()].matches('\n').count() + 1;
                (line, m.start())
            })
            .collect();

        for i in 0..cb_count.len().saturating_sub(2) {
            if cb_count[i+1].0 == cb_count[i].0 && cb_count[i+1].1 > cb_count[i].1 {
                let nesting = cb_count.iter()
                    .filter(|(l, _)| *l == cb_count[i].0)
                    .count();
                if nesting > 3 {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: cb_count[i].0,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: "Multiple chained promise callbacks on same line.".to_string(),
                        problem: format!("Callback nesting depth {}. Consider using async/await.", nesting),
                        fix_hint: "Refactor to async/await for better readability.".to_string(),
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
// JS-QUAL-009: Magic Numbers
// Severity: info | CWE-184
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsMagicNumbers;

impl LangRule for JsMagicNumbers {
    fn id(&self) -> &str { "JS-QUAL-009" }
    fn name(&self) -> &str { "Magic Numbers in Code" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let pattern = r"(?<![.\w])(\d{3,})(?![.\d])";
        if let Ok(re) = Regex::new(pattern) {
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let line_text = get_line_text(code, line).unwrap_or_default();
                if !line_text.trim().starts_with("//") && !line_text.trim().starts_with("/*") {
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("Magic number '{}'. Use a named constant instead.", m.as_str()),
                        fix_hint: "Define as const: const MAX_RETRIES = 500;".to_string(),
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
// JS-QUAL-010: Missing Promise Catch Handler
// Severity: medium
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsMissingPromiseCatch;

impl LangRule for JsMissingPromiseCatch {
    fn id(&self) -> &str { "JS-QUAL-010" }
    fn name(&self) -> &str { "Missing Promise catch Handler" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let then_re = Regex::new(r"\.then\(").unwrap();
        let catch_re = Regex::new(r"\.catch\(").unwrap();
        let catch_lines: std::collections::HashSet<usize> = catch_re
            .find_iter(code)
            .map(|m| code[..m.start()].matches('\n').count() + 1)
            .collect();

        for m in then_re.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let after = &code[m.end()..];
            let next_50 = &after[..after.len().min(200)];
            if !catch_re.is_match(next_50) && !catch_lines.contains(&line) {
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
                    problem: "Promise chain without .catch() handler. Unhandled rejections may cause silent failures.".to_string(),
                    fix_hint: "Add .catch() or use try/catch with async/await.".to_string(),
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
// JS-QUAL-011: Global Variables
// Severity: low
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsGlobalVariables;

impl LangRule for JsGlobalVariables {
    fn id(&self) -> &str { "JS-QUAL-011" }
    fn name(&self) -> &str { "Global Variable Usage" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let re = Regex::new(r"(?m)^\s*(var|let)\s+(\w+)\s*=").unwrap();
        for m in re.captures_iter(code) {
            let var = m.get(2).map(|x| x.as_str()).unwrap_or("");
            if var.len() > 2 && !var.starts_with('_') {
                let line = code[..m.get(0).map(|x| x.start()).unwrap()].matches('\n').count() + 1;
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
                    problem: format!("Variable '{}' is declared globally without being in a module.", var),
                    fix_hint: "Use 'const' or 'let' inside a module scope.".to_string(),
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
// JS-QUAL-012: Empty Catch Block
// Severity: low
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsEmptyCatchBlock;

impl LangRule for JsEmptyCatchBlock {
    fn id(&self) -> &str { "JS-QUAL-012" }
    fn name(&self) -> &str { "Empty Catch Block" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let re = Regex::new(r"(?m)^\s*}?\s*catch\s*\([^)]+\)\s*\{\s*\}").unwrap();
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
                problem: "Empty catch block detected.".to_string(),
                fix_hint: "Add error handling or logging.".to_string(),
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
// JS-QUAL-013: console.log/debugger in production
// Severity: low
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsConsoleLogProduction;

impl LangRule for JsConsoleLogProduction {
    fn id(&self) -> &str { "JS-QUAL-013" }
    fn name(&self) -> &str { "Console/Debugger in Code" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r"console\.(log|debug|info|warn|error)\s*\(", "console.log/debug usage"),
            (r"\bdebugger\b", "debugger statement"),
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
                        problem: format!("{} found in code.", desc),
                        fix_hint: "Remove debug statements or use a logging library with levels.".to_string(),
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
// JS-QUAL-014: TODO/FIXME Comments
// Severity: info | CWE-546
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsTodoCommentsQuality;

impl LangRule for JsTodoCommentsQuality {
    fn id(&self) -> &str { "JS-QUAL-014" }
    fn name(&self) -> &str { "TODO / FIXME Comments" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r"(?i)TODO", "TODO marker"),
            (r"(?i)FIXME", "FIXME marker"),
            (r"(?i)HACK", "HACK marker"),
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
                        problem: format!("{} found.", label),
                        fix_hint: "Resolve or add tracking issue.".to_string(),
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
// Registry function
// ─────────────────────────────────────────────────────────────────────────────

/// All JavaScript quality rules.
pub fn js_quality_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(JsUnusedVariable),
        Box::new(JsEmptyBlock),
        Box::new(JsDeepNesting),
        Box::new(JsMutatingGlobalState),
        Box::new(JsComplexCondition),
        Box::new(JsDuplicateImport),
        Box::new(JsDeepNestingQuality),
        Box::new(JsCallbackHell),
        Box::new(JsMagicNumbers),
        Box::new(JsMissingPromiseCatch),
        Box::new(JsGlobalVariables),
        Box::new(JsEmptyCatchBlock),
        Box::new(JsConsoleLogProduction),
        Box::new(JsTodoCommentsQuality),
    ]
}
