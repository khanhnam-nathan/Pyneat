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
// JAVA-QUAL-001: Empty Catch Block
// Severity: info
// AI generates empty catch blocks
// Auto-fix: comment out empty catch
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaEmptyCatchBlock;

impl LangRule for JavaEmptyCatchBlock {
    fn id(&self) -> &str { "JAVA-QUAL-001" }
    fn name(&self) -> &str { "Empty Catch Block" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for catch in &tree.catch_blocks {
            if catch.is_empty {
                let (start, end) = get_line_offsets(code, catch.start_line);
                let line_text = get_line_text(code, catch.start_line)
                    .unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: catch.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!(
                        "Empty catch block detected{}.",
                        catch.exception_type.as_ref()
                            .map(|e| format!(" for exception type '{}'", e))
                            .unwrap_or_default()
                    ),
                    fix_hint: "Either remove the empty catch block or add proper error handling. \
                        At minimum, log the exception: \
                        } catch (Exception e) { logger.error(\"Error occurred\", e); }".to_string(),
                    auto_fix_available: true,
                });
            }
        }

        // Also detect empty catch using regex (for blocks that aren't caught by AST)
        let empty_catch_pattern = Regex::new(
            r"(?m)^\s*}?\s*catch\s*\([^)]+\)\s*\{\s*\}"
        ).unwrap();

        let catch_with_only_comment = Regex::new(
            r"(?m)^\s*}?\s*catch\s*\([^)]+\)\s*\{\s*(?://[^\n]*)?\s*\}"
        ).unwrap();

        for m in empty_catch_pattern.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let is_just_comment = catch_with_only_comment.is_match(m.as_str());

            if !is_just_comment && !findings.iter().any(|f: &LangFinding| f.line == line) {
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
                    fix_hint: "Add error handling: log the exception or rethrow with context.".to_string(),
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
        let indent = &line_text[..line_text.len() - line_text.trim_start().len()];

        // Comment out empty catch
        let commented = format!("{}// FIXME: empty catch block - {}", indent, trimmed);
        Some(LangFix {
            rule_id: self.id().to_string(),
            original: line_text,
            replacement: commented,
            start_byte: finding.start_byte,
            end_byte: finding.end_byte,
            description: "Comment out empty catch block".to_string(),
        })
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-QUAL-002: System.out / System.err Usage
// Severity: info
// AI uses System.out.println instead of logger
// Auto-fix: comment out System.out statements
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaSystemOutUsage;

impl LangRule for JavaSystemOutUsage {
    fn id(&self) -> &str { "JAVA-QUAL-002" }
    fn name(&self) -> &str { "System.out / System.err Usage" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let system_out_patterns = [
            (r#"System\.out\.print(?:ln)?\s*\("#, "System.out.println"),
            (r#"System\.err\.print(?:ln)?\s*\("#, "System.err.println"),
            (r#"System\.out\.printf\s*\("#, "System.out.printf"),
            (r#"System\.err\.printf\s*\("#, "System.err.printf"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;

            for (pattern, name) in &system_out_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, line_num);

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line.trim().to_string(),
                            problem: format!(
                                "{} found. System.out/System.err should not be used in production. \
                                Output goes to stdout/stderr with no structure, no levels, no file rotation.",
                                name
                            ),
                            fix_hint: "Use a proper logging framework: \
                                Logger logger = Logger.getLogger(ClassName.class); \
                                logger.info(\"message\"); // or logger.debug(), logger.warn(), logger.error()".to_string(),
                            auto_fix_available: true,
                        });
                    }
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

        // Comment out System.out/err
        let commented = format!("{}// FIXME: [JAVA-QUAL-002] Use logger instead: {}", indent, trimmed);
        Some(LangFix {
            rule_id: self.id().to_string(),
            original: line_text,
            replacement: commented,
            start_byte: finding.start_byte,
            end_byte: finding.end_byte,
            description: "Replace System.out with logger".to_string(),
        })
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-QUAL-003: Deep Nesting
// Severity: medium
// AI generates deeply nested code blocks
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaDeepNesting;

impl LangRule for JavaDeepNesting {
    fn id(&self) -> &str { "JAVA-QUAL-003" }
    fn name(&self) -> &str { "Deep Nesting" }
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
                        "Deep nesting detected at depth {} (line {}). \
                        AI-generated code often has deeply nested if/else/for blocks. \
                        Nesting depth > 4 reduces readability and maintainability.",
                        dn.depth, dn.line
                    ),
                    fix_hint: "Refactor using early returns, extract methods, or use design patterns. \
                        Consider: Guard clauses (check conditions early and return). \
                        Extract nested logic into helper methods with descriptive names. \
                        Use polymorphism or strategy pattern for complex conditional logic.".to_string(),
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
// JAVA-QUAL-004: Switch Without Default
// Severity: low
// AI generates switch statements without default case
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaSwitchWithoutDefault;

impl LangRule for JavaSwitchWithoutDefault {
    fn id(&self) -> &str { "JAVA-QUAL-004" }
    fn name(&self) -> &str { "Switch Statement Without Default Case" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect switch statements using regex
        let switch_pattern = Regex::new(r"(?m)^\s*switch\s*\([^)]+\)\s*\{").unwrap();
        let default_pattern = Regex::new(r"(?m)^\s*default\s*:").unwrap();

        let mut switch_lines: Vec<usize> = vec![];
        let mut default_lines: Vec<usize> = vec![];

        for (line_idx, line) in code.lines().enumerate() {
            if switch_pattern.is_match(line) {
                switch_lines.push(line_idx + 1);
            }
            if default_pattern.is_match(line) {
                default_lines.push(line_idx + 1);
            }
        }

        // Match switches with their defaults
        for &switch_line in &switch_lines {
            // Check if there's a default within reasonable distance
            let has_default = default_lines.iter()
                .any(|&dl| dl > switch_line && dl - switch_line < 100);

            if !has_default {
                let (start, end) = get_line_offsets(code, switch_line);
                let line_text = get_line_text(code, switch_line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: switch_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: "Switch statement without default case detected. \
                        Unhandled cases may indicate bugs or future compatibility issues.".to_string(),
                    fix_hint: "Add a default case to handle unexpected values: \
                        default: throw new IllegalStateException(\"Unexpected value: \" + value); \
                        Or: default: break; // no action for unexpected values".to_string(),
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
// JAVA-QUAL-005: Raw Type Collection
// Severity: low
// AI uses raw types like List instead of List<String>
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaRawTypeCollection;

impl LangRule for JavaRawTypeCollection {
    fn id(&self) -> &str { "JAVA-QUAL-005" }
    fn name(&self) -> &str { "Raw Type Collection Usage" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let _raw_type_pattern = Regex::new(
            r"(?m)^\s*(?:private|public|protected)?\s*(?:final)?\s*(?:static)?\s*(List|Map|Set|Queue|ArrayList|HashMap|HashSet|TreeMap|TreeSet|LinkedList|Vector)\s+(\w+)\s*="
        ).unwrap();

        let parameterized_types: HashSet<&str> = [
            "List", "Map", "Set", "Queue", "ArrayList", "HashMap",
            "HashSet", "TreeMap", "TreeSet", "LinkedList", "Vector",
            "Collection", "Iterable",
        ].into_iter().collect();

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;

            // Check for raw type declarations
            if let Ok(re) = Regex::new(
                r"(?m)(?:private|public|protected)?\s*(?:final)?\s*(?:static)?\s*(List|Map|Set|Queue|ArrayList|HashMap|HashSet|TreeMap|TreeSet|LinkedList|Vector)<"
            ) {
                // This pattern might be parameterized, check if it ends without >
                if line.contains("= new ") && !line.contains("<>") {
                    if let Some(caps) = re.captures(line) {
                        let type_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                        if parameterized_types.contains(type_name) && !line.contains("<") {
                            let (start, end) = get_line_offsets(code, line_num);

                            findings.push(LangFinding {
                                rule_id: self.id().to_string(),
                                severity: self.severity().to_string(),
                                line: line_num,
                                column: 0,
                                start_byte: start,
                                end_byte: end,
                                snippet: line.trim().to_string(),
                                problem: format!(
                                    "Raw type collection '{}' detected. Use generics for type safety.",
                                    type_name
                                ),
                                fix_hint: "Specify the generic type: List<String>, Map<String, Integer>, etc. \
                                    This provides compile-time type checking and prevents ClassCastException.".to_string(),
                                auto_fix_available: false,
                            });
                        }
                    }
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
// JAVA-QUAL-006: Long Method
// Severity: info
// AI generates very long methods that are hard to read
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaLongMethod;

impl LangRule for JavaLongMethod {
    fn id(&self) -> &str { "JAVA-QUAL-006" }
    fn name(&self) -> &str { "Long Method (Too Many Lines)" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check method length from LnAst
        const MAX_METHOD_LINES: usize = 50;

        for func in &tree.functions {
            let method_length = func.end_line.saturating_sub(func.start_line);

            if method_length > MAX_METHOD_LINES {
                let (start, end) = get_line_offsets(code, func.start_line);
                let line_text = get_line_text(code, func.start_line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: func.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!(
                        "Long method '{}' detected ({} lines). Methods over {} lines \
                        are hard to read, test, and maintain. AI-generated code often has \
                        overly long methods that should be refactored.",
                        func.name, method_length, MAX_METHOD_LINES
                    ),
                    fix_hint: "Extract logical sections into separate private methods. \
                        Each method should do one thing well. Consider: \
                        - Extract validation logic into validateInput() \
                        - Extract business rules into processData() \
                        - Extract formatting into formatOutput()".to_string(),
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
// Registry function
// ─────────────────────────────────────────────────────────────────────────────

/// All Java quality rules.
pub fn java_quality_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(JavaEmptyCatchBlock),
        Box::new(JavaSystemOutUsage),
        Box::new(JavaDeepNesting),
        Box::new(JavaSwitchWithoutDefault),
        Box::new(JavaRawTypeCollection),
        Box::new(JavaLongMethod),
    ]
}
