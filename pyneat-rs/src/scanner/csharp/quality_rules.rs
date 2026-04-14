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
// CSHARP-QUAL-001: Empty Catch Block
// Severity: info
// AI generates empty catch blocks in C#
// Auto-fix: comment out empty catch
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpEmptyCatchBlock;

impl LangRule for CSharpEmptyCatchBlock {
    fn id(&self) -> &str { "CSHARP-QUAL-001" }
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
                    problem: "Empty catch block detected.".to_string(),
                    fix_hint: "Either remove the empty catch block or add proper error handling.".to_string(),
                    auto_fix_available: true,
                });
            }
        }

        // Also detect empty catch using regex
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
                    fix_hint: "Add error handling: catch (Exception e) { _logger.LogError(e); }".to_string(),
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
// CSHARP-QUAL-002: Console.Write / Console.WriteLine Usage
// Severity: info
// AI uses Console.Write for debugging
// Auto-fix: comment out Console statements
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpConsoleUsage;

impl LangRule for CSharpConsoleUsage {
    fn id(&self) -> &str { "CSHARP-QUAL-002" }
    fn name(&self) -> &str { "Console.Write / Console.WriteLine Usage" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let console_patterns = [
            (r"Console\.Write(?:Line)?\s*\(", "Console.Write/WriteLine"),
            (r"Debug\.Write(?:Line)?\s*\(", "Debug.Write/WriteLine"),
            (r"Trace\.Write(?:Line)?\s*\(", "Trace.Write/WriteLine"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;

            for (pattern, name) in &console_patterns {
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
                                "{} found. Debug output should not be left in production code.",
                                name
                            ),
                            fix_hint: "Use proper logging: _logger.LogInformation(), _logger.LogDebug(), etc.".to_string(),
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

        let commented = format!("{}// FIXME: [CSHARP-QUAL-002] Remove debug output: {}", indent, trimmed);
        Some(LangFix {
            rule_id: self.id().to_string(),
            original: line_text,
            replacement: commented,
            start_byte: finding.start_byte,
            end_byte: finding.end_byte,
            description: "Comment out debug output".to_string(),
        })
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-QUAL-003: Deep Nesting
// Severity: medium
// AI generates deeply nested code
// Auto-fix: not available
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpDeepNesting;

impl LangRule for CSharpDeepNesting {
    fn id(&self) -> &str { "CSHARP-QUAL-003" }
    fn name(&self) -> &str { "Deep Nesting (Anti-pattern)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let nesting_threshold = 4;
        let mut nesting_depth = 0;
        let mut reported_lines: std::collections::HashSet<usize> = std::collections::HashSet::new();

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            // Count opening and closing braces
            let opens = trimmed.matches('{').count();
            let closes = trimmed.matches('}').count();

            nesting_depth = nesting_depth + opens - closes;

            if nesting_depth >= nesting_threshold && opens > 0 && !reported_lines.contains(&(line_idx + 1)) {
                let (start, end) = get_line_offsets(code, line_idx + 1);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.trim().to_string(),
                    problem: format!(
                        "Deeply nested code (depth: {}). Consider extracting inner logic into separate methods.",
                        nesting_depth
                    ),
                    fix_hint: "Extract deeply nested logic into separate methods to improve readability.".to_string(),
                    auto_fix_available: false,
                });
                reported_lines.insert(line_idx + 1);
            }

            if nesting_depth == 0 {
                reported_lines.clear();
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-QUAL-004: Nullable Warning Suppression
// Severity: low
// AI disables nullable warnings
// Auto-fix: not available
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpNullableWarning;

impl LangRule for CSharpNullableWarning {
    fn id(&self) -> &str { "CSHARP-QUAL-004" }
    fn name(&self) -> &str { "Nullable Warning Suppression" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let nullable_patterns: Vec<(&str, &str)> = vec![
            (r"#nullable disable", "nullable disable"),
            (r"#pragma\s+warning\s+disable\s+\{CS8600|CS8601|CS8602|CS8603|CS8604\}", "nullable warning disabled"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;

            for (pattern, name) in &nullable_patterns {
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
                                "{} detected. Disabling nullable warnings reduces null-safety.",
                                name
                            ),
                            fix_hint: "Remove the pragma and fix the underlying null-safety issues.".to_string(),
                            auto_fix_available: false,
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
// CSHARP-QUAL-005: Magic Numbers
// Severity: info
// AI uses magic numbers without constants
// Auto-fix: not available
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpMagicNumbers;

impl LangRule for CSharpMagicNumbers {
    fn id(&self) -> &str { "CSHARP-QUAL-005" }
    fn name(&self) -> &str { "Magic Numbers" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let magic_number_pattern = Regex::new(
            r"[0-9]+(?:\.[0-9]+)?"
        ).unwrap();

        let exempt_numbers: std::collections::HashSet<&str> = [
            "0", "1", "2", "3", "4", "5", "10", "100", "1000", "60", "24", "12", "3600",
            "int.MinValue", "int.MaxValue", "long.MaxValue", "long.MinValue",
        ].into_iter().collect();

        for caps in magic_number_pattern.captures_iter(code) {
            let num_str = caps.get(1).map_or("", |m| m.as_str());
            if exempt_numbers.contains(num_str) {
                continue;
            }

            if let Some(m) = caps.get(0) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: format!("Found number: {}", num_str),
                    problem: format!("Magic number '{}' detected. Extract to a named constant.", num_str),
                    fix_hint: "Define a const: private const int MaxRetries = 5;".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSHARP-QUAL-006: TODO/FIXME Comments
// Severity: info
// AI leaves TODO comments in code
// Auto-fix: not available
// ─────────────────────────────────────────────────────────────────────────────
pub struct CSharpTodoComments;

impl LangRule for CSharpTodoComments {
    fn id(&self) -> &str { "CSHARP-QUAL-006" }
    fn name(&self) -> &str { "TODO/FIXME Comments" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        for todo in &tree.todos {
            let (start, end) = get_line_offsets(code, todo.start_line);

            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: todo.start_line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: todo.text.clone(),
                problem: format!("Unresolved {} marker: {}", todo.marker, todo.description),
                fix_hint: "Resolve this TODO item or schedule it.".to_string(),
                auto_fix_available: false,
            });
        }

        // Also detect using regex for comments
        let todo_pattern = Regex::new(r"(?i)(TODO|FIXME|HACK|XXX|BUG):").unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            if todo_pattern.is_match(line) {
                // Skip if already captured by LnAst
                if !findings.iter().any(|f: &LangFinding| f.line == line_idx + 1) {
                    let (start, end) = get_line_offsets(code, line_idx + 1);

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: line_idx + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.trim().to_string(),
                        problem: "TODO/FIXME marker detected.".to_string(),
                        fix_hint: "Resolve this TODO item or schedule it.".to_string(),
                        auto_fix_available: false,
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
// Module exports
// ─────────────────────────────────────────────────────────────────────────────

/// Return all C# quality rules
pub fn csharp_quality_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(CSharpEmptyCatchBlock),
        Box::new(CSharpConsoleUsage),
        Box::new(CSharpDeepNesting),
        Box::new(CSharpNullableWarning),
        Box::new(CSharpMagicNumbers),
        Box::new(CSharpTodoComments),
    ]
}
