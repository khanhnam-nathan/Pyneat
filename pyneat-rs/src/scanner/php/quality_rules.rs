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
// PHP-QUAL-001: Empty Catch Block
// Severity: info
// AI generates empty catch blocks in PHP
// Auto-fix: comment out empty catch
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpEmptyCatchBlock;

impl LangRule for PhpEmptyCatchBlock {
    fn id(&self) -> &str { "PHP-QUAL-001" }
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
// PHP-QUAL-002: Echo / Var_dump / Print_r Usage
// Severity: info
// AI uses echo/var_dump/print_r for debugging
// Auto-fix: comment out debug statements
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpEchoUsage;

impl LangRule for PhpEchoUsage {
    fn id(&self) -> &str { "PHP-QUAL-002" }
    fn name(&self) -> &str { "Echo / Var_dump / Print_r Usage" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect debug patterns using regex
        let debug_patterns: Vec<(&str, &str)> = vec![
            (r"var_dump\s*\(", "var_dump()"),
            (r"var_export\s*\(", "var_export()"),
            (r"print_r\s*\(", "print_r()"),
            (r#"echo\s+['"][^'"]*['"]\s*;"#, "echo string literal"),
            (r#"print\s+['"][^'"]*['"]\s*;"#, "print string literal"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;

            for (pattern, name) in &debug_patterns {
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
                            fix_hint: "Remove debug statements or use proper logging.".to_string(),
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

        let commented = format!("{}// FIXME: [PHP-QUAL-002] Remove debug output: {}", indent, trimmed);
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
// PHP-QUAL-003: Deep Nesting
// Severity: medium
// AI generates deeply nested code
// Auto-fix: not available
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpDeepNesting;

impl LangRule for PhpDeepNesting {
    fn id(&self) -> &str { "PHP-QUAL-003" }
    fn name(&self) -> &str { "Deep Nesting (Anti-pattern)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect deep nesting through regex
        let _deep_nest_pattern = Regex::new(
            r"(?m)^\s*(if|elseif|foreach|while|for|switch)\s*\("
        ).unwrap();

        let nesting_threshold = 4;
        let mut nesting_depth = 0;
        let mut nesting_start_line = 0;

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            // Count opening braces in this line
            let opens = trimmed.matches('{').count();
            let closes = trimmed.matches('}').count();

            nesting_depth = nesting_depth + opens - closes;

            if nesting_depth >= nesting_threshold {
                if nesting_start_line == 0 || opens > 0 {
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
                            "Deeply nested code (depth: {}). Consider extracting inner logic into separate functions.",
                            nesting_depth
                        ),
                        fix_hint: "Extract deeply nested logic into separate functions to improve readability.".to_string(),
                        auto_fix_available: false,
                    });
                    nesting_start_line = line_idx + 1;
                }
            }

            if nesting_depth == 0 {
                nesting_start_line = 0;
            }
        }

        findings.sort_by_key(|f| f.line);
        findings.dedup_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-QUAL-004: Superglobal Usage Without Validation
// Severity: medium
// AI uses $_GET, $_POST, $_REQUEST without proper validation
// Auto-fix: not available
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpSuperglobalUsage;

impl LangRule for PhpSuperglobalUsage {
    fn id(&self) -> &str { "PHP-QUAL-004" }
    fn name(&self) -> &str { "Superglobal Without Validation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let superglobal_pattern = Regex::new(
            r"\$_(GET|POST|REQUEST|SERVER|FILES|COOKIE|SESSION|ENV)"
        ).unwrap();

        let sanitization_functions = [
            "htmlspecialchars", "mysqli_real_escape_string", "pg_escape_string",
            "filter_var", "sanitize_text_field", "addslashes", "strip_tags",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            if superglobal_pattern.is_match(line) {
                // Check if line has any sanitization
                let has_sanitization = sanitization_functions.iter()
                    .any(|f| line.contains(f));

                if !has_sanitization {
                    let (start, end) = get_line_offsets(code, line_idx + 1);

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: line_idx + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.trim().to_string(),
                        problem: "Superglobal used without apparent sanitization.".to_string(),
                        fix_hint: "Always validate and sanitize superglobal input. Use filter_var() or appropriate sanitization functions.".to_string(),
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
// PHP-QUAL-005: Inline HTML in PHP Files
// Severity: low
// AI mixes PHP and HTML inline
// Auto-fix: not available
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpInlineHtml;

impl LangRule for PhpInlineHtml {
    fn id(&self) -> &str { "PHP-QUAL-005" }
    fn name(&self) -> &str { "Inline HTML in PHP" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect inline HTML in PHP (text outside <?php ?> tags)
        let inline_html_pattern = Regex::new(
            r"<[a-zA-Z][^>]*>"
        ).unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            // Skip PHP tags and comments
            if trimmed.starts_with("<?php") || trimmed.starts_with("<?=")
                || trimmed.starts_with("<?") || trimmed.starts_with("//")
                || trimmed.starts_with("/*") || trimmed.starts_with("*")
                || trimmed.is_empty() {
                continue;
            }

            if inline_html_pattern.is_match(line) {
                let (start, end) = get_line_offsets(code, line_idx + 1);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.trim().to_string(),
                    problem: "Inline HTML detected in PHP file.".to_string(),
                    fix_hint: "Consider using a template engine (Twig, Blade) or separating views from logic.".to_string(),
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
// PHP-QUAL-006: Missing Return Type Declarations
// Severity: info
// AI generates functions without return types
// Auto-fix: not available
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpMissingReturnType;

impl LangRule for PhpMissingReturnType {
    fn id(&self) -> &str { "PHP-QUAL-006" }
    fn name(&self) -> &str { "Missing Return Type Declaration" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect function definitions without return types
        let function_pattern = Regex::new(
            r"(?m)^\s*(public|private|protected)?\s*function\s+(\w+)\s*\([^)]*\)\s*(?::\s*\S+\s*)?\{"
        ).unwrap();

        for m in function_pattern.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let match_str = m.as_str();

            // Check if return type is present
            let has_return_type = match_str.contains(':');
            if !has_return_type {
                let (start, end) = get_line_offsets(code, line);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: m.as_str().to_string(),
                    problem: "Function without return type declaration.".to_string(),
                    fix_hint: "Add return type declaration for better type safety: function foo(): void {}".to_string(),
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
// Module exports
// ─────────────────────────────────────────────────────────────────────────────

/// Return all PHP quality rules
pub fn php_quality_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(PhpEmptyCatchBlock),
        Box::new(PhpEchoUsage),
        Box::new(PhpDeepNesting),
        Box::new(PhpSuperglobalUsage),
        Box::new(PhpInlineHtml),
        Box::new(PhpMissingReturnType),
    ]
}
