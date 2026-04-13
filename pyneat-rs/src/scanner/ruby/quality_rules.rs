//! Ruby-specific quality rules for pyneat-rs.
//!
//! Implements RUBY-QUAL-001 through RUBY-QUAL-006 for code quality issues
//! in AI-generated Ruby code.

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
// RUBY-QUAL-001: Debug Output (puts, p, print)
// Severity: info
// AI uses puts/p/print for debugging
// Auto-fix: comment out debug statements
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyDebugOutput;

impl LangRule for RubyDebugOutput {
    fn id(&self) -> &str { "RUBY-QUAL-001" }
    fn name(&self) -> &str { "Debug Output (puts/p/print)" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let debug_patterns = [
            (r"\bp\s+", "p (inspect)"),
            (r"\bputs\s+", "puts"),
            (r"\bprint\s+", "print"),
            (r"\bpp\s+", "pp (pretty print)"),
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
                            fix_hint: "Remove debug statements or use proper logging (Rails.logger, Logger).".to_string(),
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

        let commented = format!("{}# FIXME: [RUBY-QUAL-001] Remove debug output: {}", indent, trimmed);
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
// RUBY-QUAL-002: Global Variable Usage
// Severity: warning
// AI uses global variables
// Auto-fix: not available
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyGlobalVariables;

impl LangRule for RubyGlobalVariables {
    fn id(&self) -> &str { "RUBY-QUAL-002" }
    fn name(&self) -> &str { "Global Variable Usage" }
    fn severity(&self) -> &'static str { "warning" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let global_pattern = Regex::new(r"\$[a-zA-Z_][a-zA-Z0-9_]*").unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            if global_pattern.is_match(line) {
                let (start, end) = get_line_offsets(code, line_idx + 1);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.trim().to_string(),
                    problem: "Global variable detected. Global variables reduce code maintainability.".to_string(),
                    fix_hint: "Use instance variables (@), class variables (@@), or constants (CONST) instead.".to_string(),
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
// RUBY-QUAL-003: Inefficient String Concatenation
// Severity: info
// AI uses string concatenation instead of interpolation
// Auto-fix: not available
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyStringConcatenation;

impl LangRule for RubyStringConcatenation {
    fn id(&self) -> &str { "RUBY-QUAL-003" }
    fn name(&self) -> &str { "Inefficient String Concatenation" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect string concatenation patterns like: "hello" + variable
        let concat_pattern = Regex::new(r#"["'][^"']*["']\s*\+\s*\w+"#).unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            if concat_pattern.is_match(line) && !line.contains('#') {
                let (start, end) = get_line_offsets(code, line_idx + 1);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.trim().to_string(),
                    problem: "String concatenation detected. Use string interpolation for better performance.".to_string(),
                    fix_hint: "Use string interpolation: \"hello #{variable}\" instead of \"hello \" + variable.".to_string(),
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
// RUBY-QUAL-004: Magic Numbers
// Severity: info
// AI uses magic numbers without constants
// Auto-fix: not available
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyMagicNumbers;

impl LangRule for RubyMagicNumbers {
    fn id(&self) -> &str { "RUBY-QUAL-004" }
    fn name(&self) -> &str { "Magic Numbers" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Common magic numbers that should be constants
        let magic_number_pattern = Regex::new(
            r"[0-9]+(?:\.[0-9]+)?"
        ).unwrap();

        let exempt_numbers: std::collections::HashSet<&str> = [
            "0", "1", "2", "3", "4", "5", "10", "100", "1000", "60", "24", "12", "3600",
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
                    fix_hint: "Define a constant with descriptive name: MAX_RETRIES = 5".to_string(),
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
// RUBY-QUAL-005: Missing Safe Navigation
// Severity: info
// AI uses nil checks with if/unless instead of &.
// Auto-fix: not available
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyMissingSafeNavigation;

impl LangRule for RubyMissingSafeNavigation {
    fn id(&self) -> &str { "RUBY-QUAL-005" }
    fn name(&self) -> &str { "Missing Safe Navigation Operator" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect patterns like: if obj && obj.method
        let nil_check_pattern = Regex::new(
            r"if\s+\w+\s+&&\s+\w+\.|unless\s+\w+\s+&&\s+\w+\."
        ).unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            if nil_check_pattern.is_match(line) {
                let (start, end) = get_line_offsets(code, line_idx + 1);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.trim().to_string(),
                    problem: "Nil check with && detected. Use safe navigation operator (&.) instead.".to_string(),
                    fix_hint: "Replace 'obj && obj.method' with 'obj&.method' for cleaner code.".to_string(),
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
// RUBY-QUAL-006: Empty rescue Block
// Severity: info
// AI generates empty rescue blocks
// Auto-fix: not available
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyEmptyRescue;

impl LangRule for RubyEmptyRescue {
    fn id(&self) -> &str { "RUBY-QUAL-006" }
    fn name(&self) -> &str { "Empty Rescue Block" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect empty rescue blocks
        let _empty_rescue_pattern = Regex::new(
            r"(?m)rescue\s*(?:\[.*?\])?\s*\n\s*end\b"
        ).unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            if line.contains("rescue") && line.trim().ends_with("end") {
                let (start, end) = get_line_offsets(code, line_num);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_num,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.trim().to_string(),
                    problem: "Empty rescue block detected.".to_string(),
                    fix_hint: "Either remove the rescue block or add proper error handling.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        // Also use regex for multi-line rescue
        let rescue_block_pattern = Regex::new(
            r"(?s)rescue.*?\n\s*end"
        ).unwrap();

        for m in rescue_block_pattern.find_iter(code) {
            let rescue_content = m.as_str();
            let lines: Vec<&str> = rescue_content.lines().collect();

            // Check if rescue body is essentially empty (only whitespace/comments)
            let body_lines = &lines[1..lines.len()-1];
            let is_empty = body_lines.iter().all(|l| {
                let trimmed = l.trim();
                trimmed.is_empty() || trimmed.starts_with('#')
            });

            if is_empty && body_lines.len() <= 2 {
                let line = code[..m.start()].matches('\n').count() + 1;
                if !findings.iter().any(|f: &LangFinding| f.line == line) {
                    let (start, end) = get_line_offsets(code, line);

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: format!("rescue block at line {}", line),
                        problem: "Empty rescue block detected.".to_string(),
                        fix_hint: "Add error logging or handling: rescue => e; logger.error(e.message)".to_string(),
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

/// Return all Ruby quality rules
pub fn ruby_quality_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(RubyDebugOutput),
        Box::new(RubyGlobalVariables),
        Box::new(RubyStringConcatenation),
        Box::new(RubyMagicNumbers),
        Box::new(RubyMissingSafeNavigation),
        Box::new(RubyEmptyRescue),
    ]
}
