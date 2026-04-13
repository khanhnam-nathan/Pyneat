//! Java-specific rules.

use std::collections::HashSet;

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LangRule, LangFinding, LangFix};

/// Helper functions for Java-specific operations
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

/// Detect System.out.println and System.err.println.
pub struct JavaSystemOut;

impl LangRule for JavaSystemOut {
    fn id(&self) -> &str {
        "JAVA-001"
    }

    fn name(&self) -> &str {
        "System Out/Err Statement"
    }

    fn severity(&self) -> &'static str {
        "info"
    }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let system_funcs: HashSet<&str> = [
            "System.out.println", "System.out.print", "System.out.printf",
            "System.err.println", "System.err.print", "System.err.printf",
        ].into_iter().collect();

        let mut findings = vec![];

        for call in &tree.calls {
            if system_funcs.contains(call.callee.as_str()) {
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
                        "System output '{}' found. Remove or replace with proper logging.",
                        call.callee
                    ),
                    fix_hint: "Use a proper logging library (e.g., SLF4J, Log4j) for production.".to_string(),
                    auto_fix_available: true,
                });
            }
        }

        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = code.lines().nth(finding.line - 1)?;

        // Comment out the System.out/err statement
        let indented = line_text.trim_start();
        let indent_len = line_text.len() - indented.len();
        let indent = &line_text[..indent_len];

        let commented = format!("{}// {} // FIXME: use logger instead", indent, indented);

        Some(LangFix {
            rule_id: self.id().to_string(),
            original: line_text.to_string(),
            replacement: commented,
            start_byte: finding.start_byte,
            end_byte: finding.end_byte,
            description: "Comment out system output".to_string(),
        })
    }

    fn supports_auto_fix(&self) -> bool {
        true
    }
}

/// Detect TODO/FIXME comments.
pub struct JavaTodoComments;

impl LangRule for JavaTodoComments {
    fn id(&self) -> &str {
        "JAVA-002"
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
                problem: format!("Unresolved {} marker: {}", todo.marker, todo.description),
                fix_hint: "Address the TODO or provide a timeline for resolution.".to_string(),
                auto_fix_available: false,
            });
        }

        findings
    }
}

pub fn java_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(JavaSystemOut),
        Box::new(JavaTodoComments),
    ]
}
