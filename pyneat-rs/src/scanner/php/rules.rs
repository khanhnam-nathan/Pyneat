//! PHP-specific rules.

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LangRule, LangFinding, LangFix};

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

pub struct PhpTodoComments;

impl LangRule for PhpTodoComments {
    fn id(&self) -> &str { "PHP-001" }
    fn name(&self) -> &str { "TODO/FIXME Comments" }
    fn severity(&self) -> &'static str { "info" }

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

pub struct PhpEchoVarDump;

impl LangRule for PhpEchoVarDump {
    fn id(&self) -> &str { "PHP-002" }
    fn name(&self) -> &str { "Echo/Var_dump Usage" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for (i, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("echo ") || trimmed.starts_with("var_dump(") || trimmed.starts_with("print_r(") || trimmed.starts_with("var_export(") {
                let (start, end) = get_line_offsets(code, i + 1);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: i + 1,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.to_string(),
                    problem: "Debug output found. Remove before production.".to_string(),
                    fix_hint: "Use a proper logging library or remove debug output.".to_string(),
                    auto_fix_available: true,
                });
            }
        }
        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = code.lines().nth(finding.line - 1)?;
        let indented = line_text.trim_start();
        let indent_len = line_text.len() - indented.len();
        let indent = &line_text[..indent_len];
        let commented = format!("{}// {} // FIXME: removed debug output", indent, indented);
        Some(LangFix {
            rule_id: self.id().to_string(),
            original: line_text.to_string(),
            replacement: commented,
            start_byte: finding.start_byte,
            end_byte: finding.end_byte,
            description: "Comment out debug output".to_string(),
        })
    }

    fn supports_auto_fix(&self) -> bool {
        true
    }
}

pub fn php_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(PhpTodoComments),
        Box::new(PhpEchoVarDump),
    ]
}
