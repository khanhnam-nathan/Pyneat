//! Ruby language rules.

use crate::scanner::base::LangRule;
use crate::scanner::ln_ast::LnAst;

fn get_line_offsets(code: &str, line: usize) -> (usize, usize) {
    let mut current_line = 1;
    let mut line_start = 0;
    for (i, c) in code.char_indices() {
        if current_line == line {
            line_start = i;
            break;
        }
        if c == '\n' { current_line += 1; }
    }
    let mut line_end = line_start;
    for (i, c) in code[line_start..].char_indices() {
        if c == '\n' { line_end = line_start + i + 1; break; }
    }
    if line_end == line_start { line_end = code.len(); }
    (line_start, line_end)
}

fn get_line_from_byte(code: &str, byte: usize) -> usize {
    code[..byte].matches('\n').count() + 1
}

/// RUBY-TODO-001: Ruby TODO/FIXME comments
pub struct RubyTodoComments;

impl LangRule for RubyTodoComments {
    fn id(&self) -> &str { "RUBY-TODO-001" }
    fn name(&self) -> &str { "Ruby TODO/FIXME Comments" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<crate::scanner::base::LangFinding> {
        let mut findings = vec![];
        for todo in &tree.todos {
            findings.push(crate::scanner::base::LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: todo.start_line,
                column: 0,
                start_byte: 0,
                end_byte: 0,
                snippet: todo.text.clone(),
                problem: format!("TODO/FIXME marker: {} - {}", todo.marker, todo.description),
                fix_hint: "Resolve this TODO item or schedule it.".to_string(),
                auto_fix_available: false,
            });
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-DEBUG-001: Ruby debug output
pub struct RubyDebugOutput;

impl LangRule for RubyDebugOutput {
    fn id(&self) -> &str { "RUBY-DEBUG-001" }
    fn name(&self) -> &str { "Ruby Debug Output" }
    fn severity(&self) -> &'static str { "warning" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<crate::scanner::base::LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"\bputs\s+['"].*debug"##, "debug puts statement"),
            (r##"\bpp\s+"##, "pretty-print debug output"),
            (r##"\bYAML\.debug\s*\("##, "YAML debug output"),
        ];
        for (pat, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(crate::scanner::base::LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Debug output: {} - remove before production.", desc),
                        fix_hint: "Remove or comment out debug output before deploying to production.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-QUAL-001: Ruby console output (puts, print, p)
pub struct RubyConsoleOutput;

impl LangRule for RubyConsoleOutput {
    fn id(&self) -> &str { "RUBY-QUAL-001" }
    fn name(&self) -> &str { "Ruby Console Output" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<crate::scanner::base::LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"\bputs\s+"##, "puts() output - use logger"),
            (r##"\bprint\s+"##, "print() output"),
            (r##"\bp\s+"##, "p() output (debug)"),
            (r##"\bpp\s+"##, "pp() pretty-print output"),
            (r##"\bwarn\s+"##, "warn() output"),
            (r##"\blogger\.debug"##, "logger.debug - remove in production"),
            (r##"\blogger\.info"##, "logger.info - verify production logging"),
        ];
        for (pat, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(crate::scanner::base::LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Console output: {} - use proper logging framework.", desc),
                        fix_hint: "Use Ruby's Logger or a logging gem like Log4r for production.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-QUAL-002: Global variables usage
pub struct RubyGlobalVariables;

impl LangRule for RubyGlobalVariables {
    fn id(&self) -> &str { "RUBY-QUAL-002" }
    fn name(&self) -> &str { "Ruby Global Variables" }
    fn severity(&self) -> &'static str { "warning" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<crate::scanner::base::LangFinding> {
        let mut findings = vec![];
        let global_re = regex::Regex::new(r##"\$[a-zA-Z_][a-zA-Z0-9_]*"##).unwrap();
        for m in global_re.find_iter(code) {
            let line = get_line_from_byte(code, m.start());
            let (start, end) = get_line_offsets(code, line);
            let var_name = m.as_str();
            // Allow certain common globals
            if !["$LOAD_PATH", "$:", "$VERBOSE", "$DEBUG", "$stderr", "$stdout", "$stdin", "$/", "$$", "$?", "$!"].contains(&var_name) {
                findings.push(crate::scanner::base::LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: var_name.to_string(),
                    problem: format!("Global variable {} used - consider class/instance variables instead.", var_name),
                    fix_hint: "Use instance variables (@var) or class variables (@@var) or constants (VAR) instead of global variables.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-QUAL-003: Inefficient string concatenation in loops
pub struct RubyStringConcat;

impl LangRule for RubyStringConcat {
    fn id(&self) -> &str { "RUBY-QUAL-003" }
    fn name(&self) -> &str { "Ruby Inefficient String Concatenation" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<crate::scanner::base::LangFinding> {
        let mut findings = vec![];
        // Detect += on strings inside loops
        let loop_concat_re = regex::Regex::new(r##"(?s)(loop|while|until|times|each).*?\+=.*?end"##).unwrap();
        for m in loop_concat_re.find_iter(code) {
            let line = get_line_from_byte(code, m.start());
            let (start, end) = get_line_offsets(code, line);
            findings.push(crate::scanner::base::LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: m.as_str().lines().next().unwrap_or("").to_string(),
                problem: "String concatenation (+=) inside a loop is inefficient in Ruby.".to_string(),
                fix_hint: "Use string array and join(), or use << (append operator) instead of += for better performance.".to_string(),
                auto_fix_available: false,
            });
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-QUAL-004: Magic numbers
pub struct RubyMagicNumbers;

impl LangRule for RubyMagicNumbers {
    fn id(&self) -> &str { "RUBY-QUAL-004" }
    fn name(&self) -> &str { "Ruby Magic Numbers" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<crate::scanner::base::LangFinding> {
        let mut findings = vec![];
        let magic_re = regex::Regex::new(r##"([0-9]{4,}|0x[0-9a-fA-F]{3,})"##).unwrap();
        for m in magic_re.find_iter(code) {
            let line = get_line_from_byte(code, m.start());
            let (start, end) = get_line_offsets(code, line);
            let num_str = m.as_str();
            // Allow common exemptions
            if !["1000", "3600", "86400", "1024", "4096"].contains(&num_str) {
                findings.push(crate::scanner::base::LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: num_str.to_string(),
                    problem: format!("Magic number {} detected - consider extracting to a named constant.", num_str),
                    fix_hint: "Define a constant with a descriptive name: MAX_RETRIES = 5".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-QUAL-005: Missing safe navigation (consider using &.)
pub struct RubyMissingSafeNav;

impl LangRule for RubyMissingSafeNav {
    fn id(&self) -> &str { "RUBY-QUAL-005" }
    fn name(&self) -> &str { "Ruby Missing Safe Navigation" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<crate::scanner::base::LangFinding> {
        let mut findings = vec![];
        // Detect potential nil-check patterns before method calls
        let nil_check_re = regex::Regex::new(r##"(?i)(if|unless)\s+[^!=]*\.nil\?.*?\n\s*(else|end)"##).unwrap();
        for m in nil_check_re.find_iter(code) {
            let line = get_line_from_byte(code, m.start());
            let (start, end) = get_line_offsets(code, line);
            findings.push(crate::scanner::base::LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: m.as_str().lines().next().unwrap_or("").to_string(),
                problem: "Consider using safe navigation operator (&.) instead of explicit nil checks.".to_string(),
                fix_hint: "Use obj&.method instead of: if obj && obj.method".to_string(),
                auto_fix_available: false,
            });
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-QUAL-006: Missing rescue clause
pub struct RubyMissingRescue;

impl LangRule for RubyMissingRescue {
    fn id(&self) -> &str { "RUBY-QUAL-006" }
    fn name(&self) -> &str { "Ruby Missing Rescue Clause" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<crate::scanner::base::LangFinding> {
        let mut findings = vec![];
        // Detect begin blocks (simplified, no lookahead)
        let begin_re = regex::Regex::new(r##"begin\s+"##).unwrap();
        for m in begin_re.find_iter(code) {
            // Get context to check for rescue
            let start = m.start();
            let end = (start + 200).min(code.len());
            let context = &code[start..end];

            // Only report if no rescue found in context
            if !context.contains("rescue") {
                let line = get_line_from_byte(code, m.start());
                let (byte_start, byte_end) = get_line_offsets(code, line);

                findings.push(crate::scanner::base::LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: byte_start,
                    end_byte: byte_end,
                    snippet: "begin block without rescue".to_string(),
                    problem: "begin block without rescue clause - risky operations may fail silently.".to_string(),
                    fix_hint: "Add rescue clause: begin; ...; rescue StandardError => e; ...; end".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// Get all Ruby language rules.
pub fn ruby_rules() -> Vec<Box<dyn LangRule>> {
    let mut rules: Vec<Box<dyn LangRule>> = vec![
        Box::new(RubyTodoComments),
        Box::new(RubyDebugOutput),
        Box::new(RubyConsoleOutput),
        Box::new(RubyGlobalVariables),
        Box::new(RubyStringConcat),
        Box::new(RubyMagicNumbers),
        Box::new(RubyMissingSafeNav),
        Box::new(RubyMissingRescue),
    ];
    rules.extend(crate::scanner::ruby::security_rules::ruby_security_rules());
    rules
}
