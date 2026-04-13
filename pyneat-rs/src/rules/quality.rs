//! Quality rules for pyneat-rs.
//!
//! Implements code quality rules like unused imports, naming conventions, etc.

use crate::rules::base::{Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

/// Unused Import Rule
pub struct UnusedImportRule;

impl Rule for UnusedImportRule {
    fn id(&self) -> &str {
        "QUAL-001"
    }

    fn name(&self) -> &str {
        "Unused Import"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let findings = Vec::new();

        // Simple heuristic: find imports and check if they appear later in code
        let import_re = regex::Regex::new(r#"^import\s+(\w+)"#).unwrap();
        let from_import_re = regex::Regex::new(r#"^from\s+(\w+)\s+import"#).unwrap();

        for line in code.lines() {
            if let Some(caps) = import_re.captures(line) {
                let module = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if !code.contains(&format!("{}.", module))
                    && !code[code.find(line).unwrap_or(0)..].contains(module)
                {
                    // Check if this is truly unused (simplified)
                }
            }
            if let Some(caps) = from_import_re.captures(line) {
                let module = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if !code.contains(&format!("{}.", module)) {
                    // Check if this is truly unused (simplified)
                }
            }
        }

        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }

    fn enabled_by_default(&self) -> bool {
        false // Not enabled by default
    }
}

/// Debug Code Rule
pub struct DebugCodeRule;

impl Rule for DebugCodeRule {
    fn id(&self) -> &str {
        "QUAL-002"
    }

    fn name(&self) -> &str {
        "Debug Code"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"print\s*\(", "print() statement"),
            (r"pdb\.set_trace\s*\(", "pdb.set_trace()"),
            (r"breakpoint\s*\(", "breakpoint()"),
            (r"import\s+pdb", "pdb import"),
            (r"import\s+debugpy", "debugpy import"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "QUAL-002".to_string(),
                        severity: Severity::Info.as_str().to_string(),
                        cwe_id: None,
                        cvss_score: None,
                        owasp_id: None,
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: format!("Debug code found: {}", desc),
                        fix_hint: "Remove debug code before deploying to production.".to_string(),
                        auto_fix_available: m.as_str().starts_with("print"),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<Fix> {
        let original = &code[finding.start..finding.end];
        if original.starts_with("print(") {
            Some(Fix {
                rule_id: self.id().to_string(),
                description: "Remove print statement".to_string(),
                original: original.to_string(),
                replacement: "# removed: print()".to_string(),
                start: finding.start,
                end: finding.end,
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool {
        true
    }
}

/// Redundant Expression Rule
pub struct RedundantExpressionRule;

impl Rule for RedundantExpressionRule {
    fn id(&self) -> &str {
        "QUAL-003"
    }

    fn name(&self) -> &str {
        "Redundant Expression"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"\w+\s*==\s*True", "== True comparison"),
            (r"\w+\s*is\s*True", "is True comparison"),
            (r"\w+\s*!=\s*False", "!= False comparison"),
            (r"\w+\s*is\s*False", "is False comparison"),
            (r"str\s*\(\s*str\s*\(", "str(str())"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "QUAL-003".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: None,
                        cvss_score: None,
                        owasp_id: None,
                        start: m.start(),
                        end: m.end(),
                        snippet,
                        problem: format!("Redundant expression found: {}", desc),
                        fix_hint: "Simplify the expression. For example, change `x == True` to `x`.".to_string(),
                        auto_fix_available: true,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<Fix> {
        let original = &code[finding.start..finding.end];

        let replacement = original
            .replace(" == True", "")
            .replace(" is True", "")
            .replace(" != False", "")
            .replace(" is False", "")
            .replace("== True", "")
            .replace("is True", "")
            .replace("!= False", "")
            .replace("is False", "");

        if replacement != original {
            Some(Fix {
                rule_id: self.id().to_string(),
                description: "Remove redundant comparison".to_string(),
                original: original.to_string(),
                replacement,
                start: finding.start,
                end: finding.end,
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool {
        true
    }
}

/// Naming Convention Rule (QUAL-004)
pub struct NamingConventionRule;

impl Rule for NamingConventionRule {
    fn id(&self) -> &str { "QUAL-004" }
    fn name(&self) -> &str { "Naming Convention Violation" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"(?m)^class\s+[a-z]"#, "Class name should use PascalCase"),
            (r#"(?m)^def\s+[A-Z]"#, "Function name should use snake_case"),
            (r#"(?m)^[A-Z][A-Z0-9_]*\s*="#, "Variable name should use snake_case"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "QUAL-004".to_string(),
                        severity: Severity::Info.as_str().to_string(),
                        cwe_id: None,
                        cvss_score: None,
                        owasp_id: None,
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Naming convention violation: {}", desc),
                        fix_hint: "Use snake_case for functions/variables, PascalCase for classes.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// Dead Code Rule (QUAL-005)
pub struct DeadCodeRule;

impl Rule for DeadCodeRule {
    fn id(&self) -> &str { "QUAL-005" }
    fn name(&self) -> &str { "Dead Code" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"(?m)^\s*#.*$", "Empty or commented lines"),
            (r"(?m)^def\s+\w+\s*\([^)]*\)\s*:\s*(?:#.*)?$", "Function definition with only pass/return"),
            (r"(?m)^\s*pass\s*$", "Standalone pass statement"),
            (r"(?m)^\s*\.\.\.\s*$", "Ellipsis statement"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "QUAL-005".to_string(),
                        severity: Severity::Info.as_str().to_string(),
                        cwe_id: None,
                        cvss_score: None,
                        owasp_id: None,
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Dead code found: {}", desc),
                        fix_hint: "Remove dead code to improve readability.".to_string(),
                        auto_fix_available: true,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<Fix> {
        let original = &code[finding.start..finding.end];
        if original.trim() == "pass" || original.trim() == "..." {
            Some(Fix {
                rule_id: self.id().to_string(),
                description: "Remove dead code".to_string(),
                original: original.to_string(),
                replacement: String::new(),
                start: finding.start,
                end: finding.end,
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool { true }
}

/// Import Order Rule (QUAL-006)
pub struct ImportOrderRule;

impl Rule for ImportOrderRule {
    fn id(&self) -> &str { "QUAL-006" }
    fn name(&self) -> &str { "Import Order Violation" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let import_pattern = regex::Regex::new(r"(?m)^(from\s+\S+|import\s+\S+)").unwrap();

        let mut prev_import = String::new();
        let mut prev_order = 0;

        for cap in import_pattern.captures_iter(code) {
            let m = cap.get(0).unwrap();
            let import_line = m.as_str();

            let current_order = if import_line.contains(".") {
                3 // Local imports
            } else if import_line.contains("from ") && !import_line.contains("<") {
                2 // Third-party
            } else {
                1 // Standard library
            };

            // Check if order is violated
            if !prev_import.is_empty() && current_order < prev_order {
                findings.push(Finding {
                    rule_id: "QUAL-006".to_string(),
                    severity: Severity::Info.as_str().to_string(),
                    cwe_id: None,
                    cvss_score: None,
                    owasp_id: None,
                    start: m.start(),
                    end: m.end(),
                    snippet: import_line.to_string(),
                    problem: "Import order violation: local imports should come after standard library and third-party".to_string(),
                    fix_hint: "Reorder imports: standard library -> third-party -> local imports".to_string(),
                    auto_fix_available: false,
                });
            }

            prev_import = import_line.to_string();
            prev_order = current_order;
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

/// Comment Quality Rule (QUAL-007)
pub struct CommentQualityRule;

impl Rule for CommentQualityRule {
    fn id(&self) -> &str { "QUAL-007" }
    fn name(&self) -> &str { "Comment Quality" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"(?m)^\s*###+\s*$", "Empty hash comment separator"),
            (r"(?m)^\s*---+\s*$", "Empty dash comment separator"),
            (r"(?m)^\s*#\s*$", "Empty comment"),
            (r"(?i)^\s*#\s*TODO\s*:?\s*$", "TODO without description"),
            (r"(?i)^\s*#\s*FIXME\s*:?\s*$", "FIXME without description"),
            (r"(?i)^\s*#\s*HACK\s*:?\s*$", "HACK without description"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "QUAL-007".to_string(),
                        severity: Severity::Info.as_str().to_string(),
                        cwe_id: None,
                        cvss_score: None,
                        owasp_id: None,
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Low-quality comment: {}", desc),
                        fix_hint: "Either remove the comment or add meaningful content.".to_string(),
                        auto_fix_available: true,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, finding: &Finding, code: &str) -> Option<Fix> {
        let original = &code[finding.start..finding.end];
        if original.trim().starts_with("#") && (original.contains("###") || original.contains("---") || original.trim() == "#") {
            Some(Fix {
                rule_id: self.id().to_string(),
                description: "Remove empty comment".to_string(),
                original: original.to_string(),
                replacement: String::new(),
                start: finding.start,
                end: finding.end,
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool { true }
}

/// Get all quality rules.
pub fn all_quality_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(UnusedImportRule),
        Box::new(DebugCodeRule),
        Box::new(RedundantExpressionRule),
        Box::new(NamingConventionRule),
        Box::new(DeadCodeRule),
        Box::new(ImportOrderRule),
        Box::new(CommentQualityRule),
    ]
}

/// Extract a code snippet around the match (1-3 lines).
fn extract_snippet(source: &str, start: usize, end: usize) -> String {
    let line_start = source[..start]
        .rfind('\n')
        .map(|i| i + 1)
        .unwrap_or(0);

    let line_end = source[end..]
        .find('\n')
        .map(|i| end + i)
        .unwrap_or(source.len());

    let context_before = if line_start > 0 {
        source[..line_start - 1]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0)
    } else {
        line_start
    };

    let snippet = &source[context_before..line_end];
    snippet.lines().take(3).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_code() {
        let rule = DebugCodeRule;
        let code = r#"
def foo():
    print("debug")
    breakpoint()
"#;
        let tree = crate::scanner::tree_sitter::parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(findings.len() >= 2);
    }

    #[test]
    fn test_redundant_expression() {
        let rule = RedundantExpressionRule;
        let code = "if x == True:\n    pass";
        let tree = crate::scanner::tree_sitter::parse(code).unwrap();
        let findings = rule.detect(&tree, code);
        assert!(!findings.is_empty());
    }
}
