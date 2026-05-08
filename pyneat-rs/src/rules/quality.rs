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

#[allow(dead_code)]

use crate::rules::base::{extract_snippet, Fix, Finding, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;
use tree_sitter::Tree;

static IMPORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^import\s+(\w+)"#).unwrap());
static FROM_IMPORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^from\s+(\w+)\s+import"#).unwrap());
static IMPORT_ORDER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^(from\s+\S+|import\s+\S+)").unwrap());

static DEBUG_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"print\s*\(", "print() statement"),
    (r"pdb\.set_trace\s*\(", "pdb.set_trace()"),
    (r"breakpoint\s*\(", "breakpoint()"),
    (r"import\s+pdb", "pdb import"),
    (r"import\s+debugpy", "debugpy import"),
]);

static REDUNDANT_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"\w+\s*==\s*True", "== True comparison"),
    (r"\w+\s*is\s*True", "is True comparison"),
    (r"\w+\s*!=\s*False", "!= False comparison"),
    (r"\w+\s*is\s*False", "is False comparison"),
    (r"str\s*\(\s*str\s*\(", "str(str())"),
]);

static NAMING_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"(?m)^class\s+[a-z]"#, "Class name should use PascalCase"),
    (r#"(?m)^def\s+[A-Z]"#, "Function name should use snake_case"),
    (r#"(?m)^[A-Z][A-Z0-9_]*\s*="#, "Variable name should use snake_case"),
]);

#[allow(dead_code)]
static DEAD_CODE_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"(?m)^\s*#.*$", "Empty or commented lines"),
    (r"(?m)^def\s+\w+\s*\([^)]*\)\s*:\s*(?:#.*)?$", "Function definition with only pass/return"),
    (r"(?m)^\s*pass\s*$", "Standalone pass statement"),
    (r"(?m)^\s*\.\.\.\s*$", "Ellipsis statement"),
]);

static COMMENT_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"(?m)^\s*###+\s*$", "Empty hash comment separator"),
    (r"(?m)^\s*---+\s*$", "Empty dash comment separator"),
    (r"(?m)^\s*#\s*$", "Empty comment"),
    (r"(?i)^\s*#\s*TODO\s*:?\s*$", "TODO without description"),
    (r"(?i)^\s*#\s*FIXME\s*:?\s*$", "FIXME without description"),
    (r"(?i)^\s*#\s*HACK\s*:?\s*$", "HACK without description"),
]);

/// Unused Import Rule
pub struct UnusedImportRule;

impl Rule for UnusedImportRule {
    fn id(&self) -> &str { "QUAL-001" }
    fn name(&self) -> &str { "Unused Import" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let findings = Vec::new();
        for line in code.lines() {
            if let Some(caps) = IMPORT_RE.captures(line) {
                let module = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if !code.contains(&format!("{}.", module))
                    && !code[code.find(line).unwrap_or(0)..].contains(module)
                {}
            }
            if let Some(caps) = FROM_IMPORT_RE.captures(line) {
                let module = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if !code.contains(&format!("{}.", module)) {}
            }
        }
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }

    fn enabled_by_default(&self) -> bool { false }
}

/// Debug Code Rule
pub struct DebugCodeRule;

impl Rule for DebugCodeRule {
    fn id(&self) -> &str { "QUAL-002" }
    fn name(&self) -> &str { "Debug Code" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (pattern, desc) in DEBUG_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                                replacement: String::new(),
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

    fn supports_auto_fix(&self) -> bool { true }
}

/// Redundant Expression Rule
pub struct RedundantExpressionRule;

impl Rule for RedundantExpressionRule {
    fn id(&self) -> &str { "QUAL-003" }
    fn name(&self) -> &str { "Redundant Expression" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (pattern, desc) in REDUNDANT_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

    fn supports_auto_fix(&self) -> bool { true }
}

/// Naming Convention Rule (QUAL-004)
pub struct NamingConventionRule;

impl Rule for NamingConventionRule {
    fn id(&self) -> &str { "QUAL-004" }
    fn name(&self) -> &str { "Naming Convention Violation" }
    fn severity(&self) -> Severity { Severity::Info }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (pattern, desc) in NAMING_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, desc) in DEAD_CODE_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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
        let mut prev_import = String::new();
        let mut prev_order = 0;

        for cap in IMPORT_ORDER_RE.captures_iter(code) {
            let m = cap.get(0).unwrap();
            let import_line = m.as_str();

            let current_order = if import_line.contains(".") {
                3
            } else if import_line.contains("from ") && !import_line.contains("<") {
                2
            } else {
                1
            };

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
                        replacement: String::new(),
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

        for (pattern, desc) in COMMENT_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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
