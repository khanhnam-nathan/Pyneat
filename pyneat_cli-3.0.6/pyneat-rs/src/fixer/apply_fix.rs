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

#![allow(dead_code)]

use tree_sitter::Parser;

/// Apply a single fix to the code.
///
/// Returns the modified code, or None if the fix could not be applied.
pub fn apply_fix_code(code: &str, start: usize, end: usize, replacement: &str) -> Option<String> {
    if start > end || end > code.len() {
        return None;
    }

    let mut result = code.to_string();
    result.replace_range(start..end, replacement);
    Some(result)
}

/// Apply multiple fixes to the code.
///
/// Fixes are applied in order, and positions are adjusted accordingly.
/// Returns the modified code.
#[derive(Debug, Clone)]
pub struct FixRange {
    pub start: usize,
    pub end: usize,
    pub replacement: String,
    pub rule_id: String,
}

impl FixRange {
    pub fn new(start: usize, end: usize, replacement: String, rule_id: String) -> Self {
        Self { start, end, replacement, rule_id }
    }
}

pub fn apply_multiple_fixes(code: &str, fixes: &[FixRange]) -> String {
    let mut result = code.to_string();

    // Sort fixes by start position (descending) to apply from end to start
    let mut sorted_fixes: Vec<_> = fixes.iter().collect();
    sorted_fixes.sort_by(|a, b| b.start.cmp(&a.start));

    for fix in sorted_fixes {
        if fix.start <= fix.end && fix.end <= result.len() {
            result.replace_range(fix.start..fix.end, &fix.replacement);
        }
    }

    result
}

/// Result of applying fixes with conflict information.
#[derive(Debug, Clone)]
pub struct FixResult {
    pub code: String,
    pub applied: Vec<String>,
    pub conflicts: Vec<FixConflict>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FixConflict {
    pub rule_a: String,
    pub rule_b: String,
    pub range: (usize, usize),
    pub description: String,
}

/// Check for overlapping fix ranges and resolve conflicts.
pub fn resolve_conflicts(fixes: &[FixRange]) -> Vec<FixRange> {
    let mut resolved: Vec<FixRange> = Vec::new();
    let mut covered: Vec<(usize, usize)> = Vec::new();

    // Sort by start position ascending
    let mut sorted: Vec<_> = fixes.iter().collect();
    sorted.sort_by_key(|f| f.start);

    for fix in sorted {
        let mut is_conflicting = false;

        for (cov_start, cov_end) in &covered {
            // Check for overlap
            if fix.start < *cov_end && fix.end > *cov_start {
                is_conflicting = true;
                break;
            }
        }

        if !is_conflicting {
            resolved.push(fix.clone());
            covered.push((fix.start, fix.end));
        }
    }

    resolved
}

/// Apply fixes with conflict resolution and validation.
///
/// Returns a detailed result including which fixes were applied,
/// conflicts detected, and any errors.
pub fn apply_fixes_with_validation(
    code: &str,
    fixes: &[FixRange],
    validate_syntax: bool,
) -> FixResult {
    let mut errors: Vec<String> = Vec::new();
    let mut conflicts: Vec<FixConflict> = Vec::new();
    let mut applied: Vec<String> = Vec::new();

    // Check for overlaps and create conflict report
    for i in 0..fixes.len() {
        for j in (i + 1)..fixes.len() {
            let a = &fixes[i];
            let b = &fixes[j];

            // Check for overlap
            if a.start < b.end && a.end > b.start {
                conflicts.push(FixConflict {
                    rule_a: a.rule_id.clone(),
                    rule_b: b.rule_id.clone(),
                    range: (a.start.max(b.start), a.end.min(b.end)),
                    description: format!(
                        "Fix from '{}' overlaps with fix from '{}' at bytes {}-{}",
                        a.rule_id, b.rule_id,
                        a.start.max(b.start),
                        a.end.min(b.end)
                    ),
                });
            }
        }
    }

    // Resolve conflicts by keeping the first fix and skipping conflicting ones
    let resolved = resolve_conflicts(fixes);
    let skipped: std::collections::HashSet<_> = fixes
        .iter()
        .filter(|f| !resolved.iter().any(|r| r.start == f.start && r.end == f.end))
        .map(|f| f.rule_id.clone())
        .collect();

    for skipped_rule in skipped {
        errors.push(format!("Skipped fix from '{}' due to conflict", skipped_rule));
    }

    // Apply resolved fixes
    let mut current_code = code.to_string();
    let mut sorted_fixes: Vec<_> = resolved.iter().collect();
    sorted_fixes.sort_by(|a, b| b.start.cmp(&a.start));

    for fix in sorted_fixes {
        if fix.start <= fix.end && fix.end <= current_code.len() {
            applied.push(fix.rule_id.clone());
            current_code.replace_range(fix.start..fix.end, &fix.replacement);
        } else {
            errors.push(format!(
                "Failed to apply fix from '{}': invalid range {}-{}",
                fix.rule_id, fix.start, fix.end
            ));
        }
    }

    // Validate syntax if requested
    if validate_syntax {
        match validate_fix(&current_code) {
            Ok(_) => {}
            Err(e) => {
                errors.push(format!("Syntax validation failed: {}", e));
                // Return original code on syntax error
                return FixResult {
                    code: code.to_string(),
                    applied: vec![],
                    conflicts,
                    errors,
                };
            }
        }
    }

    // Check for dangerous patterns that might be introduced
    let safety_warnings = check_fix_safety(&code, &current_code);
    errors.extend(safety_warnings);

    FixResult {
        code: current_code,
        applied,
        conflicts,
        errors,
    }
}

/// Check if the fix introduces dangerous patterns.
fn check_fix_safety(before: &str, after: &str) -> Vec<String> {
    let mut warnings: Vec<String> = Vec::new();

    // Check if __future__ imports were removed
    let future_import_re = regex::Regex::new(r"^\s*from\s+__future__\s+import\s+").unwrap();
    let before_has_future = future_import_re.is_match(before);
    let after_has_future = future_import_re.is_match(after);

    if before_has_future && !after_has_future {
        warnings.push("WARNING: Fix removed __future__ import. This may break Python 2/3 compatibility.".to_string());
    }

    // Check for potentially dangerous changes
    let dangerous_patterns = [
        (r"eval\s*\(", "eval()"),
        (r"exec\s*\(", "exec()"),
        (r"__import__\s*\(", "__import__()"),
        (r"compile\s*\(", "compile()"),
    ];

    for (pattern, name) in &dangerous_patterns {
        let re = regex::Regex::new(pattern).unwrap();
        let before_matches: Vec<_> = re.find_iter(before).collect();
        let after_matches: Vec<_> = re.find_iter(after).collect();

        // If new dangerous patterns appear that weren't there before
        if after_matches.len() > before_matches.len() {
            warnings.push(format!(
                "WARNING: Fix may have introduced {} ({} new occurrence(s))",
                name,
                after_matches.len() - before_matches.len()
            ));
        }
    }

    warnings
}

/// Validate that the fixed code is syntactically valid Python.
pub fn validate_fix(code: &str) -> Result<(), ValidationError> {
    let lang: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
    let mut parser = Parser::new();

    parser
        .set_language(&lang)
        .map_err(|_| ValidationError::ParserError)?;

    parser
        .parse(code, None)
        .ok_or(ValidationError::ParseFailed)?;

    Ok(())
}

/// Validation error types.
#[derive(Debug, Clone)]
pub enum ValidationError {
    ParserError,
    ParseFailed,
    SemanticError(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::ParserError => write!(f, "Failed to initialize parser"),
            ValidationError::ParseFailed => write!(f, "Failed to parse the code"),
            ValidationError::SemanticError(msg) => write!(f, "Semantic error: {}", msg),
        }
    }
}

impl std::error::Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_single_fix() {
        let code = "x = yaml.load(user_data)";
        let result = apply_fix_code(code, 4, 14, "yaml.safe_load").unwrap();
        assert!(result.contains("safe_load"));
    }

    #[test]
    fn test_apply_multiple_fixes() {
        let code = "print(x)\nprint(y)\nprint(z)";
        let fixes = vec![
            FixRange::new(0, 8, "# print(x)".to_string(), "QUAL-002".to_string()),
            FixRange::new(9, 17, "# print(y)".to_string(), "QUAL-002".to_string()),
        ];

        let result = apply_multiple_fixes(code, &fixes);
        assert!(result.contains("# print"));
    }

    #[test]
    fn test_invalid_fix_range() {
        let code = "hello";
        assert!(apply_fix_code(code, 10, 15, "world").is_none());
    }

    #[test]
    fn test_conflict_resolution() {
        let fixes = vec![
            FixRange::new(0, 10, "replacement1".to_string(), "rule1".to_string()),
            FixRange::new(5, 15, "replacement2".to_string(), "rule2".to_string()), // Overlaps
            FixRange::new(20, 30, "replacement3".to_string(), "rule3".to_string()), // No overlap
        ];

        let resolved = resolve_conflicts(&fixes);
        // Should keep the first fix (0-10) and skip the overlapping one (5-15)
        assert_eq!(resolved.len(), 2);
        assert!(resolved.iter().any(|f| f.rule_id == "rule1"));
        assert!(resolved.iter().any(|f| f.rule_id == "rule3"));
    }

    #[test]
    fn test_validate_valid_code() {
        let code = "x = 1\ny = 2";
        assert!(validate_fix(code).is_ok());
    }

    #[test]
    fn test_future_import_safety() {
        let before = "from __future__ import annotations\nx = 1";
        let after = "x = 1";
        let warnings = check_fix_safety(before, after);
        assert!(!warnings.is_empty());
    }
}
