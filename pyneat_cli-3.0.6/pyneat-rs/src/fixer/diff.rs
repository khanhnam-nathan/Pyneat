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

/// Generate a unified diff string.
///
/// # Arguments
/// * `filename` - The name of the file being diffed
/// * `original` - The original source code
/// * `modified` - The modified source code
/// * `_context` - Number of context lines to include (default: 3) (unused for now)
///
/// # Returns
/// A unified diff string
pub fn generate_diff(filename: &str, original: &str, modified: &str, _context: usize) -> String {
    // Quick check - if they're the same, return empty
    if original == modified {
        return String::new();
    }

    let original_lines: Vec<&str> = original.lines().collect();
    let modified_lines: Vec<&str> = modified.lines().collect();

    let mut diff_lines = Vec::new();

    // Header
    diff_lines.push(format!("--- {}", filename));
    diff_lines.push(format!("+++ {}", filename));

    // Simple diff: show lines that differ
    let max_lines = original_lines.len().max(modified_lines.len());

    for i in 0..max_lines {
        let old_line = original_lines.get(i);
        let new_line = modified_lines.get(i);

        match (old_line, new_line) {
            (Some(old), Some(new)) if old == new => {
                diff_lines.push(format!(" {}", old));
            }
            (Some(old), Some(new)) => {
                diff_lines.push(format!("-{}", old));
                diff_lines.push(format!("+{}", new));
            }
            (Some(old), None) => {
                diff_lines.push(format!("-{}", old));
            }
            (None, Some(new)) => {
                diff_lines.push(format!("+{}", new));
            }
            _ => {}
        }
    }

    diff_lines.join("\n")
}

/// Format findings as a report.
pub fn format_findings_report(findings: &[crate::rules::base::Finding]) -> String {
    let mut report = String::new();
    report.push_str("Security Findings Report\n");
    report.push_str("========================\n\n");

    // Group by severity
    let mut critical = Vec::new();
    let mut high = Vec::new();
    let mut medium = Vec::new();
    let mut low = Vec::new();
    let mut info = Vec::new();

    for finding in findings {
        match finding.severity.as_str() {
            "critical" => critical.push(finding),
            "high" => high.push(finding),
            "medium" => medium.push(finding),
            "low" => low.push(finding),
            _ => info.push(finding),
        }
    }

    let mut total = 0;

    if !critical.is_empty() {
        report.push_str(&format!("CRITICAL ({}):\n", critical.len()));
        total += critical.len();
        for f in &critical {
            report.push_str(&format!("  [{}] {}\n", f.rule_id, f.problem));
            report.push_str(&format!("    Location: bytes {}-{}\n", f.start, f.end));
            report.push_str(&format!("    Fix: {}\n", f.fix_hint));
        }
        report.push('\n');
    }

    if !high.is_empty() {
        report.push_str(&format!("HIGH ({}):\n", high.len()));
        total += high.len();
        for f in &high {
            report.push_str(&format!("  [{}] {}\n", f.rule_id, f.problem));
        }
        report.push('\n');
    }

    if !medium.is_empty() {
        report.push_str(&format!("MEDIUM ({}):\n", medium.len()));
        total += medium.len();
        for f in &medium {
            report.push_str(&format!("  [{}] {}\n", f.rule_id, f.problem));
        }
        report.push('\n');
    }

    if !low.is_empty() {
        report.push_str(&format!("LOW ({}):\n", low.len()));
        total += low.len();
    }

    if !info.is_empty() {
        report.push_str(&format!("INFO ({}):\n", info.len()));
        total += info.len();
    }

    report.push_str(&format!("\nTotal: {} findings\n", total));

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_diff() {
        let original = "line 1\nline 2\nline 3";
        let modified = "line 1\nmodified\nline 3";

        let diff = generate_diff("test.py", original, modified, 3);
        assert!(diff.contains("--- test.py"));
        assert!(diff.contains("+++ test.py"));
    }

    #[test]
    fn test_no_changes() {
        let code = "line 1\nline 2";
        let diff = generate_diff("test.py", code, code, 3);
        assert!(diff.is_empty());
    }
}
