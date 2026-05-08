//! SARIF Writer - High-level API for generating SARIF reports
//!
//! Copyright (C) 2026 PyNEAT Authors

use super::{SarifReport, SarifRun, SarifTool, SarifRule, SarifResult, SarifLocation};
use crate::rules::base::Finding;
use crate::scanner::base::LangFinding;
use std::collections::HashMap;

/// High-level SARIF report builder.
pub struct SarifBuilder {
    tool_name: String,
    tool_version: String,
    tool_uri: String,
    rules: Vec<SarifRule>,
    results: Vec<SarifResult>,
    rule_index_map: HashMap<String, usize>,
}

impl SarifBuilder {
    pub fn new(tool_name: &str, tool_version: &str, tool_uri: &str) -> Self {
        Self {
            tool_name: tool_name.to_string(),
            tool_version: tool_version.to_string(),
            tool_uri: tool_uri.to_string(),
            rules: Vec::new(),
            results: Vec::new(),
            rule_index_map: HashMap::new(),
        }
    }

    /// Add a rule to the SARIF report.
    pub fn add_rule(
        mut self,
        rule_id: &str,
        name: &str,
        short_description: &str,
        full_description: &str,
        severity: &str,
        cwe_id: Option<&str>,
        owasp_ids: Option<Vec<&str>>,
    ) -> Self {
        let rule = SarifRule::new(
            rule_id,
            name,
            short_description,
            full_description,
            None,
            severity,
            cwe_id,
            owasp_ids,
        );
        let index = self.rules.len();
        self.rule_index_map.insert(rule_id.to_string(), index);
        self.rules.push(rule);
        self
    }

    /// Add a Python Finding as a SARIF result.
    pub fn add_python_finding(
        mut self,
        finding: &Finding,
        source_file: &str,
        source_code: &str,
    ) -> Self {
        let (start_line, start_col) = byte_offset_to_line_column(source_code, finding.start);
        let (end_line, end_col) = byte_offset_to_line_column(source_code, finding.end);

        let location = SarifLocation::new(source_file, start_line, start_col, end_line, end_col)
            .with_snippet(&finding.snippet);

        let mut result = SarifResult::new(
            &finding.rule_id,
            &finding.severity,
            &finding.problem,
            vec![location],
        );

        // Set rule index if we have it
        if let Some(&idx) = self.rule_index_map.get(&finding.rule_id) {
            result = result.with_rule_index(idx);
        }

        result = result.with_properties(
            finding.cwe_id.as_deref(),
            finding.owasp_id.as_ref().map(|v| vec![v.as_str()]),
            finding.cvss_score,
            Some(&finding.snippet),
            Some(&finding.fix_hint),
        );

        self.results.push(result);
        self
    }

    /// Add a LangFinding (multi-language finding) as a SARIF result.
    pub fn add_lang_finding(
        mut self,
        finding: &LangFinding,
        source_file: &str,
        source_code: &str,
    ) -> Self {
        let (start_line, start_col) = if finding.start_byte > 0 {
            byte_offset_to_line_column(source_code, finding.start_byte)
        } else {
            (finding.line, finding.column.max(1))
        };

        let (end_line, end_col) = if finding.end_byte > finding.start_byte {
            byte_offset_to_line_column(source_code, finding.end_byte)
        } else {
            (finding.line, start_col.saturating_add(finding.snippet.len()))
        };

        let location = SarifLocation::new(source_file, start_line, start_col, end_line, end_col)
            .with_snippet(&finding.snippet);

        let mut result = SarifResult::new(
            &finding.rule_id,
            &finding.severity,
            &finding.problem,
            vec![location],
        );

        if let Some(&idx) = self.rule_index_map.get(&finding.rule_id) {
            result = result.with_rule_index(idx);
        }

        result = result.with_properties(
            None,
            None,
            None,
            Some(&finding.snippet),
            Some(&finding.fix_hint),
        );

        self.results.push(result);
        self
    }

    /// Build the final SARIF report.
    pub fn build(self) -> SarifReport {
        let mut report = SarifReport::new();

        let tool = SarifTool::new(
            &self.tool_name,
            &self.tool_version,
            &self.tool_uri,
            self.rules,
        );

        let mut run = SarifRun::new(tool);
        run.results = self.results;
        report.add_run(run);

        report
    }

    /// Add a result directly.
    pub fn add_result(mut self, result: SarifResult) -> Self {
        self.results.push(result);
        self
    }
}

/// Convert byte offset to (line, column) in source code.
fn byte_offset_to_line_column(code: &str, byte_offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;
    let mut current_offset = 0;

    for c in code.chars() {
        if current_offset >= byte_offset {
            break;
        }
        if c == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
        current_offset += c.len_utf8();
    }

    (line, column)
}

/// Convenience function to create a SARIF report from findings.
pub fn create_sarif_report(
    tool_name: &str,
    tool_version: &str,
    source_file: &str,
    python_findings: &[Finding],
    lang_findings: &[LangFinding],
    source_code: &str,
) -> SarifReport {
    let mut builder = SarifBuilder::new(tool_name, tool_version, "https://github.com/pyneat/pyneat");

    // Add Python findings
    for finding in python_findings {
        builder = builder.add_python_finding(finding, source_file, source_code);
    }

    // Add multi-language findings
    for finding in lang_findings {
        builder = builder.add_lang_finding(finding, source_file, source_code);
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif_builder_basic() {
        let builder = SarifBuilder::new("PyNEAT", "3.0.0", "https://github.com/pyneat/pyneat");
        let report = builder.build();

        assert_eq!(report.version, "2.1.0");
        assert_eq!(report.runs[0].tool.driver.name, "PyNEAT");
    }

    #[test]
    fn test_byte_offset_conversion() {
        let code = "line 1\nline 2\nline 3";
        assert_eq!(byte_offset_to_line_column(code, 0), (1, 1));
        assert_eq!(byte_offset_to_line_column(code, 6), (1, 7));
    }
}
