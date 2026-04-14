//! PyNeat Rust SARIF 2.1.0 Export Module
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

pub mod writer;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub use writer::SarifBuilder;

// --------------------------------------------------------------------------
// SARIF Data Structures
// --------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    pub version: String,
    #[serde(rename = "$schema")]
    pub schema: String,
    pub runs: Vec<SarifRun>,
}

impl SarifReport {
    pub fn new() -> Self {
        Self {
            version: "2.1.0".to_string(),
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            runs: vec![],
        }
    }

    pub fn add_run(&mut self, run: SarifRun) {
        self.runs.push(run);
    }

    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| {
            serde_json::json!({
                "version": "2.1.0",
                "runs": []
            })
        })
    }
}

impl Default for SarifReport {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
    pub properties: Option<HashMap<String, Value>>,
}

impl SarifRun {
    pub fn new(tool: SarifTool) -> Self {
        Self {
            tool,
            results: vec![],
            properties: None,
        }
    }

    pub fn add_result(&mut self, result: SarifResult) {
        self.results.push(result);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

impl SarifTool {
    pub fn new(name: &str, version: &str, information_uri: &str, rules: Vec<SarifRule>) -> Self {
        Self {
            driver: SarifDriver {
                name: name.to_string(),
                version: version.to_string(),
                information_uri: Some(information_uri.to_string()),
                rules,
                ..Default::default()
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: Option<String>,
    pub rules: Vec<SarifRule>,
    #[serde(rename = "supportedTaxonomies")]
    pub supported_taxonomies: Option<Vec<SarifTaxonomy>>,
    #[serde(rename = "organization")]
    pub organization: Option<String>,
    #[serde(rename = "product")]
    pub product: Option<String>,
}

impl SarifDriver {
    pub fn new(name: &str, version: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: Option<String>,
    #[serde(rename = "shortDescription")]
    pub short_description: Option<SarifMessage>,
    #[serde(rename = "fullDescription")]
    pub full_description: Option<SarifMessage>,
    pub help: Option<SarifMessage>,
    pub properties: Option<SarifRuleProperties>,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: Option<SarifRuleConfiguration>,
}

impl SarifRule {
    pub fn new(
        id: &str,
        name: &str,
        short_description: &str,
        full_description: &str,
        help: Option<&str>,
        severity: &str,
        cwe_id: Option<&str>,
        owasp_ids: Option<Vec<&str>>,
    ) -> Self {
        let sarif_level = severity_to_sarif_level(severity);

        let tags: Vec<String> = {
            let mut t = Vec::new();
            if let Some(cwe) = cwe_id {
                t.push(format!("CWE-{}", cwe.trim_start_matches("CWE-")));
            }
            if let Some(owasp) = owasp_ids {
                t.extend(owasp.iter().map(|s| s.to_string()));
            }
            t
        };

        Self {
            id: id.to_string(),
            name: Some(name.to_string()),
            short_description: Some(SarifMessage {
                text: short_description.to_string(),
            }),
            full_description: Some(SarifMessage {
                text: full_description.to_string(),
            }),
            help: help.map(|h| SarifMessage { text: h.to_string() }),
            properties: Some(SarifRuleProperties {
                tags,
                precision: Some("very-high".to_string()),
                security_severity: Some(severity_to_cvss(severity).to_string()),
                ..Default::default()
            }),
            default_configuration: Some(SarifRuleConfiguration {
                enabled: true,
                level: sarif_level,
                rank: Some(-1.0),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SarifRuleProperties {
    #[serde(rename = "tags")]
    pub tags: Vec<String>,
    #[serde(rename = "precision")]
    pub precision: Option<String>,
    #[serde(rename = "security-severity")]
    pub security_severity: Option<String>,
    #[serde(rename = "problem.severity")]
    pub problem_severity: Option<String>,
    #[serde(rename = "custom-properties")]
    pub custom_properties: Option<HashMap<String, Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SarifRuleConfiguration {
    pub enabled: bool,
    pub level: String,
    pub rank: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleIndex")]
    pub rule_index: Option<usize>,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    pub fix: Option<SarifFix>,
    #[serde(rename = "codeFlows")]
    pub code_flows: Option<Vec<SarifCodeFlow>>,
    pub properties: Option<SarifResultProperties>,
    #[serde(rename = "suppressions")]
    pub suppressions: Option<Vec<SarifSuppression>>,
    #[serde(rename = "baselineState")]
    pub baseline_state: Option<String>,
    #[serde(rename = "evaluationTime")]
    pub evaluation_time: Option<f64>,
    #[serde(rename = "partial_fingerprints")]
    pub partial_fingerprints: Option<HashMap<String, String>>,
}

impl SarifResult {
    pub fn new(
        rule_id: &str,
        severity: &str,
        message: &str,
        locations: Vec<SarifLocation>,
    ) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            rule_index: None,
            level: severity_to_sarif_level(severity),
            message: SarifMessage {
                text: message.to_string(),
            },
            locations,
            fix: None,
            code_flows: None,
            properties: None,
            suppressions: None,
            baseline_state: None,
            evaluation_time: None,
            partial_fingerprints: None,
        }
    }

    pub fn with_rule_index(mut self, index: usize) -> Self {
        self.rule_index = Some(index);
        self
    }

    pub fn with_fix(mut self, fix: SarifFix) -> Self {
        self.fix = Some(fix);
        self
    }

    pub fn with_properties(
        mut self,
        cwe_id: Option<&str>,
        owasp_ids: Option<Vec<&str>>,
        cvss_score: Option<f32>,
        snippet: Option<&str>,
        fix_hint: Option<&str>,
    ) -> Self {
        let mut tags: Vec<String> = Vec::new();
        if let Some(cwe) = cwe_id {
            tags.push(format!("CWE-{}", cwe.trim_start_matches("CWE-")));
        }
        if let Some(owasp) = owasp_ids {
            tags.extend(owasp.into_iter().map(|s| s.to_string()));
        }

        self.properties = Some(SarifResultProperties {
            tags,
            cvss: cvss_score.map(|s| format!("{}", s)),
            snippet: snippet.map(|s| s.to_string()),
            fix_hint: fix_hint.map(|s| s.to_string()),
            ..Default::default()
        });
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

impl SarifLocation {
    pub fn new(uri: &str, start_line: usize, start_column: usize, end_line: usize, end_column: usize) -> Self {
        Self {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: uri.to_string(),
                    uri_base_id: None,
                    index: None,
                },
                region: SarifRegion {
                    start_line,
                    start_column: Some(start_column),
                    end_line: Some(end_line),
                    end_column: Some(end_column),
                    char_offset: None,
                    char_length: None,
                    snippet: None,
                    message: None,
                },
                context_region: None,
            },
        }
    }

    pub fn with_snippet(mut self, snippet: &str) -> Self {
        self.physical_location.region.snippet = Some(SarifArtifactContent {
            text: Some(snippet.to_string()),
            binary: None,
        });
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
    #[serde(rename = "contextRegion")]
    pub context_region: Option<SarifRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(rename = "uriBaseId")]
    pub uri_base_id: Option<String>,
    pub index: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
    #[serde(rename = "startColumn")]
    pub start_column: Option<usize>,
    #[serde(rename = "endLine")]
    pub end_line: Option<usize>,
    #[serde(rename = "endColumn")]
    pub end_column: Option<usize>,
    #[serde(rename = "charOffset")]
    pub char_offset: Option<usize>,
    #[serde(rename = "charLength")]
    pub char_length: Option<usize>,
    pub snippet: Option<SarifArtifactContent>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactContent {
    pub text: Option<String>,
    pub binary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifFix {
    pub description: SarifMessage,
    #[serde(rename = "artifactChanges")]
    pub artifact_changes: Vec<SarifArtifactChange>,
}

impl SarifFix {
    pub fn new(description: &str, uri: &str, replacements: Vec<SarifReplacement>) -> Self {
        Self {
            description: SarifMessage {
                text: description.to_string(),
            },
            artifact_changes: vec![SarifArtifactChange {
                artifact_location: SarifArtifactLocation {
                    uri: uri.to_string(),
                    uri_base_id: None,
                    index: None,
                },
                replacements,
            }],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactChange {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub replacements: Vec<SarifReplacement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReplacement {
    #[serde(rename = "delete_region")]
    pub delete_region: SarifRegion,
    #[serde(rename = "inserted_content")]
    pub inserted_content: SarifArtifactContent,
}

impl SarifReplacement {
    pub fn new(start_line: usize, start_column: usize, end_line: usize, end_column: usize, text: &str) -> Self {
        Self {
            delete_region: SarifRegion {
                start_line,
                start_column: Some(start_column),
                end_line: Some(end_line),
                end_column: Some(end_column),
                char_offset: None,
                char_length: None,
                snippet: None,
                message: None,
            },
            inserted_content: SarifArtifactContent {
                text: Some(text.to_string()),
                binary: None,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifCodeFlow {
    pub thread_flows: Vec<SarifThreadFlow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifThreadFlow {
    pub locations: Vec<SarifThreadFlowLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifThreadFlowLocation {
    pub location: SarifLocation,
    #[serde(rename = "kinds")]
    pub kinds: Option<Vec<String>>,
    #[serde(rename = "state")]
    pub state: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SarifResultProperties {
    #[serde(rename = "tags")]
    pub tags: Vec<String>,
    #[serde(rename = "cvss")]
    pub cvss: Option<String>,
    #[serde(rename = "snippet")]
    pub snippet: Option<String>,
    #[serde(rename = "fix-hint")]
    pub fix_hint: Option<String>,
    #[serde(rename = "custom-properties")]
    pub custom_properties: Option<HashMap<String, Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifSuppression {
    pub kind: String,
    #[serde(rename = "status")]
    pub status: Option<String>,
    #[serde(rename = "justification")]
    pub justification: Option<String>,
    #[serde(rename = "locations")]
    pub locations: Option<Vec<SarifLocation>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTaxonomy {
    pub name: String,
    pub version: Option<String>,
    #[serde(rename = "informationUri")]
    pub information_uri: Option<String>,
    #[serde(rename = "downloadUri")]
    pub download_uri: Option<String>,
}

// --------------------------------------------------------------------------
// Helper Functions
// --------------------------------------------------------------------------

/// Convert pyneat severity to SARIF level.
pub fn severity_to_sarif_level(severity: &str) -> String {
    match severity {
        "critical" | "high" => "error".to_string(),
        "medium" => "warning".to_string(),
        "low" | "info" => "note".to_string(),
        _ => "warning".to_string(),
    }
}

/// Convert pyneat severity to CVSS score string.
pub fn severity_to_cvss(severity: &str) -> &'static str {
    match severity {
        "critical" => "9.8",
        "high" => "7.8",
        "medium" => "5.0",
        "low" => "2.0",
        "info" => "0.0",
        _ => "5.0",
    }
}

/// Convert byte offset to line/column.
pub fn byte_offset_to_line_column(code: &str, byte_offset: usize) -> (usize, usize) {
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

/// Calculate byte offset from line/column.
pub fn line_column_to_byte_offset(code: &str, target_line: usize, target_column: usize) -> usize {
    let mut current_line = 1;
    let mut current_column = 1;
    let mut byte_offset = 0;

    for c in code.chars() {
        if current_line == target_line && current_column == target_column {
            break;
        }
        if c == '\n' {
            current_line += 1;
            current_column = 1;
        } else {
            current_column += 1;
        }
        byte_offset += c.len_utf8();
    }

    byte_offset
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_to_sarif_level() {
        assert_eq!(severity_to_sarif_level("critical"), "error");
        assert_eq!(severity_to_sarif_level("high"), "error");
        assert_eq!(severity_to_sarif_level("medium"), "warning");
        assert_eq!(severity_to_sarif_level("low"), "note");
        assert_eq!(severity_to_sarif_level("info"), "note");
    }

    #[test]
    fn test_byte_offset_to_line_column() {
        let code = "line 1\nline 2\nline 3";
        assert_eq!(byte_offset_to_line_column(code, 0), (1, 1));
        assert_eq!(byte_offset_to_line_column(code, 7), (2, 1));
        assert_eq!(byte_offset_to_line_column(code, 14), (3, 1));
    }

    #[test]
    fn test_sarif_report() {
        let mut report = SarifReport::new();
        let tool = SarifTool::new("PyNEAT", "3.0.0", "https://github.com/pyneat/pyneat", vec![]);
        let mut run = SarifRun::new(tool);

        let location = SarifLocation::new("test.py", 10, 1, 10, 20);
        let result = SarifResult::new("SEC-001", "high", "Hardcoded password detected", vec![location]);

        run.add_result(result);
        report.add_run(run);

        let json = report.to_json();
        assert_eq!(json["version"], "2.1.0");
        assert_eq!(json["runs"][0]["tool"]["driver"]["name"], "PyNEAT");
    }
}
