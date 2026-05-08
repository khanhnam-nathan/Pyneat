//! SonarQube Integration
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! Integrates with SonarQube for SAST analysis.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --------------------------------------------------------------------------
// SonarQube Configuration
// --------------------------------------------------------------------------

/// SonarQube configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SonarQubeConfig {
    /// SonarQube server URL.
    pub url: String,
    /// Authentication token.
    pub token: Option<String>,
    /// Project key.
    pub project_key: String,
    /// Branch or PR.
    pub branch: Option<String>,
}

impl SonarQubeConfig {
    pub fn new(url: &str, project_key: &str) -> Self {
        Self {
            url: url.to_string(),
            token: std::env::var("SONAR_TOKEN").ok(),
            project_key: project_key.to_string(),
            branch: std::env::var("SONAR_BRANCH").ok(),
        }
    }

    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }
}

// --------------------------------------------------------------------------
// SonarQube Issue Format
// --------------------------------------------------------------------------

/// SonarQube issue format for external rule engine integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SonarQubeIssue {
    pub engine_id: String,
    pub rule_id: String,
    pub severity: String,
    #[serde(rename = "type")]
    pub issue_type: String,
    pub message: String,
    pub location: SonarQubeLocation,
    #[serde(rename = "secondary_locations")]
    pub secondary_locations: Option<Vec<SonarQubeLocation>>,
    #[serde(rename = "effort_minutes")]
    pub effort_minutes: Option<i64>,
    pub tags: Option<Vec<String>>,
}

impl SonarQubeIssue {
    pub fn new(rule_id: &str, severity: &str, message: &str, file: &str, line: usize) -> Self {
        Self {
            engine_id: "pyneat".to_string(),
            rule_id: rule_id.to_string(),
            severity: severity_to_sonar(severity),
            issue_type: "VULNERABILITY".to_string(),
            message: message.to_string(),
            location: SonarQubeLocation::new(file, line),
            secondary_locations: None,
            effort_minutes: Some(effort_from_severity(severity)),
            tags: None,
        }
    }

    pub fn with_secondary(mut self, locations: Vec<SonarQubeLocation>) -> Self {
        self.secondary_locations = Some(locations);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SonarQubeLocation {
    pub file: String,
    pub line: usize,
    #[serde(rename = "text_range")]
    pub text_range: Option<SonarQubeTextRange>,
    pub message: Option<String>,
}

impl SonarQubeLocation {
    pub fn new(file: &str, line: usize) -> Self {
        Self {
            file: file.to_string(),
            line,
            text_range: None,
            message: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SonarQubeTextRange {
    #[serde(rename = "start_line")]
    pub start_line: usize,
    #[serde(rename = "end_line")]
    pub end_line: usize,
    #[serde(rename = "start_offset")]
    pub start_offset: Option<usize>,
    #[serde(rename = "end_offset")]
    pub end_offset: Option<usize>,
}

/// SonarQube SARIF output for SonarQube Cloud / SonarQube 9.4+.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SonarQubeSARIF {
    pub version: String,
    pub runs: Vec<SonarQubeSARIFRun>,
}

impl SonarQubeSARIF {
    pub fn new() -> Self {
        Self {
            version: "2.1.0".to_string(),
            runs: vec![],
        }
    }
}

impl Default for SonarQubeSARIF {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SonarQubeSARIFRun {
    #[serde(rename = "tool_probe")]
    pub tool_probe: Option<serde_json::Value>,
    pub results: Vec<serde_json::Value>,
    #[serde(rename = "tool")]
    pub tool: serde_json::Value,
}

fn severity_to_sonar(severity: &str) -> String {
    match severity {
        "critical" => "CRITICAL".to_string(),
        "high" => "MAJOR".to_string(),
        "medium" => "MAJOR".to_string(),
        "low" => "MINOR".to_string(),
        "info" => "INFO".to_string(),
        _ => "MAJOR".to_string(),
    }
}

fn effort_from_severity(severity: &str) -> i64 {
    match severity {
        "critical" => 120,
        "high" => 60,
        "medium" => 30,
        "low" => 10,
        "info" => 5,
        _ => 30,
    }
}

// --------------------------------------------------------------------------
// SonarQube Custom Rules XML Export
// --------------------------------------------------------------------------

/// Generate SonarQube custom rules XML for import.
pub fn generate_sonar_rules_xml(rules: &[(String, String, String, String, String)]) -> String {
    let mut xml = String::new();
    xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    xml.push_str("\n<rules>");
    xml.push_str("\n  <!-- Generated by PyNEAT -->\n");

    for (id, name, severity, cwe, description) in rules {
        let sonar_severity = severity_to_sonar(severity);
        xml.push_str("  <rule>\n");
        xml.push_str(&format!("    <key>pyneat:{}</key>\n", id));
        xml.push_str(&format!("    <name>{}</name>\n", escape_xml(name)));
        xml.push_str(&format!("    <severity>{}</severity>\n", sonar_severity));
        xml.push_str("    <type>VULNERABILITY</type>\n");
        xml.push_str("    <tag>pyneat</tag>\n");
        if !cwe.is_empty() {
            xml.push_str(&format!("    <tag>cwe-{}</tag>\n", cwe.replace("CWE-", "")));
        }
        xml.push_str("    <description><![CDATA[");
        xml.push_str(description);
        xml.push_str("]]></description>\n");
        xml.push_str("  </rule>\n");
    }

    xml.push_str("</rules>\n");
    xml
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// --------------------------------------------------------------------------
// SonarQube Web API Client
// --------------------------------------------------------------------------

/// SonarQube API client for submitting issues.
#[derive(Debug, Clone)]
pub struct SonarQubeClient {
    pub config: SonarQubeConfig,
}

impl SonarQubeClient {
    pub fn new(config: SonarQubeConfig) -> Self {
        Self { config }
    }

    /// Create an issue in SonarQube.
    pub async fn create_issue(&self, issue: &SonarQubeIssue) -> Result<String, String> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/issues/search", self.config.url);

        let mut form: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
        form.insert("project", self.config.project_key.clone());
        form.insert("message", issue.message.clone());
        form.insert("line", issue.location.line.to_string());
        form.insert("component", issue.location.file.clone());
        form.insert("severity", issue.severity.clone());

        let mut request = client.post(&url)
            .header("Content-Type", "application/json");

        if let Some(token) = &self.config.token {
            request = request.basic_auth("admin", Some(token));
        }

        let response = request
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(format!("SonarQube API error: {}", body));
        }

        Ok("Issue created".to_string())
    }

    /// Get project quality gates status.
    pub async fn get_quality_gate_status(&self) -> Result<QualityGateStatus, String> {
        let client = reqwest::Client::new();
        let url = format!(
            "{}/api/qualitygates/project_status?project={}",
            self.config.url, self.config.project_key
        );

        let mut request = client.get(&url);

        if let Some(token) = &self.config.token {
            request = request.basic_auth("admin", Some(token));
        }

        let response = request.send().await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("SonarQube API error: {}", response.status()));
        }

        let status: QualityGateStatus = response.json().await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        Ok(status)
    }
}

/// Quality gate status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityGateStatus {
    pub project_status: ProjectStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectStatus {
    pub status: String,
    #[serde(rename = "gateStatus")]
    pub gate_status: Option<String>,
    #[serde(rename = "conditions")]
    pub conditions: Option<Vec<Condition>>,
    #[serde(rename = "ignoredConditions")]
    pub ignored_conditions: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub status: String,
    pub metric_key: String,
    #[serde(rename = "comparator")]
    pub comparator: Option<String>,
    #[serde(rename = "error_threshold")]
    pub error_threshold: Option<String>,
    #[serde(rename = "actual_value")]
    pub actual_value: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_conversion() {
        assert_eq!(severity_to_sonar("critical"), "CRITICAL");
        assert_eq!(severity_to_sonar("high"), "MAJOR");
        assert_eq!(severity_to_sonar("low"), "MINOR");
    }

    #[test]
    fn test_effort_calculation() {
        assert_eq!(effort_from_severity("critical"), 120);
        assert_eq!(effort_from_severity("low"), 10);
    }

    #[test]
    fn test_sonar_rules_xml() {
        let rules = vec![
            ("SEC-001".to_string(), "Hardcoded Password".to_string(),
             "high".to_string(), "CWE-259".to_string(),
             "A hardcoded password was detected".to_string()),
        ];
        let xml = generate_sonar_rules_xml(&rules);
        assert!(xml.contains("pyneat:SEC-001"));
        assert!(xml.contains("Hardcoded Password"));
    }
}
