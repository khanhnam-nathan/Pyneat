//! GitLab SAST Integration
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! Integrates with GitLab SAST (Static Application Security Testing).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// GitLab CI configuration for SAST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabConfig {
    /// GitLab token for API authentication.
    pub token: Option<String>,
    /// GitLab instance URL.
    pub gitlab_url: String,
    /// Project ID or path.
    pub project_id: String,
    /// CI pipeline ID.
    pub pipeline_id: Option<i64>,
    /// CI job ID.
    pub job_id: Option<i64>,
}

impl GitLabConfig {
    pub fn new(project_id: &str) -> Self {
        Self {
            token: std::env::var("GITLAB_TOKEN").ok(),
            gitlab_url: std::env::var("GITLAB_URL")
                .unwrap_or_else(|_| "https://gitlab.com".to_string()),
            project_id: project_id.to_string(),
            pipeline_id: std::env::var("CI_PIPELINE_ID").ok().and_then(|v| v.parse().ok()),
            job_id: std::env::var("CI_JOB_ID").ok().and_then(|v| v.parse().ok()),
        }
    }

    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }

    pub fn with_gitlab_url(mut self, url: &str) -> Self {
        self.gitlab_url = url.to_string();
        self
    }
}

// --------------------------------------------------------------------------
// GitLab SAST Format
// --------------------------------------------------------------------------

/// GitLab SAST report entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSASTReport {
    pub version: String,
    pub vulnerabilities: Vec<GitLabVulnerability>,
    pub scan: GitLabScan,
}

impl GitLabSASTReport {
    pub fn new() -> Self {
        Self {
            version: "14.0.0".to_string(),
            vulnerabilities: Vec::new(),
            scan: GitLabScan::new(),
        }
    }

    pub fn add_vulnerability(&mut self, vuln: GitLabVulnerability) {
        self.vulnerabilities.push(vuln);
    }
}

impl Default for GitLabSASTReport {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabScan {
    pub status: String,
    pub scan_type: String,
    pub start_time: String,
    pub end_time: String,
    pub version: String,
    pub sbom: Option<GitLabSBOM>,
}

impl GitLabScan {
    pub fn new() -> Self {
        Self {
            status: "success".to_string(),
            scan_type: "sast".to_string(),
            start_time: chrono_lite_now(),
            end_time: chrono_lite_now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            sbom: None,
        }
    }
}

impl Default for GitLabScan {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSBOM {
    pub sbom_format: String,
    pub component: String,
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabVulnerability {
    pub id: Option<i64>,
    #[serde(rename = "category")]
    pub category: String,
    pub name: String,
    #[serde(rename = "cve")]
    pub cve: Option<String>,
    #[serde(rename = "tracker")]
    pub tracker: Option<String>,
    #[serde(rename = "identifiers")]
    pub identifiers: Vec<GitLabIdentifier>,
    #[serde(rename = "file")]
    pub file: Option<String>,
    #[serde(rename = "start_line")]
    pub start_line: Option<usize>,
    #[serde(rename = "end_line")]
    pub end_line: Option<usize>,
    #[serde(rename = "vulnerable_code")]
    pub vulnerable_code: Option<String>,
    #[serde(rename = "location")]
    pub location: GitLabLocation,
    #[serde(rename = "evidence")]
    pub evidence: Option<GitLabEvidence>,
    #[serde(rename = "solution")]
    pub solution: Option<String>,
    #[serde(rename = "severity")]
    pub severity: String,
    #[serde(rename = "confidence")]
    pub confidence: String,
    #[serde(rename = "scanner")]
    pub scanner: GitLabScanner,
    #[serde(rename = "links")]
    pub links: Vec<GitLabLink>,
    #[serde(rename = "metadata")]
    pub metadata: Option<GitLabMetadata>,
    #[serde(rename = "flags")]
    pub flags: Vec<GitLabFlag>,
    #[serde(rename = "ident")]
    pub ident: Option<String>,
}

impl GitLabVulnerability {
    pub fn new(rule_id: &str, severity: &str, message: &str) -> Self {
        Self {
            id: None,
            category: "sast".to_string(),
            name: rule_id.to_string(),
            cve: None,
            tracker: None,
            identifiers: vec![],
            file: None,
            start_line: None,
            end_line: None,
            vulnerable_code: None,
            location: GitLabLocation::new(),
            evidence: None,
            solution: None,
            severity: severity.to_string(),
            confidence: "High".to_string(),
            scanner: GitLabScanner::new("PyNEAT", env!("CARGO_PKG_VERSION")),
            links: vec![],
            metadata: None,
            flags: vec![],
            ident: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabIdentifier {
    #[serde(rename = "type")]
    pub identifier_type: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabLocation {
    #[serde(rename = "file")]
    pub file: String,
    #[serde(rename = "dependency")]
    pub dependency: Option<GitLabDependency>,
    #[serde(rename = "class")]
    pub class: Option<String>,
    #[serde(rename = "method")]
    pub method: Option<String>,
    #[serde(rename = "start_line")]
    pub start_line: Option<usize>,
    #[serde(rename = "end_line")]
    pub end_line: Option<usize>,
}

impl GitLabLocation {
    pub fn new() -> Self {
        Self {
            file: String::new(),
            dependency: None,
            class: None,
            method: None,
            start_line: None,
            end_line: None,
        }
    }

    pub fn with_file(mut self, file: &str) -> Self {
        self.file = file.to_string();
        self
    }

    pub fn with_lines(mut self, start: usize, end: usize) -> Self {
        self.start_line = Some(start);
        self.end_line = Some(end);
        self
    }
}

impl Default for GitLabLocation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabDependency {
    #[serde(rename = "package")]
    pub package: GitLabPackage,
    #[serde(rename = "version")]
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabPackage {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "ecosystem")]
    pub ecosystem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabEvidence {
    #[serde(rename = "source")]
    pub source: GitLabEvidenceSource,
    #[serde(rename = "state")]
    pub state: Option<String>,
    #[serde(rename = "supporting")]
    pub supporting: Vec<GitLabEvidenceItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabEvidenceSource {
    #[serde(rename = "id")]
    pub id: Option<String>,
    #[serde(rename = "name")]
    pub name: Option<String>,
    #[serde(rename = "value")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabEvidenceItem {
    #[serde(rename = "name")]
    pub name: Option<String>,
    #[serde(rename = "value")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabScanner {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(rename = "external_id")]
    pub external_id: Option<String>,
}

impl GitLabScanner {
    pub fn new(name: &str, version: &str) -> Self {
        Self {
            id: name.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            external_id: Some(format!("pyneat://{}", name.to_lowercase())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabLink {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabMetadata {
    #[serde(rename = "description")]
    pub description: Option<String>,
    #[serde(rename = "license")]
    pub license: Option<String>,
    #[serde(rename = "file_type")]
    pub file_type: Option<String>,
    #[serde(rename = "lang")]
    pub lang: Option<String>,
    #[serde(rename = "cwe")]
    pub cwe: Option<Vec<GitLabCWE>>,
    #[serde(rename = "owasp")]
    pub owasp: Option<Vec<String>>,
    #[serde(rename = "git")]
    pub git: Option<GitLabGit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabCWE {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabGit {
    #[serde(rename = "commit_id")]
    pub commit_id: Option<String>,
    #[serde(rename = "commit_title")]
    pub commit_title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabFlag {
    #[serde(rename = "type")]
    pub flag_type: String,
    #[serde(rename = "origin")]
    pub origin: Option<String>,
    #[serde(rename = "mode")]
    pub mode: Option<String>,
    #[serde(rename = "value")]
    pub value: Option<String>,
}

/// Convert pyneat findings to GitLab SAST format.
pub fn create_gitlab_sast_report(
    source_file: &str,
    vulnerabilities: Vec<GitLabVulnerability>,
) -> GitLabSASTReport {
    let mut report = GitLabSASTReport::new();
    for vuln in vulnerabilities {
        report.add_vulnerability(vuln);
    }
    report
}

// --------------------------------------------------------------------------
// Helper
// --------------------------------------------------------------------------

fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // ISO 8601 format approximation
    format!("1970-01-01T00:00:00Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gitlab_sast_report() {
        let report = GitLabSASTReport::new();
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("version"));
        assert!(json.contains("vulnerabilities"));
    }

    #[test]
    fn test_gitlab_vulnerability() {
        let vuln = GitLabVulnerability::new("SEC-001", "high", "Hardcoded password detected");
        let json = serde_json::to_string(&vuln).unwrap();
        assert!(json.contains("SEC-001"));
        assert!(json.contains("high"));
    }
}
