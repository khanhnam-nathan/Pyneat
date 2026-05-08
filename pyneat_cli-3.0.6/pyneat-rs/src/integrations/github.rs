//! GitHub Advanced Security (GHAS) Integration
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! Integrates with GitHub Code Scanning API to upload SARIF reports.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// GitHub API configuration for Code Scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    /// GitHub token for API authentication.
    pub token: Option<String>,
    /// Owner (user or organization).
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// API base URL (defaults to https://api.github.com).
    pub api_url: String,
}

impl GitHubConfig {
    pub fn new(owner: &str, repo: &str) -> Self {
        Self {
            token: std::env::var("GITHUB_TOKEN").ok(),
            owner: owner.to_string(),
            repo: repo.to_string(),
            api_url: "https://api.github.com".to_string(),
        }
    }

    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }

    pub fn with_api_url(mut self, url: &str) -> Self {
        self.api_url = url.to_string();
        self
    }

    /// Upload a SARIF report to GitHub Code Scanning.
    pub async fn upload_sarif(&self, sarif_content: &str, category: &str) -> Result<UploadResponse, String> {
        let client = reqwest::Client::new();
        let url = format!(
            "{}/repos/{}/{}/code-scanning/sarifs",
            self.api_url, self.owner, self.repo
        );

        let body = serde_json::json!({
            "sarif": sarif_content,
            "checkout_uri": ".",
            "commit_sha": self.get_commit_sha(),
            "ref": self.get_ref(),
            "category": category,
        });

        let mut request = client.post(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&body);

        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request.send().await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("GitHub API error {}: {}", status, body));
        }

        let result: UploadResponse = response.json().await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        Ok(result)
    }

    /// Poll the status of a SARIF upload.
    pub async fn get_sarif_status(&self, sarif_id: &str) -> Result<SarifStatusResponse, String> {
        let client = reqwest::Client::new();
        let url = format!(
            "{}/repos/{}/{}/code-scanning/sarifs/{}",
            self.api_url, self.owner, self.repo, sarif_id
        );

        let mut request = client.get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");

        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request.send().await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("GitHub API error {}: {}", status, body));
        }

        let result: SarifStatusResponse = response.json().await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        Ok(result)
    }

    fn get_commit_sha(&self) -> String {
        std::env::var("GITHUB_SHA")
            .unwrap_or_else(|_| "HEAD".to_string())
    }

    fn get_ref(&self) -> String {
        std::env::var("GITHUB_REF")
            .unwrap_or_else(|_| "refs/heads/main".to_string())
    }
}

/// Response from SARIF upload API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResponse {
    pub id: String,
    pub status: String,
    #[serde(rename = "upload_url")]
    pub upload_url: Option<String>,
}

/// Status response from SARIF status API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifStatusResponse {
    pub id: String,
    pub status: String,
    #[serde(rename = "commit_sha")]
    pub commit_sha: String,
    pub ref_field: String,
    #[serde(rename = "check_name")]
    pub check_name: Option<String>,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(rename = "updated_at")]
    pub updated_at: String,
    #[serde(rename = "url")]
    pub url: Option<String>,
    #[serde(rename = "errors")]
    pub errors: Option<Vec<SarifProcessingError>>,
    /// Analysis successfully completed. Only present when status is complete.
    #[serde(rename = "analysis_status")]
    pub analysis_status: Option<String>,
    #[serde(rename = "analysis_url")]
    pub analysis_url: Option<String>,
}

/// Processing error from SARIF analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifProcessingError {
    #[serde(rename = "type")]
    pub error_type: String,
    #[serde(rename = "description")]
    pub description: String,
}

// --------------------------------------------------------------------------
// GitHub Security Advisories
// --------------------------------------------------------------------------

/// Represents a GitHub Security Advisory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubAdvisory {
    /// GHSA identifier (e.g., "GHSA-xxxx-xxxx-xxxx").
    pub ghsa_id: String,
    /// CVE identifier if available.
    pub cve_id: Option<String>,
    /// Summary of the advisory.
    pub summary: String,
    /// Detailed description.
    pub description: String,
    /// Severity level.
    pub severity: String,
    /// CVSS score.
    pub cvss_score: Option<f32>,
    /// Vector string.
    pub cvss_vector_string: Option<String>,
    /// Affected ecosystems.
    pub ecosystems: Vec<String>,
    /// Vulnerability classification.
    pub classifications: Vec<String>,
    /// Published date.
    pub published_at: String,
    /// Updated date.
    pub updated_at: String,
    /// Patched versions.
    pub patched_versions: Option<String>,
    /// Vulnerable version range.
    pub vulnerable_version_range: Option<String>,
    /// Advisory URL.
    pub html_url: String,
    /// Weaknesses.
    pub weaknesses: Vec<GitHubWeakness>,
}

/// Weakness in a GitHub Security Advisory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubWeakness {
    #[serde(rename = "type")]
    pub weakness_type: String,
    /// CWE identifiers.
    pub cwes: Vec<GitHubCWE>,
}

/// CWE reference in a weakness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubCWE {
    pub cwe_id: String,
    pub name: String,
}

/// GitHub Advisory Client for querying the GitHub Advisory Database.
pub struct GitHubAdvisoryClient {
    pub config: GitHubConfig,
}

impl GitHubAdvisoryClient {
    pub fn new(config: GitHubConfig) -> Self {
        Self { config }
    }

    /// Query advisories by ecosystem (e.g., "pip", "npm", "go").
    pub async fn query_by_ecosystem(&self, ecosystem: &str) -> Result<Vec<GitHubAdvisory>, String> {
        let client = reqwest::Client::new();
        let url = format!(
            "{}/advisories?type=reviewed&ecosystem={}&per_page=100",
            self.config.api_url, ecosystem
        );

        let mut request = client.get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");

        if let Some(token) = &self.config.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request.send().await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("GitHub API error: {}", response.status()));
        }

        let advisories: Vec<serde_json::Value> = response.json().await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        let result: Vec<GitHubAdvisory> = advisories
            .into_iter()
            .filter_map(|adv| {
                serde_json::from_value(adv).ok()
            })
            .collect();

        Ok(result)
    }

    /// Query advisories by CWE.
    pub async fn query_by_cwe(&self, cwe_id: &str) -> Result<Vec<GitHubAdvisory>, String> {
        let client = reqwest::Client::new();
        let url = format!(
            "{}/advisories?type=reviewed&cwe_id={}&per_page=100",
            self.config.api_url, cwe_id
        );

        let mut request = client.get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");

        if let Some(token) = &self.config.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request.send().await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("GitHub API error: {}", response.status()));
        }

        let advisories: Vec<serde_json::Value> = response.json().await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        let result: Vec<GitHubAdvisory> = advisories
            .into_iter()
            .filter_map(|adv| {
                serde_json::from_value(adv).ok()
            })
            .collect();

        Ok(result)
    }
}

// --------------------------------------------------------------------------
// Secret Scanning
// --------------------------------------------------------------------------

/// Secret scanning alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScanningAlert {
    pub number: i64,
    pub state: String,
    #[serde(rename = "secret_type")]
    pub secret_type: String,
    #[serde(rename = "secret_type_display_name")]
    pub secret_type_display_name: String,
    pub resolution: Option<String>,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(rename = "updated_at")]
    pub updated_at: String,
    #[serde(rename = "url")]
    pub url: String,
}

/// GitHub Secret Scanning Client.
pub struct GitHubSecretScanningClient {
    pub config: GitHubConfig,
}

impl GitHubSecretScanningClient {
    pub fn new(config: GitHubConfig) -> Self {
        Self { config }
    }

    /// List secret scanning alerts.
    pub async fn list_alerts(&self, state: Option<&str>) -> Result<Vec<SecretScanningAlert>, String> {
        let client = reqwest::Client::new();
        let mut url = format!(
            "{}/repos/{}/{}/secret-scanning/alerts",
            self.config.api_url, self.config.owner, self.config.repo
        );

        if let Some(s) = state {
            url.push_str(&format!("?state={}", s));
        }

        let mut request = client.get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");

        if let Some(token) = &self.config.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request.send().await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("GitHub API error: {}", response.status()));
        }

        let alerts: Vec<SecretScanningAlert> = response.json().await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        Ok(alerts)
    }
}
