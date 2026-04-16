//! PyNEAT Pro Engine IPC Protocol
//!
//! This module defines the JSON-based communication protocol between
//! pyneat-core (AGPL) and pyneat-pro-engine (proprietary).
//!
//! Communication is done via stdin/stdout:
//! - pyneat-core sends JSON requests to pyneat-pro-engine via stdin
//! - pyneat-pro-engine responds with JSON via stdout

use serde::{Deserialize, Serialize};

// ============================================================================
// REQUEST TYPES (Core -> Pro Engine)
// ============================================================================

/// Top-level request envelope
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProEngineRequest {
    /// Analyze code with advanced semantic analysis
    #[serde(rename = "semantic_analysis")]
    SemanticAnalysis {
        code: String,
        language: String,
        options: SemanticAnalysisOptions,
    },

    /// Type-aware validation
    #[serde(rename = "type_validation")]
    TypeValidation {
        original_code: String,
        transformed_code: String,
        file_path: String,
        options: TypeValidationOptions,
    },

    /// Scope analysis for dead code detection
    #[serde(rename = "scope_analysis")]
    ScopeAnalysis {
        code: String,
        language: String,
        file_path: String,
    },

    /// Advanced security scanning with CVSS scoring
    #[serde(rename = "advanced_security_scan")]
    AdvancedSecurityScan {
        code: String,
        language: String,
        options: SecurityScanOptions,
    },

    /// Run semantic diff between two code versions
    #[serde(rename = "semantic_diff")]
    SemanticDiff {
        original_code: String,
        transformed_code: String,
        language: String,
    },

    /// AI bug detection
    #[serde(rename = "ai_bug_detection")]
    AIBugDetection {
        code: String,
        language: String,
        confidence_threshold: f32,
    },

    /// Dependency vulnerability scan
    #[serde(rename = "dependency_scan")]
    DependencyScan {
        dependencies: Vec<Dependency>,
        ecosystem: Ecosystem,
    },

    /// CVE/GHSA advisory lookup
    #[serde(rename = "advisory_lookup")]
    AdvisoryLookup {
        package: String,
        version: Option<String>,
        ecosystem: Ecosystem,
    },

    /// Health check
    #[serde(rename = "ping")]
    Ping,
}

// ============================================================================
// RESPONSE TYPES (Pro Engine -> Core)
// ============================================================================

/// Top-level response envelope
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ProEngineResponse {
    /// Success response
    #[serde(rename = "ok")]
    Ok {
        #[serde(flatten)]
        data: ProEngineResult,
    },

    /// Error response
    #[serde(rename = "error")]
    Error {
        code: String,
        message: String,
        details: Option<String>,
    },
}

/// Result data for successful responses
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result_type")]
pub enum ProEngineResult {
    /// Semantic analysis result
    #[serde(rename = "semantic_analysis")]
    SemanticAnalysis {
        has_semantic_changes: bool,
        critical_changes: Vec<SemanticChange>,
        warnings: Vec<String>,
        safe_to_transform: bool,
    },

    /// Type validation result
    #[serde(rename = "type_validation")]
    TypeValidation {
        is_valid: bool,
        new_errors: Vec<TypeError>,
        original_error_count: usize,
        new_error_count: usize,
    },

    /// Scope analysis result
    #[serde(rename = "scope_analysis")]
    ScopeAnalysis {
        dead_functions: Vec<DeadFunction>,
        dead_classes: Vec<DeadClass>,
        referenced_globals: Vec<String>,
        unused_variables: Vec<UnusedVariable>,
    },

    /// Advanced security scan result
    #[serde(rename = "advanced_security_scan")]
    AdvancedSecurityScan {
        findings: Vec<SecurityFinding>,
        summary: SecuritySummary,
    },

    /// Semantic diff result
    #[serde(rename = "semantic_diff")]
    SemanticDiff {
        changes: Vec<DiffChange>,
        is_breaking: bool,
        summary: String,
    },

    /// AI bug detection result
    #[serde(rename = "ai_bug_detection")]
    AIBugDetection {
        bugs: Vec<AIBug>,
        overall_confidence: f32,
    },

    /// Dependency scan result
    #[serde(rename = "dependency_scan")]
    DependencyScan {
        vulnerabilities: Vec<DependencyVulnerability>,
        safe_dependencies: Vec<String>,
    },

    /// Advisory lookup result
    #[serde(rename = "advisory_lookup")]
    AdvisoryLookup {
        advisories: Vec<SecurityAdvisory>,
        is_known_vulnerable: bool,
    },

    /// Ping response
    #[serde(rename = "pong")]
    Pong {
        version: String,
        features: Vec<String>,
    },
}

// ============================================================================
// OPTION TYPES
// ============================================================================

/// Options for semantic analysis
#[derive(Debug, Serialize, Deserialize)]
pub struct SemanticAnalysisOptions {
    pub check_imports: bool,
    pub check_types: bool,
    pub check_side_effects: bool,
    pub allowed_semantic_nodes: Vec<String>,
}

/// Options for type validation
#[derive(Debug, Serialize, Deserialize)]
pub struct TypeValidationOptions {
    pub type_checker: TypeChecker,
    pub strict_mode: bool,
    pub fail_on_warnings: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum TypeChecker {
    #[serde(rename = "mypy")]
    Mypy,
    #[serde(rename = "pyright")]
    Pyright,
    #[serde(rename = "pyre")]
    Pyre,
}

/// Options for security scanning
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityScanOptions {
    pub include_critical: bool,
    pub include_high: bool,
    pub include_medium: bool,
    pub include_low: bool,
    pub include_info: bool,
    pub include_cwe_mapping: bool,
    pub include_owasp_mapping: bool,
    pub include_cvss_scoring: bool,
}

// ============================================================================
// RESULT TYPES
// ============================================================================

/// A semantic change detected during transformation
#[derive(Debug, Serialize, Deserialize)]
pub struct SemanticChange {
    pub node_type: String,
    pub node_name: String,
    pub change_type: ChangeType,
    pub severity: String,
    pub description: String,
    pub line: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ChangeType {
    #[serde(rename = "removed")]
    Removed,
    #[serde(rename = "modified")]
    Modified,
    #[serde(rename = "reordered")]
    Reordered,
    #[serde(rename = "type_changed")]
    TypeChanged,
}

/// A type error introduced by transformation
#[derive(Debug, Serialize, Deserialize)]
pub struct TypeError {
    pub message: String,
    pub line: usize,
    pub column: usize,
    pub error_code: Option<String>,
    pub severity: String,
}

/// A dead function detected by scope analysis
#[derive(Debug, Serialize, Deserialize)]
pub struct DeadFunction {
    pub name: String,
    pub line: usize,
    pub column: usize,
    pub reason: String,
    pub is_exported: bool,
    pub has_side_effects: bool,
}

/// A dead class detected by scope analysis
#[derive(Debug, Serialize, Deserialize)]
pub struct DeadClass {
    pub name: String,
    pub line: usize,
    pub column: usize,
    pub reason: String,
}

/// An unused variable
#[derive(Debug, Serialize, Deserialize)]
pub struct UnusedVariable {
    pub name: String,
    pub line: usize,
    pub column: usize,
    pub scope: String,
}

/// A security finding from advanced scanning
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub rule_id: String,
    pub severity: String,
    pub cwe_id: Option<String>,
    pub owasp_id: Option<String>,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub problem: String,
    pub fix_hint: String,
    pub auto_fix_available: bool,
    pub fix_constraints: Vec<String>,
    pub do_not: Vec<String>,
    pub verify: Vec<String>,
}

/// Summary of security scan
#[derive(Debug, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub auto_fixable: usize,
}

/// A change in semantic diff
#[derive(Debug, Serialize, Deserialize)]
pub struct DiffChange {
    pub change_type: String,
    pub description: String,
    pub line: Option<usize>,
    pub before: Option<String>,
    pub after: Option<String>,
}

/// An AI-specific bug
#[derive(Debug, Serialize, Deserialize)]
pub struct AIBug {
    pub bug_type: String,
    pub rule_id: String,
    pub severity: String,
    pub confidence: f32,
    pub line: usize,
    pub snippet: String,
    pub problem: String,
    pub fix_hint: String,
}

/// A dependency to scan
#[derive(Debug, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
}

/// Supported ecosystems
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Ecosystem {
    #[serde(rename = "pip")]
    Pip,
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "go")]
    Go,
    #[serde(rename = "cargo")]
    Cargo,
    #[serde(rename = "maven")]
    Maven,
    #[serde(rename = "nuget")]
    NuGet,
    #[serde(rename = "packagist")]
    Packagist,
    #[serde(rename = "rubygems")]
    RubyGems,
}

/// A vulnerability in a dependency
#[derive(Debug, Serialize, Deserialize)]
pub struct DependencyVulnerability {
    pub dependency: String,
    pub version: String,
    pub cve_id: Option<String>,
    pub ghsa_id: Option<String>,
    pub severity: String,
    pub cvss_score: Option<f32>,
    pub description: String,
    pub fixed_in: Option<String>,
    pub recommendation: String,
}

/// A security advisory
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityAdvisory {
    pub id: String,
    pub source: String,
    pub severity: String,
    pub cvss_score: Option<f32>,
    pub summary: String,
    pub description: String,
    pub published_at: Option<String>,
    pub updated_at: Option<String>,
    pub references: Vec<String>,
    pub vulnerable_versions: Option<String>,
    pub patched_versions: Option<String>,
}

// ============================================================================
// PROTOCOL HELPERS
// ============================================================================

impl ProEngineRequest {
    /// Serialize request to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize request from JSON string
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

impl ProEngineResponse {
    /// Serialize response to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize response from JSON string
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

impl ProEngineResponse {
    /// Create an error response
    pub fn error(code: &str, message: &str) -> Self {
        ProEngineResponse::Error {
            code: code.to_string(),
            message: message.to_string(),
            details: None,
        }
    }

    /// Create an error response with details
    pub fn error_with_details(code: &str, message: &str, details: &str) -> Self {
        ProEngineResponse::Error {
            code: code.to_string(),
            message: message.to_string(),
            details: Some(details.to_string()),
        }
    }
}
