//! IaC Security Scanner for Docker, Kubernetes, and Terraform files.
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

use crate::rules::base::{extract_snippet, Fix, Finding, Rule, Severity};
use std::mem::MaybeUninit;

/// Custom trait for IaC rules to specify supported file extensions
pub trait IaCRule: Rule {
    fn supported_extensions(&self) -> Vec<&'static str>;

    /// Detect issues using regex-only pattern matching (no AST required)
    #[allow(invalid_value)]
    fn detect_regex_only(&self, code: &str) -> Vec<Finding> {
        let _dummy = unsafe { MaybeUninit::<tree_sitter::Tree>::uninit().assume_init() };
        self.detect(&_dummy, code)
    }
}

/// IAC-003: Docker Secrets in Env
pub struct DockerSecretsInEnvRule;

impl Rule for DockerSecretsInEnvRule {
    fn id(&self) -> &str {
        "IAC-003"
    }

    fn name(&self) -> &str {
        "DockerSecretsInEnv"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &tree_sitter::Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let secret_pattern = regex::Regex::new(
            r"^\s*ENV\s+.*?(?:SECRET|PASSWORD|PASSWD|PWD|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|PRIVATEKEY|ACCESS_KEY|ACCESSKEY|AWS_)[^\s]*"
        ).unwrap();

        for m in secret_pattern.find_iter(code) {
            let snippet = extract_snippet(code, m.start(), m.end());
            findings.push(Finding {
                rule_id: "IAC-003".to_string(),
                severity: Severity::High.as_str().to_string(),
                cwe_id: Some("CWE-798".to_string()),
                cvss_score: Some(7.5),
                owasp_id: Some("A02:2021".to_string()),
                start: m.start(),
                end: m.end(),
                snippet,
                problem: "Environment variable contains or references a secret value that could be exposed in Docker image layers".to_string(),
                fix_hint: "Use Docker secrets or environment variable injection at runtime instead of hardcoding sensitive values".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }

    fn supports_auto_fix(&self) -> bool {
        false
    }
}

impl IaCRule for DockerSecretsInEnvRule {
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["Dockerfile", ".dockerfile"]
    }
}

/// IAC-004: Kubernetes Privileged Pod
pub struct KubernetesPrivilegedPodRule;

impl Rule for KubernetesPrivilegedPodRule {
    fn id(&self) -> &str {
        "IAC-004"
    }

    fn name(&self) -> &str {
        "KubernetesPrivilegedPod"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, _tree: &tree_sitter::Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let privileged_pattern = regex::Regex::new(
            r#"^\s*privileged:\s*["']?true["']?"#
        ).unwrap();

        for m in privileged_pattern.find_iter(code) {
            let snippet = extract_snippet(code, m.start(), m.end());
            findings.push(Finding {
                rule_id: "IAC-004".to_string(),
                severity: Severity::Critical.as_str().to_string(),
                cwe_id: Some("CWE-250".to_string()),
                cvss_score: Some(9.8),
                owasp_id: Some("A01:2021".to_string()),
                start: m.start(),
                end: m.end(),
                snippet,
                problem: "Container is running with privileged access, allowing access to host system resources".to_string(),
                fix_hint: "Set privileged: false in securityContext. If privileged access is required, ensure it's scoped to specific namespaces with proper RBAC controls".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }

    fn supports_auto_fix(&self) -> bool {
        false
    }
}

impl IaCRule for KubernetesPrivilegedPodRule {
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec![".yaml", ".yml"]
    }
}

/// IAC-005: Terraform S3 Public Access
pub struct TerraformS3PublicAccessRule;

impl Rule for TerraformS3PublicAccessRule {
    fn id(&self) -> &str {
        "IAC-005"
    }

    fn name(&self) -> &str {
        "TerraformS3PublicAccess"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &tree_sitter::Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for public ACL
        let public_acl_pattern = regex::Regex::new(
            r#"^\s*acl\s*=\s*["']public[-_]?(?:read|write|read[-_]?write)["']"#
        ).unwrap();

        for m in public_acl_pattern.find_iter(code) {
            let snippet = extract_snippet(code, m.start(), m.end());
            findings.push(Finding {
                rule_id: "IAC-005".to_string(),
                severity: Severity::High.as_str().to_string(),
                cwe_id: Some("CWE-284".to_string()),
                cvss_score: Some(8.2),
                owasp_id: Some("A01:2021".to_string()),
                start: m.start(),
                end: m.end(),
                snippet,
                problem: "S3 bucket ACL is set to public access, allowing anyone on the internet to read/write".to_string(),
                fix_hint: "Remove the public ACL and use private access with IAM policies for controlled access".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        // Check for S3 buckets missing encryption
        let s3_bucket_pattern = regex::Regex::new(
            r#"resource\s+["']aws_s3_bucket["']"#
        ).unwrap();

        let encryption_pattern = regex::Regex::new(
            r"server_side_encryption_configuration\s*=|encrypt\s*=\s*true|kms_key_id\s*="
        ).unwrap();

        for bucket_m in s3_bucket_pattern.find_iter(code) {
            let search_start = bucket_m.end();
            let search_end = std::cmp::min(code.len(), search_start + 2000);
            let bucket_section = &code[search_start..search_end];

            let has_encryption = encryption_pattern.is_match(bucket_section);

            if !has_encryption {
                let snippet = extract_snippet(code, bucket_m.start(), bucket_m.end());
                findings.push(Finding {
                    rule_id: "IAC-005".to_string(),
                    severity: Severity::High.as_str().to_string(),
                    cwe_id: Some("CWE-311".to_string()),
                    cvss_score: Some(7.5),
                    owasp_id: Some("A02:2021".to_string()),
                    start: bucket_m.start(),
                    end: bucket_m.end(),
                    snippet,
                    problem: "S3 bucket does not have server-side encryption configured".to_string(),
                    fix_hint: "Add server_side_encryption_configuration with AES-256 or AWS KMS encryption".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }

    fn supports_auto_fix(&self) -> bool {
        false
    }
}

impl IaCRule for TerraformS3PublicAccessRule {
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec![".tf", ".tfvars"]
    }
}

/// IAC-006: K8s HostPath Mount
pub struct K8sHostPathMountRule;

impl Rule for K8sHostPathMountRule {
    fn id(&self) -> &str {
        "IAC-006"
    }

    fn name(&self) -> &str {
        "K8sHostPathMount"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &tree_sitter::Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Multi-line hostPath detection
        let hostpath_pattern = regex::Regex::new(
            r#"^\s*hostPath:\s*$[^$]*?(?:path:\s*["']/?[^"']+["'])"#
        ).unwrap();

        for m in hostpath_pattern.find_iter(code) {
            let snippet = extract_snippet(code, m.start(), std::cmp::min(m.end(), m.start() + 100));
            findings.push(Finding {
                rule_id: "IAC-006".to_string(),
                severity: Severity::High.as_str().to_string(),
                cwe_id: Some("CWE-668".to_string()),
                cvss_score: Some(8.1),
                owasp_id: Some("A01:2021".to_string()),
                start: m.start(),
                end: m.end(),
                snippet,
                problem: "Volume is mounted directly from the host filesystem, bypassing container isolation".to_string(),
                fix_hint: "Avoid hostPath mounts in production. Use emptyDir volumes, persistentVolumeClaims, or cloud-specific storage classes".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        // Single-line hostPath detection
        let hostpath_simple = regex::Regex::new(
            r#"^\s*hostPath:\s*["']/?[^"']+["']"#
        ).unwrap();

        for m in hostpath_simple.find_iter(code) {
            let start = m.start();
            let end = m.end();
            let already_found = findings.iter().any(|f| f.start <= start && f.end >= end);
            if !already_found {
                let snippet = extract_snippet(code, start, end);
                findings.push(Finding {
                    rule_id: "IAC-006".to_string(),
                    severity: Severity::High.as_str().to_string(),
                    cwe_id: Some("CWE-668".to_string()),
                    cvss_score: Some(8.1),
                    owasp_id: Some("A01:2021".to_string()),
                    start,
                    end,
                    snippet,
                    problem: "Volume is mounted directly from the host filesystem".to_string(),
                    fix_hint: "Consider using emptyDir instead of hostPath, or use readOnly: true if unavoidable".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }

    fn supports_auto_fix(&self) -> bool {
        false
    }
}

impl IaCRule for K8sHostPathMountRule {
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec![".yaml", ".yml"]
    }
}

/// IAC-007: Docker --network=host
pub struct DockerNetworkHostRule;

impl Rule for DockerNetworkHostRule {
    fn id(&self) -> &str {
        "IAC-007"
    }

    fn name(&self) -> &str {
        "DockerNetworkHost"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn detect(&self, _tree: &tree_sitter::Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let network_host_pattern = regex::Regex::new(
            r"--\s*network\s+host|--network\s+host"
        ).unwrap();

        for m in network_host_pattern.find_iter(code) {
            let snippet = extract_snippet(code, m.start(), m.end());
            findings.push(Finding {
                rule_id: "IAC-007".to_string(),
                severity: Severity::Medium.as_str().to_string(),
                cwe_id: Some("CWE-654".to_string()),
                cvss_score: Some(6.5),
                owasp_id: Some("A01:2021".to_string()),
                start: m.start(),
                end: m.end(),
                snippet,
                problem: "Container is using host network mode, removing network isolation between containers".to_string(),
                fix_hint: "Use bridge network mode with explicit port mappings instead of host network mode".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }

    fn supports_auto_fix(&self) -> bool {
        false
    }
}

impl IaCRule for DockerNetworkHostRule {
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["Dockerfile", ".dockerfile"]
    }
}

/// IAC-008: K8s Allow Privilege Escalation
pub struct K8sAllowPrivilegeEscalationRule;

impl Rule for K8sAllowPrivilegeEscalationRule {
    fn id(&self) -> &str {
        "IAC-008"
    }

    fn name(&self) -> &str {
        "K8sAllowPrivilegeEscalation"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &tree_sitter::Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let priv_escalation_pattern = regex::Regex::new(
            r#"^\s*allowPrivilegeEscalation:\s*["']?true["']?"#
        ).unwrap();

        for m in priv_escalation_pattern.find_iter(code) {
            let snippet = extract_snippet(code, m.start(), m.end());
            findings.push(Finding {
                rule_id: "IAC-008".to_string(),
                severity: Severity::High.as_str().to_string(),
                cwe_id: Some("CWE-269".to_string()),
                cvss_score: Some(8.1),
                owasp_id: Some("A01:2021".to_string()),
                start: m.start(),
                end: m.end(),
                snippet,
                problem: "Container allows privilege escalation, permitting child processes to gain more privileges than parent".to_string(),
                fix_hint: "Set allowPrivilegeEscalation: false in securityContext and ensure runAsNonRoot: true".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }

    fn supports_auto_fix(&self) -> bool {
        false
    }
}

impl IaCRule for K8sAllowPrivilegeEscalationRule {
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec![".yaml", ".yml"]
    }
}

/// IAC-009: Terraform State Not Encrypted
pub struct TerraformStateNotEncryptedRule;

impl Rule for TerraformStateNotEncryptedRule {
    fn id(&self) -> &str {
        "IAC-009"
    }

    fn name(&self) -> &str {
        "TerraformStateNotEncrypted"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn detect(&self, _tree: &tree_sitter::Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let s3_backend_pattern = regex::Regex::new(
            r#"backend\s+["']s3["']"#
        ).unwrap();

        let encrypt_pattern = regex::Regex::new(
            r"encrypt\s*=\s*true"
        ).unwrap();

        for backend_m in s3_backend_pattern.find_iter(code) {
            let search_content = &code[backend_m.end()..];
            let block_end = search_content.find('}').map(|i| std::cmp::min(i + 1, 2000)).unwrap_or(2000);
            let backend_block = &search_content[..block_end];

            let has_encryption = encrypt_pattern.is_match(backend_block);

            if !has_encryption {
                let snippet = extract_snippet(code, backend_m.start(), backend_m.end());
                findings.push(Finding {
                    rule_id: "IAC-009".to_string(),
                    severity: Severity::Medium.as_str().to_string(),
                    cwe_id: Some("CWE-311".to_string()),
                    cvss_score: Some(6.5),
                    owasp_id: Some("A02:2021".to_string()),
                    start: backend_m.start(),
                    end: backend_m.end(),
                    snippet,
                    problem: "Terraform state backend is configured without encryption enabled".to_string(),
                    fix_hint: "Add encrypt = true to the S3 backend configuration to enable server-side encryption for Terraform state".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }

    fn supports_auto_fix(&self) -> bool {
        false
    }
}

impl IaCRule for TerraformStateNotEncryptedRule {
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec![".tf", ".tfvars"]
    }
}

/// IAC-010: K8s Root Container
pub struct K8sRootContainerRule;

impl Rule for K8sRootContainerRule {
    fn id(&self) -> &str {
        "IAC-010"
    }

    fn name(&self) -> &str {
        "K8sRootContainer"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, _tree: &tree_sitter::Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let run_as_root_pattern = regex::Regex::new(
            r#"^\s*runAsUser:\s*["']?\s*0\s*["']?"#
        ).unwrap();

        for m in run_as_root_pattern.find_iter(code) {
            let snippet = extract_snippet(code, m.start(), m.end());
            findings.push(Finding {
                rule_id: "IAC-010".to_string(),
                severity: Severity::High.as_str().to_string(),
                cwe_id: Some("CWE-250".to_string()),
                cvss_score: Some(7.5),
                owasp_id: Some("A01:2021".to_string()),
                start: m.start(),
                end: m.end(),
                snippet,
                problem: "Container is configured to run as root user (UID 0)".to_string(),
                fix_hint: "Change runAsUser to a non-zero value (e.g., 1000) and ensure runAsNonRoot: true is set".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> {
        None
    }

    fn supports_auto_fix(&self) -> bool {
        false
    }
}

impl IaCRule for K8sRootContainerRule {
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec![".yaml", ".yml"]
    }
}

/// IaC Scanner that orchestrates all IaC security rules
pub struct IaCScanner {
    rules: Vec<Box<dyn IaCRule>>,
}

impl IaCScanner {
    pub fn new() -> Self {
        let rules: Vec<Box<dyn IaCRule>> = vec![
            Box::new(DockerSecretsInEnvRule),
            Box::new(KubernetesPrivilegedPodRule),
            Box::new(TerraformS3PublicAccessRule),
            Box::new(K8sHostPathMountRule),
            Box::new(DockerNetworkHostRule),
            Box::new(K8sAllowPrivilegeEscalationRule),
            Box::new(TerraformStateNotEncryptedRule),
            Box::new(K8sRootContainerRule),
        ];
        Self { rules }
    }

    /// Scan content using regex-based detection (no tree-sitter needed)
    pub fn scan_regex(&self, code: &str, file_path: &str) -> Vec<IacFinding> {
        let mut all_findings = Vec::new();

        // Check file extension
        let path_lower = file_path.to_lowercase();

        // Run all applicable rules
        for rule in &self.rules {
            let extensions = rule.supported_extensions();
            let supports_file = extensions.iter().any(|ext| path_lower.ends_with(ext));

            if supports_file {
                // IaC rules are regex-based and don't need a parse tree
                let findings = rule.detect_regex_only(code);
                for f in findings {
                    all_findings.push(IacFinding {
                        rule_id: f.rule_id,
                        severity: f.severity,
                        cwe_id: f.cwe_id,
                        line: code[..f.start].chars().filter(|&c| c == '\n').count() + 1,
                        snippet: f.snippet,
                        problem: f.problem,
                        fix_hint: f.fix_hint,
                        file_path: file_path.to_string(),
                    });
                }
            }
        }

        // Sort by line number
        all_findings.sort_by_key(|f| f.line);
        all_findings
    }

    pub fn get_rules(&self) -> Vec<(String, String)> {
        self.rules
            .iter()
            .map(|r| (r.id().to_string(), r.name().to_string()))
            .collect()
    }
}

impl Default for IaCScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// A finding from the IaC scanner
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IacFinding {
    /// Rule identifier (e.g., "IAC-003")
    pub rule_id: String,
    /// Severity level
    pub severity: String,
    /// CWE identifier
    pub cwe_id: Option<String>,
    /// Line number where the issue was found
    pub line: usize,
    /// Matched code snippet
    pub snippet: String,
    /// Problem description
    pub problem: String,
    /// Fix hint
    pub fix_hint: String,
    /// File path
    pub file_path: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_secrets_detection() {
        let scanner = IaCScanner::new();
        let code = r#"
FROM ubuntu:20.04
ENV DB_PASSWORD=secret123
ENV API_KEY=my-secret-key
"#;
        let findings = scanner.scan_regex(code, "Dockerfile");
        assert!(findings.len() >= 2);
        assert!(findings.iter().any(|f| f.rule_id == "IAC-003"));
    }

    #[test]
    fn test_kubernetes_privileged_detection() {
        let scanner = IaCScanner::new();
        let code = r#"
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: test
      securityContext:
        privileged: true
"#;
        let findings = scanner.scan_regex(code, "pod.yaml");
        assert!(findings.iter().any(|f| f.rule_id == "IAC-004"));
    }

    #[test]
    fn test_terraform_s3_public_acl() {
        let scanner = IaCScanner::new();
        let code = r#"
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"
}
"#;
        let findings = scanner.scan_regex(code, "main.tf");
        assert!(findings.iter().any(|f| f.rule_id == "IAC-005"));
    }

    #[test]
    fn test_hostpath_detection() {
        let scanner = IaCScanner::new();
        let code = r#"
volumes:
  - name: host-volume
    hostPath:
      path: /var/log
"#;
        let findings = scanner.scan_regex(code, "deployment.yaml");
        assert!(findings.iter().any(|f| f.rule_id == "IAC-006"));
    }

    #[test]
    fn test_network_host_detection() {
        let scanner = IaCScanner::new();
        let code = r#"
FROM nginx:latest
RUN --network host curl http://example.com
"#;
        let findings = scanner.scan_regex(code, "Dockerfile");
        assert!(findings.iter().any(|f| f.rule_id == "IAC-007"));
    }

    #[test]
    fn test_privilege_escalation_detection() {
        let scanner = IaCScanner::new();
        let code = r#"
securityContext:
  allowPrivilegeEscalation: true
"#;
        let findings = scanner.scan_regex(code, "pod.yaml");
        assert!(findings.iter().any(|f| f.rule_id == "IAC-008"));
    }

    #[test]
    fn test_terraform_state_encryption() {
        let scanner = IaCScanner::new();
        let code = r#"
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "env:/dev/terraform.tfstate"
  }
}
"#;
        let findings = scanner.scan_regex(code, "backend.tf");
        assert!(findings.iter().any(|f| f.rule_id == "IAC-009"));
    }

    #[test]
    fn test_root_container_detection() {
        let scanner = IaCScanner::new();
        let code = r#"
securityContext:
  runAsUser: 0
"#;
        let findings = scanner.scan_regex(code, "pod.yaml");
        assert!(findings.iter().any(|f| f.rule_id == "IAC-010"));
    }
}
