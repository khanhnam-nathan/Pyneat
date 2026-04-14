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

use crate::rules::base::{extract_snippet, Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

/// SEC-070: Docker Vulnerability Rule
///
/// CWE-1104: Use of Unmaintained Third-Party Components
pub struct DockerVulnerabilityRule;

impl Rule for DockerVulnerabilityRule {
    fn id(&self) -> &str { "SEC-070" }
    fn name(&self) -> &str { "Missing Docker Image Vulnerability Scan" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let is_docker_file = code.contains("Dockerfile") ||
                             code.contains("docker-compose") ||
                             code.contains("FROM");

        let has_scan = [
            r"(?i)trivy",
            r"(?i)grype",
            r"(?i)anchore",
            r"(?i)snyk",
            r"(?i)clair",
            r"(?i)vulnerability\s*scan",
        ];

        let scan_found = has_scan.iter().any(|p| {
            regex::Regex::new(p).map(|re| re.is_match(code)).unwrap_or(false)
        });

        if is_docker_file && !scan_found {
            if let Ok(re) = regex::Regex::new(r#"FROM\s+[^:]+:[^\s]+"#) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-070".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-1104".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A06:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: "Docker configuration without vulnerability scanning".to_string(),
                        fix_hint: "Add vulnerability scanning to Docker workflow: 'docker scan IMAGE' or use Trivy/Grype in CI/CD.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.start);
        findings.dedup_by(|a, b| a.start == b.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}
