//! Git Secrets and Infrastructure Security Rules
//!
//! Detects hardcoded secrets, misconfigured cloud resources, and CI/CD vulnerabilities.

use regex::Regex;
use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LangRule, LangFinding};

// --------------------------------------------------------------------------
// Git Secrets / Gitleaks Patterns
// --------------------------------------------------------------------------

pub struct GitSecretsPattern;

impl LangRule for GitSecretsPattern {
    fn id(&self) -> &str { "GITLEAKS-001" }
    fn name(&self) -> &str { "Hardcoded Git Secret Pattern" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let secret_patterns = [
            // AWS
            (r##"(?i)aws_access_key_id\s*[=:]\s*['"]?[A-Z0-9]{16,}['"]?"##,
             "AWS Access Key ID detected"),
            (r##"(?i)aws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40,}['"]?"##,
             "AWS Secret Access Key detected"),
            (r"AKIA[0-9A-Z]{16}",
             "AWS Access Key ID pattern (AKIA...)"),
            // GitHub
            (r"ghp_[A-Za-z0-9]{36}",
             "GitHub Personal Access Token detected"),
            (r"gho_[A-Za-z0-9]{36}",
             "GitHub OAuth Token detected"),
            (r"ghu_[A-Za-z0-9]{36}",
             "GitHub User Access Token detected"),
            (r"ghs_[A-Za-z0-9]{36}",
             "GitHub Server Access Token detected"),
            (r"ghr_[A-Za-z0-9]{36}",
             "GitHub Refresh Token detected"),
            (r##"(?i)github[_-]?token\s*[=:]\s*['"]?[A-Za-z0-9_\\-]{36,}['"]?"##,
             "GitHub Token detected"),
            // GitLab
            (r##"glpat-[A-Za-z0-9\\-_]{20}"##,
             "GitLab Personal Access Token detected"),
            // Slack
            (r##"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"##,
             "Slack Token detected"),
            // Stripe
            (r##"sk_live_[A-Za-z0-9]{24,}"##,
             "Stripe Secret Key detected"),
            (r##"rk_live_[A-Za-z0-9]{24,}"##,
             "Stripe Restricted Key detected"),
            // Twilio
            (r##"SK[0-9a-fA-F]{32}"##,
             "Twilio API Key detected"),
            // JWT
            (r##"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*"##,
             "JWT Token detected (may be hardcoded)"),
            // Private Key
            (r##"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"##,
             "Private Key detected in source"),
            // Generic API keys
            (r##"(?i)(api[_-]?key|apikey|api_secret)\s*[=:]\s*['"]?[A-Za-z0-9]{20,}['"]?"##,
             "Generic API Key detected"),
            // Database connection strings
            (r##"(?i)(password|pwd|pass)\s*[=:]\s*['"][^'"]{8,}['"]"##,
             "Hardcoded Password in connection string"),
            // Telegram
            (r##"[0-9]{8,}:[A-Za-z0-9_-]{35}"##,
             "Telegram Bot Token detected"),
            // Discord
            (r##"[MN][A-Za-z\\d]{23,}\\.[\\w-]{6}\\.[\\w-]{27}"##,
             "Discord Bot Token detected"),
            // SendGrid
            (r##"SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}"##,
             "SendGrid API Key detected"),
            // Azure
            (r##"[A-Za-z0-9+/]{86}=="##,
             "Azure Shared Key detected (base64 encoded)"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("#") || trimmed.starts_with("'") {
                continue;
            }

            for (pat, desc) in &secret_patterns {
                let re = Regex::new(pat).unwrap();
                if re.is_match(trimmed) {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: line_idx + 1,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: trimmed.to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Remove hardcoded secrets. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// --------------------------------------------------------------------------
// AWS IAM Overly Permissive Policy
// --------------------------------------------------------------------------

pub struct AwsIamOverlyPermissive;

impl LangRule for AwsIamOverlyPermissive {
    fn id(&self) -> &str { "AWS-IAM-001" }
    fn name(&self) -> &str { "AWS IAM Overly Permissive Policy" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let risky_actions = [
            ("s3:*", "S3 full access is overly permissive"),
            ("ec2:*", "EC2 full access is overly permissive"),
            ("iam:*", "IAM full access is extremely dangerous"),
            ("*:\"", "Wildcard (*) in Action allows all actions"),
            ("logs:*", "CloudWatch Logs full access may leak data"),
            ("secretsmanager:*", "Secrets Manager full access exposes all secrets"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            for (action, msg) in &risky_actions {
                if trimmed.contains(action) {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: line_idx + 1,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: trimmed.to_string(),
                        problem: msg.to_string(),
                        fix_hint: "Follow the principle of least privilege. Grant only the specific actions needed.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                    break;
                }
            }
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// --------------------------------------------------------------------------
// Terraform S3 Public Bucket
// --------------------------------------------------------------------------

pub struct TerraformS3PublicBucket;

impl LangRule for TerraformS3PublicBucket {
    fn id(&self) -> &str { "TF-S3-001" }
    fn name(&self) -> &str { "Terraform S3 Bucket Public Access" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let acl_public = Regex::new(r#""acl"\s*=\s*"public-read""#).unwrap();
        let public_bucket = Regex::new(r#""access_control_policy"\s*=\s*\{"#).unwrap();
        let block_public_acls = Regex::new(r#"block_public_acls\s*=\s*false"#).unwrap();
        let block_public_policy = Regex::new(r#"block_public_policy\s*=\s*false"#).unwrap();
        let ignore_public_acls = Regex::new(r#"ignore_public_acls\s*=\s*false"#).unwrap();
        let restrict_public_buckets = Regex::new(r#"restrict_public_buckets\s*=\s*false"#).unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            if acl_public.is_match(trimmed) || public_bucket.is_match(trimmed) {
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: trimmed.to_string(),
                    problem: "S3 bucket configured with public access".to_string(),
                    fix_hint: "Remove public ACL. Enable block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }

            if block_public_acls.is_match(trimmed)
                || block_public_policy.is_match(trimmed)
                || ignore_public_acls.is_match(trimmed)
                || restrict_public_buckets.is_match(trimmed)
            {
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: "high".to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: trimmed.to_string(),
                    problem: "S3 bucket has public access block disabled".to_string(),
                    fix_hint: "Set all public access block options to 'true' to prevent accidental public exposure.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// --------------------------------------------------------------------------
// Kubernetes Privileged Container
// --------------------------------------------------------------------------

pub struct K8sPrivilegedContainer;

impl LangRule for K8sPrivilegedContainer {
    fn id(&self) -> &str { "K8S-001" }
    fn name(&self) -> &str { "Kubernetes Privileged Container" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let privileged = Regex::new(r#"privileged\s*:\s*true"#).unwrap();
        let host_pid = Regex::new(r#"hostPID\s*:\s*true"#).unwrap();
        let host_network = Regex::new(r#"hostNetwork\s*:\s*true"#).unwrap();
        let host_ipc = Regex::new(r#"hostIPC\s*:\s*true"#).unwrap();
        let allow_privilege_escalation = Regex::new(r#"allowPrivilegeEscalation\s*:\s*true"#).unwrap();
        let capabilities_add = Regex::new(r#"capabilities\s*:\s*\n\s*add\s*:\s*\n\s*-\s*\"(SYS_ADMIN|NET_ADMIN|SYS_MODULE|DAC_READ_SEARCH)\""#).unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            if privileged.is_match(trimmed) {
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: trimmed.to_string(),
                    problem: "Container runs in privileged mode (full host access)".to_string(),
                    fix_hint: "Remove 'privileged: true'. Use a minimal container image with read-only root filesystem.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }

            if host_pid.is_match(trimmed) {
                findings.push(LangFinding {
                    rule_id: "K8S-002".to_string(),
                    severity: "high".to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: trimmed.to_string(),
                    problem: "Container shares host PID namespace (process visibility)".to_string(),
                    fix_hint: "Remove 'hostPID: true'. Use process isolation.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }

            if host_network.is_match(trimmed) {
                findings.push(LangFinding {
                    rule_id: "K8S-003".to_string(),
                    severity: "high".to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: trimmed.to_string(),
                    problem: "Container shares host network namespace".to_string(),
                    fix_hint: "Remove 'hostNetwork: true'. Use Kubernetes NetworkPolicy for pod-to-pod communication.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }

            if host_ipc.is_match(trimmed) {
                findings.push(LangFinding {
                    rule_id: "K8S-004".to_string(),
                    severity: "high".to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: trimmed.to_string(),
                    problem: "Container shares host IPC namespace (shared memory access)".to_string(),
                    fix_hint: "Remove 'hostIPC: true'. Use pod-level IPC namespace.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }

            if allow_privilege_escalation.is_match(trimmed) {
                findings.push(LangFinding {
                    rule_id: "K8S-005".to_string(),
                    severity: "high".to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: trimmed.to_string(),
                    problem: "Container allows privilege escalation".to_string(),
                    fix_hint: "Set 'allowPrivilegeEscalation: false' and run as non-root user.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }

            if capabilities_add.is_match(trimmed) {
                findings.push(LangFinding {
                    rule_id: "K8S-006".to_string(),
                    severity: "high".to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: trimmed.to_string(),
                    problem: "Container adds dangerous Linux capabilities".to_string(),
                    fix_hint: "Remove dangerous capabilities (SYS_ADMIN, NET_ADMIN). Only add the minimum required capabilities.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// --------------------------------------------------------------------------
// Kubernetes HostPath Mount
// --------------------------------------------------------------------------

pub struct K8sHostPathMount;

impl LangRule for K8sHostPathMount {
    fn id(&self) -> &str { "K8S-007" }
    fn name(&self) -> &str { "Kubernetes HostPath Volume Mount" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let hostpath = Regex::new(r#"hostPath\s*:\s*\n\s*path\s*:\s*\"([^\"]+)\""#).unwrap();
        let dangerous_paths = [
            "/", "/etc", "/root", "/var/run/docker.sock",
            "/proc", "/sys", "/boot", "/dev",
            "/宿",  // /run/systemd
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            let context: String = code.lines().skip(line_idx.saturating_sub(5)).take(10).collect::<Vec<_>>().join("\n");

            if let Some(caps) = hostpath.captures(&context) {
                if let Some(path_match) = caps.get(1) {
                    let path = path_match.as_str();
                    if dangerous_paths.iter().any(|dp| path == *dp || path.starts_with(&format!("{}/", dp))) {
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: line_idx + 1,
                            column: 0,
                            start_byte: 0,
                            end_byte: 0,
                            snippet: trimmed.to_string(),
                            problem: format!("HostPath mount accesses sensitive host path: {}", path),
                            fix_hint: "Avoid HostPath volumes. Use emptyDir with a different storage type, or a CSI driver.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                    }
                }
            }
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// --------------------------------------------------------------------------
// Dockerfile USER Directive (Running as Root)
// --------------------------------------------------------------------------

pub struct DockerfileUserRoot;

impl LangRule for DockerfileUserRoot {
    fn id(&self) -> &str { "DOCKER-001" }
    fn name(&self) -> &str { "Dockerfile Runs as Root User" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let user_root = Regex::new(r#"^\s*USER\s+(root|0|:0)($|\s)"#).unwrap();

        let mut last_from_line = 0;
        let mut has_user_directive = false;

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("FROM") {
                last_from_line = line_idx;
                has_user_directive = false;
            }
            if trimmed.starts_with("USER") {
                has_user_directive = true;
                if user_root.is_match(trimmed) {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: line_idx + 1,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: trimmed.to_string(),
                        problem: "Docker container runs as root user".to_string(),
                        fix_hint: "Create a non-root user: 'RUN adduser -D appuser' and 'USER appuser'.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        // Flag if no USER directive at all (implies root)
        if !has_user_directive && last_from_line > 0 {
            // Check if there are any USER directives at all
            let any_user = code.lines().any(|l| l.trim().starts_with("USER"));
            if !any_user {
                // This is a heuristic - most images default to root
                findings.push(LangFinding {
                    rule_id: "DOCKER-002".to_string(),
                    severity: "low".to_string(),
                    line: last_from_line + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: code.lines().nth(last_from_line).unwrap_or("").trim().to_string(),
                    problem: "Dockerfile has no USER directive (defaults to root)".to_string(),
                    fix_hint: "Add a USER directive to run as non-root: 'RUN adduser -D appuser && USER appuser'.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// --------------------------------------------------------------------------
// Dockerfile HEALTHCHECK Missing
// --------------------------------------------------------------------------

pub struct DockerfileMissingHealthcheck;

impl LangRule for DockerfileMissingHealthcheck {
    fn id(&self) -> &str { "DOCKER-003" }
    fn name(&self) -> &str { "Dockerfile Missing HEALTHCHECK" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let has_healthcheck = Regex::new(r"(?i)^\s*HEALTHCHECK").unwrap();
        let from_pattern = Regex::new(r"(?i)^\s*FROM\s+(?!scratch)").unwrap();
        let is_scratch = Regex::new(r"(?i)^\s*FROM\s+scratch").unwrap();

        let mut has_healthcheck_directive = false;
        let mut has_non_scratch_base = false;
        let mut base_line = 0;

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if has_healthcheck.is_match(trimmed) {
                has_healthcheck_directive = true;
            }
            if from_pattern.is_match(trimmed) {
                has_non_scratch_base = true;
                base_line = line_idx + 1;
            }
            if is_scratch.is_match(trimmed) {
                has_non_scratch_base = false;
            }
        }

        if has_non_scratch_base && !has_healthcheck_directive {
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: base_line,
                column: 0,
                start_byte: 0,
                end_byte: 0,
                snippet: code.lines().nth(base_line - 1).unwrap_or("").trim().to_string(),
                problem: "Dockerfile has no HEALTHCHECK directive".to_string(),
                fix_hint: "Add HEALTHCHECK to enable container health monitoring: 'HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1'.".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// --------------------------------------------------------------------------
// GitHub Actions Secret Exposure
// --------------------------------------------------------------------------

pub struct GithubActionsSecretExposure;

impl LangRule for GithubActionsSecretExposure {
    fn id(&self) -> &str { "GHACTION-001" }
    fn name(&self) -> &str { "GitHub Actions Secret Exposure in Logs" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect echo/print of known secret patterns
        let echo_secret = Regex::new(r#"(?i)(echo|print|::(debug|notice|warning|error))\s+['\"]?.*(\${{.*secrets\.|secrets\.|AWS_|GITHUB_|PAT_|TOKEN_|API_KEY)"#).unwrap();
        // Detect set -x (verbose shell) which exposes variables
        let verbose_shell = Regex::new(r#"(?i)^\s*set\s+-x\s*$"#).unwrap();
        // Detect curl/wget with secrets in URL
        let curl_with_secret = Regex::new(r#"(?i)(curl|wget)\s+.*['\"]?https?://[^'\"\\s]*[\?\&](api_key|token|key|secret|password)=[^'\"\\s]*['\"]?"#).unwrap();
        // Detect ::add-mask but missing secrets
        let _mask_but_expose = Regex::new(r#"(?i)::add-mask::.*"#).unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            if echo_secret.is_match(trimmed) && !trimmed.contains("::add-mask::") {
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: trimmed.to_string(),
                    problem: "GitHub Actions may expose secret value in workflow logs".to_string(),
                    fix_hint: "Use '::add-mask::' before echoing secrets, or use '${{ secrets.SECRET_NAME }}' in a context that auto-masks.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }

            if verbose_shell.is_match(trimmed) {
                findings.push(LangFinding {
                    rule_id: "GHACTION-002".to_string(),
                    severity: "high".to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: trimmed.to_string(),
                    problem: "'set -x' causes verbose shell output that exposes variable values in logs".to_string(),
                    fix_hint: "Remove 'set -x' or use it only in non-secret contexts.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }

            if curl_with_secret.is_match(trimmed) {
                findings.push(LangFinding {
                    rule_id: "GHACTION-003".to_string(),
                    severity: "critical".to_string(),
                    line: line_idx + 1,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: trimmed.to_string(),
                    problem: "Secret embedded in URL query parameter may appear in logs".to_string(),
                    fix_hint: "Use headers instead of query params for secrets: -H 'Authorization: Bearer ${{ secrets.TOKEN }}'.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// --------------------------------------------------------------------------
// Registry
// --------------------------------------------------------------------------

pub fn infrastructure_security_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(GitSecretsPattern),
        Box::new(AwsIamOverlyPermissive),
        Box::new(TerraformS3PublicBucket),
        Box::new(K8sPrivilegedContainer),
        Box::new(K8sHostPathMount),
        Box::new(DockerfileUserRoot),
        Box::new(DockerfileMissingHealthcheck),
        Box::new(GithubActionsSecretExposure),
    ]
}
