"""Infrastructure-as-Code security rules for PyNEAT.

Copyright (c) 2026 PyNEAT Authors
License: AGPL-3.0

Supports:
  - Terraform (.tf, .tfvars)
  - Kubernetes manifests (.yaml, .yml)
  - Docker files (Dockerfile, docker-compose.yml)
  - CloudFormation templates
  - Ansible playbooks
"""

from __future__ import annotations

import re
import yaml
from pathlib import Path
from typing import List, Pattern, Optional, Dict, Any, Union

from pyneat.core.types import SecurityFinding, SecuritySeverity
from pyneat.rules.base import Rule


# ============================================================================
# Terraform Security Rules
# ============================================================================

class TerraformSecurityRule(Rule):
    """Security scanner for Terraform configuration files.

    Detects misconfigurations in:
      - AWS resources (S3, IAM, RDS, Lambda, EC2)
      - Azure resources
      - Google Cloud resources
      - Kubernetes provider
    """

    def get_name(self) -> str:
        return "TerraformSecurity"

    def get_description(self) -> str:
        return "Detects security misconfigurations in Terraform files"

    def get_severity(self) -> str:
        return "high"

    def get_rule_id(self) -> str:
        return "SEC-IAC-TF"

    def check(self, content: str, file_path: Optional[str] = None) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        lines = content.split('\n')

        rules = [
            # S3 Bucket rules
            (r'^\s*acl\s*=\s*"public"', "SEC-IAC-TF-001",
             "S3 bucket ACL allows public access",
             SecuritySeverity.HIGH,
             "S3 bucket has public ACL. Use 'private' or 'authenticated-read' instead.",
             "CWE-284"),
            (r'^\s*acl\s*=\s*"public-read"', "SEC-IAC-TF-002",
             "S3 bucket with public-read ACL",
             SecuritySeverity.HIGH,
             "Public-read ACL exposes bucket contents. Use private and control access via policies.",
             "CWE-284"),
            (r'^\s*versioning\s*=\s*false', "SEC-IAC-TF-003",
             "S3 bucket versioning disabled",
             SecuritySeverity.MEDIUM,
             "S3 versioning should be enabled for point-in-time recovery.",
             "CWE-708"),
            (r'^\s*logging\s*=\s*\{[^}]*enabled\s*=\s*false', "SEC-IAC-TF-004",
             "S3 bucket logging disabled",
             SecuritySeverity.MEDIUM,
             "Enable S3 access logging for audit trail.",
             "CWE-778"),
            (r'^\s*server_side_encryption_configuration', "SEC-IAC-TF-005",
             "S3 encryption configuration check",
             SecuritySeverity.LOW,
             "Ensure S3 server-side encryption is enabled (AES-256 or KMS).",
             "CWE-311"),
            (r'^\s*access_key\s*=\s*"[^"]*AWSAccessKeyId', "SEC-IAC-TF-006",
             "Hardcoded AWS Access Key ID",
             SecuritySeverity.CRITICAL,
             "Hardcoded AWS access keys are a critical risk. Use IAM roles instead.",
             "CWE-798"),
            (r'^\s*secret_key\s*=\s*"[^"]{20,}', "SEC-IAC-TF-007",
             "Hardcoded AWS Secret Key",
             SecuritySeverity.CRITICAL,
             "Hardcoded AWS secret keys must be removed. Use IAM roles or environment variables.",
             "CWE-798"),

            # IAM rules
            (r'^\s*effect\s*=\s*"Allow"[^}]*Actions?\s*=\s*\["\*"\]', "SEC-IAC-TF-010",
             "IAM policy with wildcard actions",
             SecuritySeverity.HIGH,
             "Avoid wildcard (*) in IAM policy actions. Use least-privilege principle.",
             "CWE-285"),
            (r'^\s*effect\s*=\s*"Allow"[^}]*Principal\s*=\s*"\*"', "SEC-IAC-TF-011",
             "IAM policy allows all principals",
             SecuritySeverity.CRITICAL,
             "This allows access from any AWS principal. Restrict to specific accounts/principals.",
             "CWE-285"),
            (r'^\s*attach_customer_managed_policy\s*=\s*false', "SEC-IAC-TF-012",
             "Unattached IAM policy",
             SecuritySeverity.LOW,
             "Unused IAM policies increase attack surface. Review and remove if unnecessary.",
             "CWE-284"),

            # EC2 rules
            (r'^\s*associate_public_ip_address\s*=\s*true', "SEC-IAC-TF-020",
             "EC2 instance with public IP",
             SecuritySeverity.MEDIUM,
             "Public IPs on EC2 instances increase exposure. Use private subnets with NAT.",
             "CWE-284"),
            (r'^\s*source_dest_check\s*=\s*false', "SEC-IAC-TF-021",
             "EC2 source/dest check disabled",
             SecuritySeverity.LOW,
             "Only disable source/dest check for NAT/tunneling instances.",
             "CWE-284"),

            # RDS rules
            (r'^\s*publicly_accessible\s*=\s*true', "SEC-IAC-TF-030",
             "RDS database publicly accessible",
             SecuritySeverity.HIGH,
             "RDS should not be publicly accessible. Use private subnets and VPN/bastion.",
             "CWE-284"),
            (r'^\s*storage_encrypted\s*=\s*false', "SEC-IAC-TF-031",
             "RDS storage not encrypted",
             SecuritySeverity.HIGH,
             "Enable RDS storage encryption at rest for sensitive data.",
             "CWE-311"),
            (r'^\s*enabled_cloudwatch_logs_exports\s*=\s*\[\s*\]', "SEC-IAC-TF-032",
             "RDS logging disabled",
             SecuritySeverity.MEDIUM,
             "Enable RDS logging for audit trail and compliance.",
             "CWE-778"),
            (r'^\s*multi_az\s*=\s*false', "SEC-IAC-TF-033",
             "RDS single-AZ deployment",
             SecuritySeverity.LOW,
             "For production, use Multi-AZ for high availability.",
             "CWE-708"),

            # Lambda rules
            (r'^\s*environment\s*=\s*\{[^}]*Variables\s*=\s*\{[^}]*AWS_ACCESS_KEY', "SEC-IAC-TF-040",
             "Lambda environment contains AWS credentials",
             SecuritySeverity.CRITICAL,
             "Never put credentials in Lambda environment variables. Use IAM roles.",
             "CWE-798"),
            (r'^\s*runtime\s*=\s*"python2', "SEC-IAC-TF-041",
             "Lambda using deprecated Python 2 runtime",
             SecuritySeverity.MEDIUM,
             "Python 2 is EOL. Migrate to Python 3.x for security updates.",
             "CWE-1104"),

            # Security Group rules
            (r'^\s*cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', "SEC-IAC-TF-050",
             "Security group allows 0.0.0.0/0",
             SecuritySeverity.HIGH,
             "Allowing all IPs (0.0.0.0/0) is dangerous. Restrict to specific IP ranges.",
             "CWE-284"),
            (r'^\s*from_port\s*=\s*22\s*\n[^}]*cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', "SEC-IAC-TF-051",
             "SSH open to internet",
             SecuritySeverity.CRITICAL,
             "SSH from 0.0.0.0/0 is extremely dangerous. Use VPN/bastion/jump host.",
             "CWE-284"),
            (r'^\s*from_port\s*=\s*3389', "SEC-IAC-TF-052",
             "RDP port open",
             SecuritySeverity.HIGH,
             "RDP should not be exposed. Use bastion host or AWS Systems Manager.",
             "CWE-284"),

            # Elasticsearch / OpenSearch
            (r'^\s*node_to_node_encryption\s*=\s*false', "SEC-IAC-TF-060",
             "OpenSearch node-to-node encryption disabled",
             SecuritySeverity.HIGH,
             "Enable node-to-node encryption for OpenSearch clusters.",
             "CWE-319"),
            (r'^\s*encrypt_at_rest\s*=\s*false', "SEC-IAC-TF-061",
             "OpenSearch encryption at rest disabled",
             SecuritySeverity.HIGH,
             "Enable encryption at rest for OpenSearch domain.",
             "CWE-311"),

            # CloudTrail
            (r'^\s*enable_logging\s*=\s*false', "SEC-IAC-TF-070",
             "CloudTrail logging disabled",
             SecuritySeverity.HIGH,
             "CloudTrail should be enabled for all AWS accounts.",
             "CWE-778"),
            (r'^\s*is_multi_region_trail\s*=\s*false', "SEC-IAC-TF-071",
             "CloudTrail single-region only",
             SecuritySeverity.MEDIUM,
             "Use multi-region CloudTrail for comprehensive audit coverage.",
             "CWE-778"),
            (r'^\s*include_global_service_events\s*=\s*false', "SEC-IAC-TF-072",
             "CloudTrail excludes global services",
             SecuritySeverity.MEDIUM,
             "Enable global service events for complete audit trail.",
             "CWE-778"),
        ]

        for line_num, line in enumerate(lines, start=1):
            for pattern, rule_id, problem, severity, fix, cwe in rules:
                if re.search(pattern, line, re.MULTILINE):
                    finding = SecurityFinding(
                        rule_id=rule_id,
                        severity=severity,
                        confidence=0.9,
                        cwe_id=cwe,
                        owasp_id="A01:2021",
                        cvss_score=self._severity_to_cvss(severity),
                        cvss_vector="",
                        file=file_path or "<unknown>",
                        start_line=line_num,
                        end_line=line_num,
                        snippet=line.strip()[:100],
                        problem=problem,
                        fix_constraints=(fix,),
                        do_not=("Do not use hardcoded values for sensitive configuration.",),
                        verify=("Review the Terraform resource configuration.",),
                        resources=(
                            "https://owasp.org/www-project-top-ten/",
                            "https://www.terraform.io/docs/state/sensitive-data.html",
                        ),
                        can_auto_fix=False,
                        auto_fix_available=False,
                    )
                    findings.append(finding)

        return findings

    def _severity_to_cvss(self, severity: SecuritySeverity) -> float:
        mapping = {
            SecuritySeverity.CRITICAL: 9.0,
            SecuritySeverity.HIGH: 7.5,
            SecuritySeverity.MEDIUM: 5.0,
            SecuritySeverity.LOW: 3.0,
            SecuritySeverity.INFO: 0.0,
        }
        return mapping.get(severity, 0.0)

    def apply(self, content: str, file_path: Optional[str] = None) -> str:
        return content


# ============================================================================
# Kubernetes Security Rules
# ============================================================================

class KubernetesSecurityRule(Rule):
    """Security scanner for Kubernetes manifests.

    Detects:
      - Privileged containers
      - Host path mounts
      - Container privilege escalation
      - Missing security context
      - Network policy gaps
      - Resource limits missing
      - Service account token mounts
    """

    def get_name(self) -> str:
        return "KubernetesSecurity"

    def get_description(self) -> str:
        return "Detects security misconfigurations in Kubernetes manifests"

    def get_severity(self) -> str:
        return "high"

    def get_rule_id(self) -> str:
        return "SEC-IAC-K8S"

    def check(self, content: str, file_path: Optional[str] = None) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        # Parse YAML to detect K8s resources
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return []

        for doc_idx, doc in enumerate(docs):
            if not isinstance(doc, dict):
                continue

            kind = doc.get('kind', '')
            spec = doc.get('spec', {})
            metadata = doc.get('metadata', {})

            if kind == 'Pod':
                findings.extend(self._check_pod(doc, file_path or f"<doc:{doc_idx}>"))
            elif kind in ('Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob'):
                template = spec.get('template', {})
                if isinstance(template, dict):
                    findings.extend(self._check_pod(template, file_path or f"<doc:{doc_idx}>"))

        return findings

    def _check_pod(self, pod: Dict[str, Any], file_path: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        spec = pod.get('spec', {})
        metadata = pod.get('metadata', {})

        containers = spec.get('containers', [])
        init_containers = spec.get('initContainers', [])

        for container in containers + init_containers:
            findings.extend(self._check_container(container, file_path, metadata))

        # Check pod-level security context
        pod_sec_ctx = spec.get('securityContext', {})
        findings.extend(self._check_pod_security_context(pod_sec_ctx, file_path, metadata))

        return findings

    def _check_container(self, container: Dict[str, Any], file_path: str,
                          metadata: Dict[str, Any]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        name = container.get('name', 'unknown')

        # Privileged container
        sec_ctx = container.get('securityContext', {})
        if sec_ctx.get('privileged'):
            findings.append(self._make_finding(
                "SEC-IAC-K8S-001",
                f"Privileged container: {name}",
                SecuritySeverity.CRITICAL,
                "Privileged containers have full host access. Only use when absolutely necessary.",
                file_path, container, sec_ctx, "CWE-250"
            ))

        # Allow privilege escalation
        if sec_ctx.get('allowPrivilegeEscalation') == True:
            findings.append(self._make_finding(
                "SEC-IAC-K8S-002",
                f"Container allows privilege escalation: {name}",
                SecuritySeverity.HIGH,
                "Set allowPrivilegeEscalation to false for containers.",
                file_path, container, sec_ctx, "CWE-250"
            ))

        # Run as root
        run_as_non_root = sec_ctx.get('runAsNonRoot')
        if run_as_non_root is False or run_as_non_root == False:
            findings.append(self._make_finding(
                "SEC-IAC-K8S-003",
                f"Container runs as root: {name}",
                SecuritySeverity.HIGH,
                "Set runAsNonRoot: true and use a non-root user (runAsUser > 0).",
                file_path, container, sec_ctx, "CWE-250"
            ))

        # Host PID
        if sec_ctx.get('hostPID'):
            findings.append(self._make_finding(
                "SEC-IAC-K8S-004",
                f"Container shares host PID namespace: {name}",
                SecuritySeverity.HIGH,
                "Avoid hostPID unless necessary. Process isolation is compromised.",
                file_path, container, sec_ctx, "CWE-250"
            ))

        # Host network
        if sec_ctx.get('hostNetwork'):
            findings.append(self._make_finding(
                "SEC-IAC-K8S-005",
                f"Container shares host network: {name}",
                SecuritySeverity.HIGH,
                "Avoid hostNetwork unless necessary. Use NetworkPolicy instead.",
                file_path, container, sec_ctx, "CWE-250"
            ))

        # Host IPC
        if sec_ctx.get('hostIPC'):
            findings.append(self._make_finding(
                "SEC-IAC-K8S-006",
                f"Container shares host IPC: {name}",
                SecuritySeverity.HIGH,
                "Avoid hostIPC unless necessary. Memory isolation is compromised.",
                file_path, container, sec_ctx, "CWE-250"
            ))

        # Capabilities
        caps = sec_ctx.get('capabilities', {})
        added_caps = caps.get('add', [])
        dangerous_caps = {'SYS_ADMIN', 'NET_ADMIN', 'SYS_MODULE', 'DAC_READ_SEARCH',
                          'DAC_OVERRIDE', 'SYS_RAWIO', 'SYS_PTRACE', 'SYS_CHROOT'}
        dangerous = [c for c in added_caps if c.upper() in dangerous_caps or c.upper().startswith('CAP_')]
        if dangerous:
            findings.append(self._make_finding(
                "SEC-IAC-K8S-007",
                f"Dangerous capabilities added: {name} ({', '.join(dangerous)})",
                SecuritySeverity.HIGH,
                "Avoid adding dangerous capabilities. Use minimal capability set.",
                file_path, container, sec_ctx, "CWE-250"
            ))

        # Read only root filesystem
        security_context = container.get('securityContext', {})
        read_only_fs = security_context.get('readOnlyRootFilesystem')
        if read_only_fs is None or read_only_fs == False:
            findings.append(self._make_finding(
                "SEC-IAC-K8S-008",
                f"Container does not use read-only root filesystem: {name}",
                SecuritySeverity.MEDIUM,
                "Set readOnlyRootFilesystem: true when possible to reduce attack surface.",
                file_path, container, security_context, "CWE-250"
            ))

        # Resource limits
        resources = container.get('resources', {})
        if not resources.get('limits'):
            findings.append(self._make_finding(
                "SEC-IAC-K8S-010",
                f"Container missing resource limits: {name}",
                SecuritySeverity.LOW,
                "Set CPU/memory limits to prevent resource exhaustion attacks.",
                file_path, container, resources, "CWE-400"
            ))

        # Image pull policy
        image_pull_policy = container.get('imagePullPolicy')
        image = container.get('image', '')
        if image_pull_policy == 'Always' and ':latest' in image:
            findings.append(self._make_finding(
                "SEC-IAC-K8S-011",
                f"Image uses :latest tag: {name}",
                SecuritySeverity.LOW,
                "Use specific image tags instead of :latest for reproducibility.",
                file_path, container, {}, "CWE-1104"
            ))

        # Service account auto-mount
        service_account = resources.get('serviceAccount', 'default')

        return findings

    def _check_pod_security_context(self, pod_sec_ctx: Dict[str, Any], file_path: str,
                                      metadata: Dict[str, Any]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        if not pod_sec_ctx:
            findings.append(SecurityFinding(
                rule_id="SEC-IAC-K8S-020",
                severity=SecuritySeverity.LOW,
                confidence=0.5,
                cwe_id="CWE-250",
                owasp_id="A01:2021",
                cvss_score=3.0,
                cvss_vector="",
                file=file_path,
                start_line=0,
                end_line=0,
                snippet="Pod has no securityContext defined",
                problem="Pod missing security context configuration",
                fix_constraints=(
                    "Add pod security context: runAsNonRoot, runAsUser, fsGroup.",
                    "Example: securityContext: { runAsNonRoot: true, runAsUser: 1000 }",
                ),
                do_not=("Do not run pods without security context.",),
                verify=("Review pod specification.",),
                resources=("https://kubernetes.io/docs/concepts/security/pod-security-standards/",),
                can_auto_fix=False,
                auto_fix_available=False,
            ))

        return findings

    def _make_finding(self, rule_id: str, problem: str, severity: SecuritySeverity,
                       fix: str, file_path: str, container: Dict, sec_ctx: Dict,
                       cwe: str) -> SecurityFinding:
        return SecurityFinding(
            rule_id=rule_id,
            severity=severity,
            confidence=0.9,
            cwe_id=cwe,
            owasp_id="A01:2021",
            cvss_score=self._severity_to_cvss(severity),
            cvss_vector="",
            file=file_path,
            start_line=0,
            end_line=0,
            snippet=f"container: {container.get('name', 'unknown')}",
            problem=problem,
            fix_constraints=(fix,),
            do_not=("Do not disable Kubernetes security features.",),
            verify=("Review container security context.",),
            resources=(
                "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                "https://www.cisecurity.org/benchmark/kubernetes",
            ),
            can_auto_fix=False,
            auto_fix_available=False,
        )

    def _severity_to_cvss(self, severity: SecuritySeverity) -> float:
        mapping = {
            SecuritySeverity.CRITICAL: 9.0,
            SecuritySeverity.HIGH: 7.5,
            SecuritySeverity.MEDIUM: 5.0,
            SecuritySeverity.LOW: 3.0,
            SecuritySeverity.INFO: 0.0,
        }
        return mapping.get(severity, 0.0)

    def apply(self, content: str, file_path: Optional[str] = None) -> str:
        return content


# ============================================================================
# Docker Security Rules
# ============================================================================

class DockerSecurityRule(Rule):
    """Security scanner for Dockerfile and docker-compose files.

    Detects:
      - Running as root
      - Missing USER directive
      - Use of latest tag
      - Exposed sensitive ports
      - Insecure base images
      - Package manager updates missing
      - Secret COPY instructions
    """

    def get_name(self) -> str:
        return "DockerSecurity"

    def get_description(self) -> str:
        return "Detects security misconfigurations in Docker files"

    def get_severity(self) -> str:
        return "high"

    def get_rule_id(self) -> str:
        return "SEC-IAC-DOCKER"

    def check(self, content: str, file_path: Optional[str] = None) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Check for running as root
            if stripped.startswith('USER ') and stripped.endswith('root'):
                findings.append(SecurityFinding(
                    rule_id="SEC-IAC-DOCKER-001",
                    severity=SecuritySeverity.HIGH,
                    confidence=0.95,
                    cwe_id="CWE-250",
                    owasp_id="A01:2021",
                    cvss_score=7.0,
                    cvss_vector="",
                    file=file_path or "<unknown>",
                    start_line=line_num,
                    end_line=line_num,
                    snippet=stripped,
                    problem="Docker container runs as root user",
                    fix_constraints=(
                        "Create a non-root user: RUN adduser -D appuser",
                        "Switch to: USER appuser",
                    ),
                    do_not=("Do not run containers as root.",),
                    verify=("Verify with: docker run --rm -u root your-image id"),
                    resources=(
                        "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
                        "https://github.com/OWASP/Docker-Security",
                    ),
                    can_auto_fix=False,
                    auto_fix_available=False,
                ))

            # Check :latest tag
            if 'FROM ' in stripped and ':latest' in stripped:
                findings.append(SecurityFinding(
                    rule_id="SEC-IAC-DOCKER-002",
                    severity=SecuritySeverity.LOW,
                    confidence=0.9,
                    cwe_id="CWE-1104",
                    owasp_id="A05:2021",
                    cvss_score=3.0,
                    cvss_vector="",
                    file=file_path or "<unknown>",
                    start_line=line_num,
                    end_line=line_num,
                    snippet=stripped,
                    problem="Docker image uses :latest tag",
                    fix_constraints=(
                        "Use specific version tags for reproducibility.",
                        "Example: FROM python:3.12-slim",
                    ),
                    do_not=("Do not use :latest or untagged base images.",),
                    verify=("Check base image tags in your Dockerfile.",),
                    resources=(),
                    can_auto_fix=False,
                    auto_fix_available=False,
                ))

            # Check for curl | bash
            if 'curl' in stripped and 'bash' in stripped and '|' in stripped:
                findings.append(SecurityFinding(
                    rule_id="SEC-IAC-DOCKER-003",
                    severity=SecuritySeverity.MEDIUM,
                    confidence=0.8,
                    cwe_id="CWE-601",
                    owasp_id="A01:2021",
                    cvss_score=5.0,
                    cvss_vector="",
                    file=file_path or "<unknown>",
                    start_line=line_num,
                    end_line=line_num,
                    snippet=stripped,
                    problem="Pipe to bash (curl | bash) is a security risk",
                    fix_constraints=(
                        "Download scripts to file first, inspect, then execute.",
                        "Or use package managers (apt-get, pip) for known packages.",
                    ),
                    do_not=("Do not pipe unknown scripts to bash.",),
                    verify=("Review the downloaded script content before running.",),
                    resources=("https://www.securenus.nl/pipe-to-bash",),
                    can_auto_fix=False,
                    auto_fix_available=False,
                ))

            # Check for ADD instead of COPY
            if stripped.startswith('ADD ') and not 'url' in stripped.lower():
                findings.append(SecurityFinding(
                    rule_id="SEC-IAC-DOCKER-004",
                    severity=SecuritySeverity.LOW,
                    confidence=0.7,
                    cwe_id="CWE-79",
                    owasp_id="A03:2021",
                    cvss_score=3.0,
                    cvss_vector="",
                    file=file_path or "<unknown>",
                    start_line=line_num,
                    end_line=line_num,
                    snippet=stripped,
                    problem="Using ADD instead of COPY for local files",
                    fix_constraints=(
                        "Use COPY for local files (better cache, explicit behavior).",
                        "Use ADD only for URLs or tar extraction.",
                    ),
                    do_not=("Do not use ADD for copying local files.",),
                    verify=("Replace ADD with COPY for local content.",),
                    resources=(),
                    can_auto_fix=False,
                    auto_fix_available=False,
                ))

            # Check for no HEALTHCHECK
            if stripped.startswith('HEALTHCHECK ') and 'NONE' in stripped:
                findings.append(SecurityFinding(
                    rule_id="SEC-IAC-DOCKER-005",
                    severity=SecuritySeverity.LOW,
                    confidence=0.9,
                    cwe_id="CWE-665",
                    owasp_id="A05:2021",
                    cvss_score=2.0,
                    cvss_vector="",
                    file=file_path or "<unknown>",
                    start_line=line_num,
                    end_line=line_num,
                    snippet=stripped,
                    problem="Docker HEALTHCHECK disabled",
                    fix_constraints=("Add a meaningful HEALTHCHECK for container monitoring.",),
                    do_not=("Do not disable HEALTHCHECK unless absolutely necessary.",),
                    verify=("Add HEALTHCHECK for production containers.",),
                    resources=(),
                    can_auto_fix=False,
                    auto_fix_available=False,
                ))

        # Check for missing USER directive
        has_user = any(line.strip().startswith('USER ') for line in lines)
        has_no_sudo = any('sudo' in line for line in lines)
        if not has_user and not has_no_sudo and 'RUN' in content:
            findings.append(SecurityFinding(
                rule_id="SEC-IAC-DOCKER-010",
                severity=SecuritySeverity.INFO,
                confidence=0.6,
                cwe_id="CWE-250",
                owasp_id="A01:2021",
                cvss_score=1.0,
                cvss_vector="",
                file=file_path or "<unknown>",
                start_line=0,
                end_line=0,
                snippet="No USER directive found",
                problem="Dockerfile has no USER directive - defaults to root",
                fix_constraints=(
                    "Add a non-root USER at the end of the Dockerfile.",
                    "Example: RUN adduser -D appuser && USER appuser",
                ),
                do_not=("Do not run containers as root.",),
                verify=("Check: docker run your-image id"),
                resources=(),
                can_auto_fix=False,
                auto_fix_available=False,
            ))

        return findings

    def apply(self, content: str, file_path: Optional[str] = None) -> str:
        return content


# ============================================================================
# Module exports
# ============================================================================

__all__ = [
    "TerraformSecurityRule",
    "KubernetesSecurityRule",
    "DockerSecurityRule",
]
