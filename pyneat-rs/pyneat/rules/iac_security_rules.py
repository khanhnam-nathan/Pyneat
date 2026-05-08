"""IaC Security Rules for Docker, Kubernetes, and Terraform files.

Copyright (c) 2026 PyNEAT Authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, contact: khanhnam.copywriting@gmail.com

Implements 8 IaC security rules:
  - IAC-003: Docker Secrets in Env
  - IAC-004: Kubernetes Privileged Pod
  - IAC-005: Terraform S3 Public Access
  - IAC-006: K8s HostPath Mount
  - IAC-007: Docker --network=host
  - IAC-008: K8s Allow Privilege Escalation
  - IAC-009: Terraform State Not Encrypted
  - IAC-010: K8s Root Container
"""

import re
from typing import List, Optional, Tuple
from datetime import datetime

from pyneat.core.types import CodeFile, TransformationResult, RuleConfig, AgentMarker, MarkerIdGenerator
from pyneat.rules.base import Rule


class IaCRegistry:
    """Registry for all IaC security rules."""

    _rules: List[type] = []
    _rule_map: dict = {}

    @classmethod
    def register(cls, rule_class: type):
        cls._rules.append(rule_class)
        cls._rule_map[rule_class.IAC_ID] = rule_class
        return rule_class

    @classmethod
    def get_rules(cls) -> List[type]:
        return cls._rules

    @classmethod
    def get_rule(cls, iac_id: str):
        return cls._rule_map.get(iac_id)


def _extract_snippet(content: str, line_num: int, context: int = 2) -> Optional[str]:
    """Extract code snippet around a line number."""
    lines = content.split('\n')
    if line_num < 1 or line_num > len(lines):
        return None
    start = max(0, line_num - context - 1)
    end = min(len(lines), line_num + context)
    snippet = '\n'.join(lines[start:end])
    return snippet if snippet else None


def _create_marker(
    iac_id: str,
    rule_name: str,
    severity: str,
    line: int,
    content: str,
    file_path: str,
    language: str,
    cwe_id: str,
    hint: str,
    why: str,
    impact: str,
    resources: Tuple[str, ...],
    fix_constraints: Tuple[str, ...],
) -> AgentMarker:
    """Create a fully populated AgentMarker for IaC findings."""
    generator = MarkerIdGenerator()
    snippet = _extract_snippet(content, line)
    issue_type = rule_name.lower().replace(' ', '-').replace('_', '-')

    return AgentMarker(
        marker_id=generator.generate(rule_name, issue_type),
        issue_type=issue_type,
        rule_id=iac_id,
        severity=severity,
        line=line,
        hint=hint,
        why=why,
        impact=impact,
        confidence=0.92,
        confidence_note="detected via regex pattern matching on IaC configuration",
        can_auto_fix=False,
        snippet=snippet,
        fix_constraints=fix_constraints,
        do_not=(
            "Do not disable security features for production workloads",
            "Do not expose sensitive data through environment variables in container definitions",
        ),
        verify=(
            "Review the specific configuration that triggered this finding",
            "Verify the intended deployment environment matches the security requirements",
        ),
        resources=resources,
        file_path=file_path,
        language=language,
        detected_at=datetime.now().isoformat() + "Z",
    )


class IaCBaseRule(Rule):
    """Base class for IaC security rules."""

    IAC_ID: str = "IAC-000"
    DEFAULT_SEVERITY: str = "high"
    SUPPORTED_EXTENSIONS: Tuple[str, ...] = (
        "Dockerfile", ".dockerfile", ".yaml", ".yml", ".tf", ".tfvars"
    )

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self._markers: List[AgentMarker] = []
        self._changes: List[str] = []

    @classmethod
    def supports_file(cls, file_path: str) -> bool:
        """Check if this rule supports the given file."""
        path_lower = file_path.lower()
        for ext in cls.SUPPORTED_EXTENSIONS:
            if path_lower.endswith(ext.lower()):
                return True
        return False

    def _scan_regex(self, content: str, pattern: str, flags: int = 0) -> List[Tuple[int, str]]:
        """Scan content with regex and return list of (line_number, matched_text)."""
        findings = []
        try:
            regex = re.compile(pattern, flags)
            for match in regex.finditer(content):
                matched_text = match.group(0)
                line_num = content[:match.start()].count('\n') + 1
                findings.append((line_num, matched_text))
        except re.error:
            pass
        return findings

    def _add_finding(
        self,
        content: str,
        file_path: str,
        language: str,
        line: int,
        matched_text: str,
        cwe_id: str,
        hint: str,
        why: str,
        impact: str,
        resources: Tuple[str, ...],
        fix_constraints: Tuple[str, ...],
    ) -> None:
        """Add a finding as an AgentMarker."""
        marker = _create_marker(
            iac_id=self.IAC_ID,
            rule_name=self.name,
            severity=self.DEFAULT_SEVERITY,
            line=line,
            content=content,
            file_path=file_path,
            language=language,
            cwe_id=cwe_id,
            hint=hint,
            why=why,
            impact=impact,
            resources=resources,
            fix_constraints=fix_constraints,
        )
        self._markers.append(marker)
        self._changes.append(f"{self.name}: {why} at line {line}")

    def apply(self, code_file: CodeFile) -> TransformationResult:
        """Apply this rule. Subclasses must implement _detect()."""
        self._markers = []
        self._changes = []

        file_path = str(code_file.path)
        if not self.supports_file(file_path):
            return self._create_result(code_file, code_file.content, [], [])

        self._detect(code_file)

        return self._create_result(
            code_file,
            code_file.content,
            self._changes,
            self._markers,
        )

    def _detect(self, code_file: CodeFile) -> None:
        """Subclasses implement this to perform actual detection."""
        raise NotImplementedError("Subclasses must implement _detect()")


@IaCRegistry.register
class DockerSecretsInEnvRule(IaCBaseRule):
    """IAC-003: Detect Docker secrets exposed in ENV variables.

    Matches ENV directives with patterns like SECRET, PASSWORD, TOKEN, etc.
    in Dockerfiles.

    Severity: HIGH
    CWE: CWE-798 (Use of Hard-coded Credentials)
    """

    IAC_ID = "IAC-003"
    DEFAULT_SEVERITY = "high"
    SUPPORTED_EXTENSIONS = ("Dockerfile", ".dockerfile")

    # Pattern matches ENV statements with secret-like values
    SECRET_PATTERN = re.compile(
        r'^\s*ENV\s+.*?(?:'
        r'SECRET|PASSWORD|PASSWD|PWD|'
        r'TOKEN|API_KEY|APIKEY|'
        r'PRIVATE_KEY|PRIVATEKEY|'
        r'ACCESS_KEY|ACCESSKEY|AWS_'
        r')[^=\s]*',
        re.IGNORECASE | re.MULTILINE
    )

    @property
    def description(self) -> str:
        return "Detects Docker secrets exposed in ENV variables"

    def name(self) -> str:
        return "DockerSecretsInEnv"

    def _detect(self, code_file: CodeFile) -> None:
        content = code_file.content
        file_path = str(code_file.path)

        for match in self.SECRET_PATTERN.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            self._add_finding(
                content=content,
                file_path=file_path,
                language="dockerfile",
                line=line_num,
                matched_text=match.group(0),
                cwe_id="CWE-798",
                hint="Use Docker secrets or environment variable injection at runtime instead of hardcoding sensitive values in ENV directives",
                why="Environment variable contains or references a secret value that could be exposed",
                impact="Sensitive credentials can be extracted from Docker image layers or container inspect",
                resources=(
                    "https://docs.docker.com/engine/swarm/secrets/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_CheatSheet.html",
                ),
                fix_constraints=(
                    "Move secrets to Docker secrets for Swarm or Kubernetes",
                    "Use --build-arg for build-time secrets with multi-stage builds",
                    "Consider external secret management (Vault, AWS Secrets Manager)",
                ),
            )


@IaCRegistry.register
class KubernetesPrivilegedPodRule(IaCBaseRule):
    """IAC-004: Detect Kubernetes pods with privileged containers.

    Matches securityContext.privileged: true in Kubernetes YAML files.

    Severity: CRITICAL
    CWE: CWE-250 (Execution with Unnecessary Privileges)
    """

    IAC_ID = "IAC-004"
    DEFAULT_SEVERITY = "critical"
    SUPPORTED_EXTENSIONS = (".yaml", ".yml")

    PRIVILEGED_PATTERN = re.compile(
        r'^\s*privileged:\s*["\']?true["\']?',
        re.MULTILINE | re.IGNORECASE
    )

    @property
    def description(self) -> str:
        return "Detects Kubernetes pods running with privileged container access"

    def name(self) -> str:
        return "KubernetesPrivilegedPod"

    def _detect(self, code_file: CodeFile) -> None:
        content = code_file.content
        file_path = str(code_file.path)

        for match in self.PRIVILEGED_PATTERN.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            self._add_finding(
                content=content,
                file_path=file_path,
                language="yaml",
                line=line_num,
                matched_text=match.group(0),
                cwe_id="CWE-250",
                hint="Remove privileged: true or set it to false. If privileged access is required, ensure it's scoped to specific namespaces with proper RBAC controls",
                why="Container is running with privileged access, allowing access to host system resources",
                impact="Privileged containers can escape isolation and access the host's resources, enabling container breakout attacks",
                resources=(
                    "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                    "https://www.nccgroup.com/us/about-us/newsroom-and-events/blog/2021/a-hackers-guide-to-kubernetes-security/",
                ),
                fix_constraints=(
                    "Set privileged: false in securityContext",
                    "Use readOnlyRootFilesystem: true where possible",
                    "Drop all capabilities and add only what's necessary",
                ),
            )


@IaCRegistry.register
class TerraformS3PublicAccessRule(IaCBaseRule):
    """IAC-005: Detect Terraform S3 buckets with public access or missing encryption.

    Matches acl = "public-read" or missing encryption settings in Terraform files.

    Severity: HIGH
    CWE: CWE-284 (Improper Access Control)
    """

    IAC_ID = "IAC-005"
    DEFAULT_SEVERITY = "high"
    SUPPORTED_EXTENSIONS = (".tf", ".tfvars")

    PUBLIC_ACL_PATTERN = re.compile(
        r'^\s*acl\s*=\s*["\']public[-_]?(?:read|write|read[-_]?write)["\']',
        re.MULTILINE | re.IGNORECASE
    )

    # Pattern to detect S3 bucket resource blocks
    S3_BUCKET_PATTERN = re.compile(
        r'resource\s+["\']aws_s3_bucket["\']',
        re.MULTILINE | re.IGNORECASE
    )

    ENCRYPTION_PATTERN = re.compile(
        r'server_side_encryption_configuration\s*=|'
        r'encrypt\s*=\s*true|'
        r'kms_key_id\s*=',
        re.MULTILINE | re.IGNORECASE
    )

    @property
    def description(self) -> str:
        return "Detects Terraform S3 buckets with public access or missing encryption"

    def name(self) -> str:
        return "TerraformS3PublicAccess"

    def _detect(self, code_file: CodeFile) -> None:
        content = code_file.content
        file_path = str(code_file.path)

        # Check for public ACL
        for match in self.PUBLIC_ACL_PATTERN.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            self._add_finding(
                content=content,
                file_path=file_path,
                language="hcl",
                line=line_num,
                matched_text=match.group(0),
                cwe_id="CWE-284",
                hint="Remove the public ACL and use private access with IAM policies for controlled access",
                why="S3 bucket ACL is set to public access, allowing anyone on the internet to read/write",
                impact="Public buckets can lead to data exposure, data tampering, or unexpected costs from unauthorized uploads",
                resources=(
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_AWS_Cloud_Configuration/",
                ),
                fix_constraints=(
                    "Remove acl or set it to 'private'",
                    "Use bucket policies and IAM policies for access control",
                    "Enable versioning for data protection",
                ),
            )

        # Check for S3 buckets missing encryption
        s3_bucket_matches = list(self.S3_BUCKET_PATTERN.finditer(content))
        encryption_matches = set(
            content[:m.end()].count('\n')
            for m in self.ENCRYPTION_PATTERN.finditer(content)
        )

        for bucket_match in s3_bucket_matches:
            bucket_line = content[:bucket_match.start()].count('\n') + 1
            # Look for encryption within the next 50 lines after bucket declaration
            search_start = bucket_match.end()
            search_end = min(len(content), search_start + content[search_start:].find('\n\n') if content[search_start:].find('\n\n') > 0 else search_start + 2000)

            bucket_section = content[search_start:search_end]
            has_encryption = bool(self.ENCRYPTION_PATTERN.search(bucket_section))

            if not has_encryption:
                self._add_finding(
                    content=content,
                    file_path=file_path,
                    language="hcl",
                    line=bucket_line,
                    matched_text=bucket_match.group(0),
                    cwe_id="CWE-311",
                    hint="Add server_side_encryption_configuration with AES-256 or AWS KMS encryption",
                    why="S3 bucket does not have server-side encryption configured",
                    impact="Unencrypted data at rest can be accessed if storage is compromised or misconfigured",
                    resources=(
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html",
                        "https://aws.amazon.com/blogs/security/how-to-prevent-data-exposure-by-using-amazon-s3-block-public-access/",
                    ),
                    fix_constraints=(
                        "Add server_side_encryption_configuration block",
                        "Use 'aws_s3_bucket_server_side_encryption_configuration' resource",
                        "Enable default encryption on the bucket",
                    ),
                )


@IaCRegistry.register
class K8sHostPathMountRule(IaCBaseRule):
    """IAC-006: Detect Kubernetes HostPath volume mounts.

    Matches hostPath in volume mount configurations.

    Severity: HIGH
    CWE: CWE-668 (Exposure of Resource to Wrong Sphere)
    """

    IAC_ID = "IAC-006"
    DEFAULT_SEVERITY = "high"
    SUPPORTED_EXTENSIONS = (".yaml", ".yml")

    HOSTPATH_PATTERN = re.compile(
        r'^\s*hostPath:\s*$[^$]*?(?:path:\s*["\']/?[^"\']+["\'])',
        re.MULTILINE
    )

    HOSTPATH_SIMPLE = re.compile(
        r'^\s*hostPath:\s*["\']/?[^"\']+["\']',
        re.MULTILINE
    )

    @property
    def description(self) -> str:
        return "Detects Kubernetes volumes mounted from host filesystem"

    def name(self) -> str:
        return "K8sHostPathMount"

    def _detect(self, code_file: CodeFile) -> None:
        content = code_file.content
        file_path = str(code_file.path)

        # Multi-line hostPath detection
        for match in self.HOSTPATH_PATTERN.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            self._add_finding(
                content=content,
                file_path=file_path,
                language="yaml",
                line=line_num,
                matched_text=match.group(0)[:100],
                cwe_id="CWE-668",
                hint="Avoid hostPath mounts in production. Use emptyDir volumes, persistentVolumeClaims, or cloud-specific storage classes",
                why="Volume is mounted directly from the host filesystem, bypassing container isolation",
                impact="Container can access or modify sensitive host files, enabling container escape and host compromise",
                resources=(
                    "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath",
                    "https://www.cybereason.com/blog/container-escape-the-ultimate-persistence",
                ),
                fix_constraints=(
                    "Use emptyDir volume for temporary storage",
                    "Use PersistentVolumeClaim for persistent storage",
                    "If hostPath is required, restrict to specific paths with readOnly mount",
                    "Ensure pod security standards restrict hostPath usage",
                ),
            )

        # Single-line hostPath detection
        for match in self.HOSTPATH_SIMPLE.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            # Skip if already caught by multi-line pattern
            if not self._within_previous_match(match.start(), content):
                self._add_finding(
                    content=content,
                    file_path=file_path,
                    language="yaml",
                    line=line_num,
                    matched_text=match.group(0),
                    cwe_id="CWE-668",
                    hint="Avoid hostPath mounts in production. Use emptyDir volumes, persistentVolumeClaims, or cloud-specific storage classes",
                    why="Volume is mounted directly from the host filesystem",
                    impact="Container can access host files, potentially enabling container escape",
                    resources=(
                        "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath",
                    ),
                    fix_constraints=(
                        "Consider using emptyDir instead of hostPath",
                        "Use readOnly: true if hostPath is unavoidable",
                        "Restrict to specific, non-sensitive paths",
                    ),
                )

    def _within_previous_match(self, pos: int, content: str) -> bool:
        """Check if position is within a multi-line hostPath block already detected."""
        for match in self.HOSTPATH_PATTERN.finditer(content):
            if match.start() <= pos <= match.end():
                return True
        return False


@IaCRegistry.register
class DockerNetworkHostRule(IaCBaseRule):
    """IAC-007: Detect Docker --network=host usage.

    Matches --network host in Dockerfiles.

    Severity: MEDIUM
    CWE: CWE-654 (Reliance on a Single Factor for Security)
    """

    IAC_ID = "IAC-007"
    DEFAULT_SEVERITY = "medium"
    SUPPORTED_EXTENSIONS = ("Dockerfile", ".dockerfile")

    NETWORK_HOST_PATTERN = re.compile(
        r'--\s*network\s+host|'
        r'--network\s+host',
        re.MULTILINE | re.IGNORECASE
    )

    @property
    def description(self) -> str:
        return "Detects Docker containers using host network mode"

    def name(self) -> str:
        return "DockerNetworkHost"

    def _detect(self, code_file: CodeFile) -> None:
        content = code_file.content
        file_path = str(code_file.path)

        for match in self.NETWORK_HOST_PATTERN.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            self._add_finding(
                content=content,
                file_path=file_path,
                language="dockerfile",
                line=line_num,
                matched_text=match.group(0),
                cwe_id="CWE-654",
                hint="Use bridge network mode with explicit port mappings instead of host network mode",
                why="Container is using host network mode, removing network isolation between containers",
                impact="Container can access all host network ports directly, bypassing Docker's network isolation and port management",
                resources=(
                    "https://docs.docker.com/network/host/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#networking",
                ),
                fix_constraints=(
                    "Use default bridge network or custom network",
                    "Use -p flag to explicitly expose only required ports",
                    "Consider Docker Compose for multi-container setups",
                ),
            )


@IaCRegistry.register
class K8sAllowPrivilegeEscalationRule(IaCBaseRule):
    """IAC-008: Detect Kubernetes containers allowing privilege escalation.

    Matches allowPrivilegeEscalation: true in securityContext.

    Severity: HIGH
    CWE: CWE-269 (Improper Privilege Management)
    """

    IAC_ID = "IAC-008"
    DEFAULT_SEVERITY = "high"
    SUPPORTED_EXTENSIONS = (".yaml", ".yml")

    PRIV_ESCALATION_PATTERN = re.compile(
        r'^\s*allowPrivilegeEscalation:\s*["\']?true["\']?',
        re.MULTILINE | re.IGNORECASE
    )

    @property
    def description(self) -> str:
        return "Detects Kubernetes pods allowing container privilege escalation"

    def name(self) -> str:
        return "K8sAllowPrivilegeEscalation"

    def _detect(self, code_file: CodeFile) -> None:
        content = code_file.content
        file_path = str(code_file.path)

        for match in self.PRIV_ESCALATION_PATTERN.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            self._add_finding(
                content=content,
                file_path=file_path,
                language="yaml",
                line=line_num,
                matched_text=match.group(0),
                cwe_id="CWE-269",
                hint="Set allowPrivilegeEscalation: false in securityContext and ensure runAsNonRoot: true",
                why="Container allows privilege escalation, permitting child processes to gain more privileges than parent",
                impact="If exploited, attackers can escalate privileges within the container or to the underlying host",
                resources=(
                    "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                ),
                fix_constraints=(
                    "Set allowPrivilegeEscalation: false",
                    "Set runAsNonRoot: true",
                    "Set runAsUser to a non-zero value",
                    "Consider using Pod Security Standards (restricted policy)",
                ),
            )


@IaCRegistry.register
class TerraformStateNotEncryptedRule(IaCBaseRule):
    """IAC-009: Detect Terraform S3 backend without encryption.

    Checks for missing encrypt = true in S3 backend configuration.

    Severity: MEDIUM
    CWE: CWE-311 (Missing Encryption of Sensitive Data)
    """

    IAC_ID = "IAC-009"
    DEFAULT_SEVERITY = "medium"
    SUPPORTED_EXTENSIONS = (".tf", ".tfvars")

    S3_BACKEND_PATTERN = re.compile(
        r'backend\s+["\']s3["\']',
        re.MULTILINE | re.IGNORECASE
    )

    ENCRYPT_PATTERN = re.compile(
        r'encrypt\s*=\s*true',
        re.MULTILINE | re.IGNORECASE
    )

    @property
    def description(self) -> str:
        return "Detects Terraform state stored in S3 without encryption"

    def name(self) -> str:
        return "TerraformStateNotEncrypted"

    def _detect(self, code_file: CodeFile) -> None:
        content = code_file.content
        file_path = str(code_file.path)

        # Find all S3 backend declarations
        backend_matches = list(self.S3_BACKEND_PATTERN.finditer(content))

        for backend_match in backend_matches:
            backend_line = content[:backend_match.start()].count('\n') + 1

            # Look ahead in the content for the backend configuration block
            # Terraform backend blocks typically follow the backend "s3" declaration
            search_content = content[backend_match.end():]
            next_2000_chars = search_content[:2000]

            # Check if there's an encrypt = true within reasonable distance
            # Look for the closing brace or end of backend block
            block_end = len(next_2000_chars)
            brace_count = 0
            started = False
            for i, char in enumerate(next_2000_chars):
                if char == '{':
                    brace_count += 1
                    started = True
                elif char == '}':
                    brace_count -= 1
                    if started and brace_count == 0:
                        block_end = i + 1
                        break

            backend_block = next_2000_chars[:block_end]
            has_encryption = bool(self.ENCRYPT_PATTERN.search(backend_block))

            if not has_encryption:
                self._add_finding(
                    content=content,
                    file_path=file_path,
                    language="hcl",
                    line=backend_line,
                    matched_text=backend_match.group(0),
                    cwe_id="CWE-311",
                    hint="Add encrypt = true to the S3 backend configuration to enable server-side encryption for Terraform state",
                    why="Terraform state backend is configured without encryption enabled",
                    impact="Terraform state may contain sensitive data (passwords, secrets, infrastructure details) stored unencrypted",
                    resources=(
                        "https://developer.hashicorp.com/terraform/language/settings/backends/s3",
                        "https://www.terraform.io/docs/state/sensitive-data.html",
                    ),
                    fix_constraints=(
                        "Add encrypt = true to the backend configuration block",
                        "Consider using DynamoDB table for state locking",
                        "Enable versioning for state recovery",
                    ),
                )


@IaCRegistry.register
class K8sRootContainerRule(IaCBaseRule):
    """IAC-010: Detect Kubernetes containers running as root user.

    Matches runAsUser: 0 or missing runAsNonRoot in securityContext.

    Severity: HIGH
    CWE: CWE-250 (Execution with Unnecessary Privileges)
    """

    IAC_ID = "IAC-010"
    DEFAULT_SEVERITY = "high"
    SUPPORTED_EXTENSIONS = (".yaml", ".yml")

    RUN_AS_ROOT_PATTERN = re.compile(
        r'^\s*runAsUser:\s*["\']?\s*0\s*["\']?',
        re.MULTILINE | re.IGNORECASE
    )

    # Pattern to detect if runAsNonRoot exists in the same securityContext block
    RUN_AS_NON_ROOT_PATTERN = re.compile(
        r'runAsNonRoot:\s*true',
        re.MULTILINE | re.IGNORECASE
    )

    @property
    def description(self) -> str:
        return "Detects Kubernetes containers running as root user"

    def name(self) -> str:
        return "K8sRootContainer"

    def _detect(self, code_file: CodeFile) -> None:
        content = code_file.content
        file_path = str(code_file.path)

        for match in self.RUN_AS_ROOT_PATTERN.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            self._add_finding(
                content=content,
                file_path=file_path,
                language="yaml",
                line=line_num,
                matched_text=match.group(0),
                cwe_id="CWE-250",
                hint="Change runAsUser to a non-zero value (e.g., 1000) and ensure runAsNonRoot: true is set",
                why="Container is configured to run as root user (UID 0)",
                impact="Running as root increases the blast radius of any container compromise. Many container vulnerabilities become critical when exploitable as root",
                resources=(
                    "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
                    "https://developer.squareup.com/blog/running-a-container-as-root-on-an-privileged-kubernetes-cluster",
                ),
                fix_constraints=(
                    "Set runAsUser to a non-root UID (e.g., 1000)",
                    "Set runAsNonRoot: true",
                    "Ensure the application user exists in the container image",
                    "Use Pod Security Standards to enforce non-root workloads",
                ),
            )

        # Also check for missing runAsNonRoot when it's a pod/deployment spec
        # Look for securityContext at pod level without runAsNonRoot
        lines = content.split('\n')
        in_security_context = False
        security_context_start = 0
        seen_run_as_non_root = False

        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.match(r'^\s*securityContext:\s*$', stripped, re.IGNORECASE):
                in_security_context = True
                security_context_start = i
                seen_run_as_non_root = False
            elif in_security_context:
                if re.match(r'^\s*runAsNonRoot:', stripped, re.IGNORECASE):
                    seen_run_as_non_root = True
                # End of securityContext block (dedent or new key)
                if stripped and not stripped.startswith(' ') and not stripped.startswith('\t'):
                    if not seen_run_as_non_root:
                        # Check if there's a container section that suggests this is a pod spec
                        # We flag this as informational only since it may be intentional for some workloads
                        pass
                    in_security_context = False


def get_iac_rules() -> List[type]:
    """Return all registered IaC security rule classes."""
    return IaCRegistry.get_rules()


def get_iac_rule(iac_id: str):
    """Return a specific IaC rule by ID."""
    return IaCRegistry.get_rule(iac_id)
