"""Policy engine for PyNEAT - enforce security policies across the codebase.

Copyright (c) 2026 PyNEAT Authors
License: AGPL-3.0

Features:
  - Define security policies in YAML/TOML
  - Block commits based on policy violations
  - Enforce severity thresholds
  - Custom rule allowlists
  - Compliance reporting (SOC2, ISO27001, GDPR, HIPAA)
"""

from __future__ import annotations

import json
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any, Set

from pyneat.core.types import SecurityFinding, SecuritySeverity


class ComplianceFramework:
    """Supported compliance frameworks."""
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    OWASP = "owasp"


@dataclass
class Policy:
    """A security policy definition."""
    name: str
    description: str
    severity_threshold: SecuritySeverity
    blocked_rules: Set[str] = field(default_factory=set)
    allowed_rules: Set[str] = field(default_factory=set)
    exclude_paths: Set[str] = field(default_factory=set)
    include_paths: Set[str] = field(default_factory=set)
    max_findings_per_file: int = 100
    fail_on_warning: bool = False
    compliance_frameworks: Set[str] = field(default_factory=set)
    custom_config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "severity_threshold": self.severity_threshold.value,
            "blocked_rules": list(self.blocked_rules),
            "allowed_rules": list(self.allowed_rules),
            "exclude_paths": list(self.exclude_paths),
            "include_paths": list(self.include_paths),
            "max_findings_per_file": self.max_findings_per_file,
            "fail_on_warning": self.fail_on_warning,
            "compliance_frameworks": list(self.compliance_frameworks),
        }


@dataclass
class PolicyViolation:
    """A policy violation found during scanning."""
    policy_name: str
    finding: SecurityFinding
    file_path: str
    blocked: bool
    reason: str


@dataclass
class PolicyResult:
    """Result of evaluating a policy against scan results."""
    policy: Policy
    violations: List[PolicyViolation]
    passed: bool
    blocked: bool
    summary: Dict[str, int]
    message: str


@dataclass
class ComplianceReport:
    """Compliance report for a framework."""
    framework: str
    requirements: List[Dict[str, Any]]
    findings: List[SecurityFinding]
    covered: List[str]
    gaps: List[str]
    score: float  # 0.0 - 100.0


class PolicyEngine:
    """Evaluates scan results against defined security policies.

    Supports:
      - Multiple policies with different thresholds
      - Compliance framework mapping
      - Git pre-commit blocking
      - CI/CD gate evaluation
      - Detailed violation reporting
    """

    DEFAULT_POLICIES: Dict[str, Policy] = {}

    def __init__(self, policies: Optional[List[Policy]] = None):
        self.policies: Dict[str, Policy] = {}
        if policies:
            for policy in policies:
                self.policies[policy.name] = policy
        else:
            self._load_default_policies()

    def _load_default_policies(self):
        """Load default policies."""
        self.policies = {
            "strict": Policy(
                name="strict",
                description="Maximum security - blocks any potential issue",
                severity_threshold=SecuritySeverity.INFO,
                blocked_rules=set(),
                fail_on_warning=True,
            ),
            "production": Policy(
                name="production",
                description="Production-ready security policy",
                severity_threshold=SecuritySeverity.MEDIUM,
                blocked_rules={"SEC-IAC-DOCKER-002"},  # :latest tag is warning only
                fail_on_warning=False,
            ),
            "development": Policy(
                name="development",
                description="Development-friendly policy - only blocks critical issues",
                severity_threshold=SecuritySeverity.HIGH,
                fail_on_warning=False,
            ),
            "compliance": Policy(
                name="compliance",
                description="SOC2/ISO27001 compliance policy",
                severity_threshold=SecuritySeverity.MEDIUM,
                blocked_rules=set(),
                compliance_frameworks={ComplianceFramework.SOC2, ComplianceFramework.ISO27001},
            ),
        }

    def add_policy(self, policy: Policy) -> None:
        """Add a policy to the engine."""
        self.policies[policy.name] = policy

    def remove_policy(self, name: str) -> bool:
        """Remove a policy by name."""
        if name in self.policies:
            del self.policies[name]
            return True
        return False

    def get_policy(self, name: str) -> Optional[Policy]:
        """Get a policy by name."""
        return self.policies.get(name)

    def list_policies(self) -> List[str]:
        """List all available policy names."""
        return list(self.policies.keys())

    def evaluate(self, findings: List[SecurityFinding],
                 policy_name: str = "production") -> PolicyResult:
        """Evaluate findings against a policy.

        Args:
            findings: List of security findings to evaluate
            policy_name: Name of the policy to use

        Returns:
            PolicyResult with pass/fail status and violations
        """
        policy = self.policies.get(policy_name)
        if not policy:
            return PolicyResult(
                policy=None,
                violations=[],
                passed=False,
                blocked=False,
                summary={},
                message=f"Policy '{policy_name}' not found",
            )

        violations: List[PolicyViolation] = []
        severity_counts: Dict[str, int] = {}

        for finding in findings:
            # Check file path exclusions
            if self._is_excluded(finding.file, policy):
                continue

            # Check rule allowlist
            if policy.allowed_rules and finding.rule_id not in policy.allowed_rules:
                continue

            # Check rule blocklist
            blocked = finding.rule_id in policy.blocked_rules

            # Check severity threshold
            severity_order = [
                SecuritySeverity.CRITICAL,
                SecuritySeverity.HIGH,
                SecuritySeverity.MEDIUM,
                SecuritySeverity.LOW,
                SecuritySeverity.INFO,
            ]
            finding_severity_idx = severity_order.index(finding.severity)
            threshold_idx = severity_order.index(policy.severity_threshold)
            exceeds_threshold = finding_severity_idx <= threshold_idx

            if exceeds_threshold or blocked:
                reason_parts = []
                if blocked:
                    reason_parts.append(f"Rule {finding.rule_id} is blocked")
                if exceeds_threshold:
                    reason_parts.append(f"Severity {finding.severity.value} exceeds threshold {policy.severity_threshold.value}")

                violation = PolicyViolation(
                    policy_name=policy.name,
                    finding=finding,
                    file_path=finding.file,
                    blocked=blocked or policy.fail_on_warning,
                    reason="; ".join(reason_parts),
                )
                violations.append(violation)

            # Count by severity
            sev_key = finding.severity.value
            severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1

        # Determine pass/fail
        blocked_violations = [v for v in violations if v.blocked]
        passed = len(blocked_violations) == 0

        return PolicyResult(
            policy=policy,
            violations=violations,
            passed=passed,
            blocked=not passed,
            summary=severity_counts,
            message="Policy passed" if passed else f"Policy violated: {len(blocked_violations)} blocking issue(s)",
        )

    def _is_excluded(self, file_path: str, policy: Policy) -> bool:
        """Check if a file path is excluded by the policy."""
        if not policy.exclude_paths:
            return False

        for pattern in policy.exclude_paths:
            if pattern in file_path:
                return True
        return False

    def check_pre_commit(self, findings: List[SecurityFinding],
                         policy_name: str = "production") -> tuple[bool, str]:
        """Check if findings should block a commit.

        Returns:
            (should_block, message) tuple
        """
        result = self.evaluate(findings, policy_name)

        if result.blocked:
            lines = [f"Policy '{policy_name}' violation:"]
            for v in result.violations[:5]:  # Show first 5
                lines.append(f"  - {v.finding.rule_id} ({v.finding.severity.value}): {v.finding.problem}")
            if len(result.violations) > 5:
                lines.append(f"  ... and {len(result.violations) - 5} more")
            return True, '\n'.join(lines)

        return False, "No policy violations"

    def generate_compliance_report(self, findings: List[SecurityFinding],
                                    framework: str) -> ComplianceReport:
        """Generate a compliance report for a framework."""
        requirements = self._get_framework_requirements(framework)
        covered: List[str] = []
        gaps: List[str] = []
        relevant_findings: List[SecurityFinding] = []

        for req in requirements:
            cwe_ids = req.get("cwe_ids", [])
            severity_threshold = req.get("min_severity", SecuritySeverity.MEDIUM)

            # Check if any findings match this requirement
            matching = [
                f for f in findings
                if (f.cwe_id in cwe_ids or not cwe_ids)
                and self._severity_le(f.severity, severity_threshold)
            ]

            if matching:
                covered.append(req["id"])
                relevant_findings.extend(matching)
            else:
                gaps.append(req["id"])

        # Calculate score
        total_reqs = len(requirements)
        covered_count = len(covered)
        score = (covered_count / total_reqs * 100) if total_reqs > 0 else 100.0

        return ComplianceReport(
            framework=framework,
            requirements=requirements,
            findings=relevant_findings,
            covered=covered,
            gaps=gaps,
            score=score,
        )

    def _get_framework_requirements(self, framework: str) -> List[Dict[str, Any]]:
        """Get compliance requirements for a framework."""
        frameworks = {
            ComplianceFramework.SOC2: [
                {"id": "CC6.1", "name": "Logical Access Controls", "cwe_ids": ["CWE-284", "CWE-285"], "min_severity": SecuritySeverity.HIGH},
                {"id": "CC6.3", "name": "Encryption of Data", "cwe_ids": ["CWE-311", "CWE-319"], "min_severity": SecuritySeverity.HIGH},
                {"id": "CC6.6", "name": "Security Incident Management", "cwe_ids": [], "min_severity": SecuritySeverity.MEDIUM},
                {"id": "CC7.2", "name": "Vulnerability Management", "cwe_ids": [], "min_severity": SecuritySeverity.MEDIUM},
            ],
            ComplianceFramework.ISO27001: [
                {"id": "A.9.1", "name": "Access Control Policy", "cwe_ids": ["CWE-284"], "min_severity": SecuritySeverity.HIGH},
                {"id": "A.10.1", "name": "Cryptography", "cwe_ids": ["CWE-311", "CWE-319", "CWE-329"], "min_severity": SecuritySeverity.HIGH},
                {"id": "A.12.4", "name": "Logging and Monitoring", "cwe_ids": ["CWE-778"], "min_severity": SecuritySeverity.MEDIUM},
                {"id": "A.14.2", "name": "Security in Development", "cwe_ids": [], "min_severity": SecuritySeverity.MEDIUM},
            ],
            ComplianceFramework.GDPR: [
                {"id": "Art.5", "name": "Data Minimization", "cwe_ids": ["CWE-200", "CWE-359"], "min_severity": SecuritySeverity.HIGH},
                {"id": "Art.32", "name": "Security of Processing", "cwe_ids": ["CWE-311", "CWE-319"], "min_severity": SecuritySeverity.HIGH},
                {"id": "Art.33", "name": "Breach Notification", "cwe_ids": [], "min_severity": SecuritySeverity.MEDIUM},
            ],
            ComplianceFramework.HIPAA: [
                {"id": "164.312(a)", "name": "Access Control", "cwe_ids": ["CWE-284"], "min_severity": SecuritySeverity.HIGH},
                {"id": "164.312(e)", "name": "Transmission Security", "cwe_ids": ["CWE-311", "CWE-319"], "min_severity": SecuritySeverity.HIGH},
                {"id": "164.312(b)", "name": "Audit Controls", "cwe_ids": ["CWE-778"], "min_severity": SecuritySeverity.MEDIUM},
            ],
        }
        return frameworks.get(framework, [])

    def _severity_le(self, a: SecuritySeverity, b: SecuritySeverity) -> bool:
        """Check if severity a is less than or equal to b (more severe)."""
        order = [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH,
                 SecuritySeverity.MEDIUM, SecuritySeverity.LOW, SecuritySeverity.INFO]
        return order.index(a) <= order.index(b)

    def load_policy_from_file(self, path: Path) -> Policy:
        """Load a policy from a YAML or JSON file."""
        content = path.read_text()

        if path.suffix in ('.yaml', '.yml'):
            data = yaml.safe_load(content)
        elif path.suffix == '.json':
            data = json.loads(content)
        else:
            raise ValueError(f"Unsupported policy file format: {path.suffix}")

        return self._parse_policy_data(data)

    def _parse_policy_data(self, data: Dict[str, Any]) -> Policy:
        """Parse policy data from dict."""
        severity_str = data.get("severity_threshold", "medium")
        severity = SecuritySeverity(severity_str)

        return Policy(
            name=data["name"],
            description=data.get("description", ""),
            severity_threshold=severity,
            blocked_rules=set(data.get("blocked_rules", [])),
            allowed_rules=set(data.get("allowed_rules", [])),
            exclude_paths=set(data.get("exclude_paths", [])),
            include_paths=set(data.get("include_paths", [])),
            max_findings_per_file=data.get("max_findings_per_file", 100),
            fail_on_warning=data.get("fail_on_warning", False),
            compliance_frameworks=set(data.get("compliance_frameworks", [])),
            custom_config=data.get("custom_config", {}),
        )

    def save_policy_to_file(self, policy: Policy, path: Path) -> None:
        """Save a policy to a YAML or JSON file."""
        data = policy.to_dict()

        if path.suffix in ('.yaml', '.yml'):
            content = yaml.dump(data, default_flow_style=False)
        elif path.suffix == '.json':
            content = json.dumps(data, indent=2)
        else:
            raise ValueError(f"Unsupported policy file format: {path.suffix}")

        path.write_text(content)


def check_policy(findings: List[SecurityFinding],
                 policy_name: str = "production") -> PolicyResult:
    """Convenience function to check findings against a policy."""
    engine = PolicyEngine()
    return engine.evaluate(findings, policy_name)


def check_pre_commit(findings: List[SecurityFinding],
                     policy_name: str = "production") -> tuple[bool, str]:
    """Convenience function for pre-commit policy checking."""
    engine = PolicyEngine()
    return engine.check_pre_commit(findings, policy_name)


def generate_compliance_report(findings: List[SecurityFinding],
                                framework: str) -> ComplianceReport:
    """Convenience function to generate a compliance report."""
    engine = PolicyEngine()
    return engine.generate_compliance_report(findings, framework)


__all__ = [
    "Policy",
    "PolicyViolation",
    "PolicyResult",
    "ComplianceReport",
    "PolicyEngine",
    "ComplianceFramework",
    "check_policy",
    "check_pre_commit",
    "generate_compliance_report",
]
