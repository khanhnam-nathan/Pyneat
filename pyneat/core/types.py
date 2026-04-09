"""Domain types and data models.

Copyright (c) 2024-2026 PyNEAT Authors

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

For commercial licensing, contact: license@pyneat.dev
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set

from pathlib import Path

# --------------------------------------------------------------------------
# Security severity levels
# --------------------------------------------------------------------------

class SecuritySeverity:
    """Security severity levels aligned with industry standards."""
    CRITICAL = "critical"  # Must fix immediately (RCE, injection)
    HIGH = "high"          # Should fix (secrets, weak crypto)
    MEDIUM = "medium"      # Consider fixing (SSRF, XSS)
    LOW = "low"            # Informational (PII in logs)
    INFO = "info"          # Best practices (deprecated APIs)

    @classmethod
    def all_levels(cls) -> List[str]:
        return [cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW, cls.INFO]

    @classmethod
    def from_string(cls, s: str) -> str:
        s = s.lower()
        if s in ("crit", "critical"):
            return cls.CRITICAL
        if s == "high":
            return cls.HIGH
        if s in ("med", "medium"):
            return cls.MEDIUM
        if s == "low":
            return cls.LOW
        return cls.INFO


# --------------------------------------------------------------------------
# CWE to Severity mapping (industry-standard alignment)
# --------------------------------------------------------------------------

CWE_SEVERITY_MAP: Dict[str, str] = {
    # CRITICAL: Remote Code Execution, Injection
    "CWE-78": SecuritySeverity.CRITICAL,   # OS Command Injection
    "CWE-79": SecuritySeverity.MEDIUM,     # Cross-site Scripting (XSS)
    "CWE-89": SecuritySeverity.CRITICAL,   # SQL Injection
    "CWE-90": SecuritySeverity.MEDIUM,     # LDAP Injection
    "CWE-94": SecuritySeverity.CRITICAL,   # Code Injection
    "CWE-95": SecuritySeverity.CRITICAL,   # Eval Injection
    "CWE-98": SecuritySeverity.HIGH,       # Path Traversal (PHP)
    "CWE-22": SecuritySeverity.CRITICAL,   # Path Traversal
    "CWE-23": SecuritySeverity.HIGH,       # Relative Path Traversal
    "CWE-36": SecuritySeverity.MEDIUM,     # Absolute Path Traversal
    "CWE-78": SecuritySeverity.CRITICAL,   # OS Command Injection
    "CWE-79": SecuritySeverity.MEDIUM,     # Cross-site Scripting
    "CWE-89": SecuritySeverity.CRITICAL,   # SQL Injection
    "CWE-90": SecuritySeverity.MEDIUM,     # LDAP Injection
    "CWE-94": SecuritySeverity.CRITICAL,   # Code Injection
    "CWE-95": SecuritySeverity.CRITICAL,   # Eval Injection
    "CWE-98": SecuritySeverity.HIGH,       # Path Traversal
    "CWE-122": SecuritySeverity.CRITICAL,  # Heap-based Buffer Overflow
    "CWE-123": SecuritySeverity.CRITICAL,  # Write-what-where Condition
    "CWE-190": SecuritySeverity.MEDIUM,     # Integer Overflow
    "CWE-191": SecuritySeverity.MEDIUM,     # Integer Underflow
    "CWE-194": SecuritySeverity.MEDIUM,     # Signed to Unsigned Conversion
    "CWE-195": SecuritySeverity.MEDIUM,     # Signed to Unsigned Conversion
    "CWE-196": SecuritySeverity.MEDIUM,     # Signed to Unsigned Conversion
    "CWE-369": SecuritySeverity.LOW,        # Divide By Zero
    "CWE-377": SecuritySeverity.LOW,        # Insecure Temporary File
    "CWE-401": SecuritySeverity.LOW,        # Memory Leak
    "CWE-415": SecuritySeverity.CRITICAL,   # Double Free
    "CWE-416": SecuritySeverity.CRITICAL,   # Use After Free
    "CWE-426": SecuritySeverity.HIGH,       # Untrusted Search Path
    "CWE-434": SecuritySeverity.HIGH,       # Unrestricted Upload
    "CWE-457": SecuritySeverity.LOW,        # Use of Uninitialized Variable
    "CWE-459": SecuritySeverity.LOW,        # Incomplete Cleanup
    "CWE-467": SecuritySeverity.INFO,        # Use of sizeof() on Pointer
    "CWE-476": SecuritySeverity.INFO,        # NULL Pointer Dereference
    "CWE-482": SecuritySeverity.LOW,        # Overly Permissive Assignment
    "CWE-484": SecuritySeverity.LOW,        # Omitted Break Statement
    "CWE-489": SecuritySeverity.MEDIUM,     # Active Debug Code
    "CWE-498": SecuritySeverity.HIGH,       # Information Leak by Inserted Text
    "CWE-499": SecuritySeverity.HIGH,       # Information Leak by Returned Text
    "CWE-501": SecuritySeverity.MEDIUM,     # Trust Boundary Violation
    "CWE-502": SecuritySeverity.CRITICAL,   # Deserialization of Untrusted Data
    "CWE-506": SecuritySeverity.HIGH,       # Covert Storage Channel
    "CWE-507": SecuritySeverity.MEDIUM,     # Covert Timing Channel
    "CWE-508": SecuritySeverity.HIGH,       # Non-repurposing Identity
    "CWE-522": SecuritySeverity.HIGH,       # Insufficiently Protected Credentials
    "CWE-565": SecuritySeverity.HIGH,       # Reliance on Cookies
    "CWE-598": SecuritySeverity.MEDIUM,     # Information Leak via Query String
    "CWE-601": SecuritySeverity.HIGH,       # Open Redirect
    "CWE-611": SecuritySeverity.HIGH,       # XML External Entity (XXE)
    "CWE-613": SecuritySeverity.MEDIUM,     # Insufficient Session Expiration
    "CWE-642": SecuritySeverity.HIGH,       # External Control of State
    "CWE-643": SecuritySeverity.CRITICAL,   # XPath Injection
    "CWE-644": SecuritySeverity.MEDIUM,     # Improper Validation of HTTP Headers
    "CWE-646": SecuritySeverity.MEDIUM,     # Reliance on File Name
    "CWE-648": SecuritySeverity.MEDIUM,     # Incorrect Trust in Operation Mode
    "CWE-654": SecuritySeverity.HIGH,       # Reliance on Single Factor
    "CWE-655": SecuritySeverity.HIGH,       # Insufficient Psychological Acceptability
    "CWE-656": SecuritySeverity.HIGH,       # Insufficient Economic Security
    "CWE-673": SecuritySeverity.MEDIUM,     # External Control of Resource
    "CWE-681": SecuritySeverity.MEDIUM,     # Numeric Errors
    "CWE-692": SecuritySeverity.MEDIUM,     # Incomplete Blacklist
    "CWE-697": SecuritySeverity.MEDIUM,     # Incorrect Comparison
    "CWE-698": SecuritySeverity.MEDIUM,    # Redirect After Auth
    "CWE-703": SecuritySeverity.MEDIUM,     # Improper Check for Dropped Privileges
    "CWE-705": SecuritySeverity.LOW,        # Incorrect Control Flow
    "CWE-706": SecuritySeverity.LOW,        # Use of Invalid Reference
    "CWE-732": SecuritySeverity.HIGH,       # Incorrect Permission Assignment
    "CWE-749": SecuritySeverity.HIGH,       # Exposed Method
    "CWE-755": SecuritySeverity.MEDIUM,     # Improper Handling of Exception
    "CWE-759": SecuritySeverity.HIGH,       # Use of Weak Hash
    "CWE-760": SecuritySeverity.HIGH,       # Use of Predictable Salt
    "CWE-770": SecuritySeverity.MEDIUM,     # Resource Allocation
    "CWE-772": SecuritySeverity.LOW,        # Missing Release of Resource
    "CWE-776": SecuritySeverity.MEDIUM,     # Unbounded Resource
    "CWE-779": SecuritySeverity.LOW,        # Logging of Excess Data
    "CWE-789": SecuritySeverity.CRITICAL,   # Memory Allocation
    "CWE-798": SecuritySeverity.HIGH,       # Hardcoded Credentials
    "CWE-799": SecuritySeverity.MEDIUM,     # Improper Control of Interaction
    "CWE-803": SecuritySeverity.MEDIUM,     # Race Condition
    "CWE-807": SecuritySeverity.HIGH,       # Reliance on Untrusted Inputs
    "CWE-829": SecuritySeverity.HIGH,       # Inclusion of Functionality
    "CWE-834": SecuritySeverity.LOW,        # Excessive Iteration
    "CWE-835": SecuritySeverity.LOW,        # Loop with Unreachable Exit
    "CWE-841": SecuritySeverity.MEDIUM,     # Improper Enforcement
    "CWE-862": SecuritySeverity.HIGH,       # Missing Authorization
    "CWE-863": SecuritySeverity.HIGH,       # Incorrect Authorization
    "CWE-898": SecuritySeverity.INFO,        # Use of Groovy Builder
    "CWE-915": SecuritySeverity.MEDIUM,     # Improperly Controlled Modification
    "CWE-918": SecuritySeverity.HIGH,       # Server-Side Request Forgery
    "CWE-939": SecuritySeverity.MEDIUM,     # Improper Authorization
    "CWE-1004": SecuritySeverity.MEDIUM,     # Sensitive Cookie
    "CWE-1004": SecuritySeverity.MEDIUM,     # Missing HttpOnly
    "CWE-1021": SecuritySeverity.LOW,        # Restriction of Rendered UI Layer
    "CWE-1173": SecuritySeverity.MEDIUM,     # Improper Use of Validation
    "CWE-1274": SecuritySeverity.MEDIUM,     # Insufficient Protection
    "CWE-1275": SecuritySeverity.MEDIUM,     # Improper Handling
    "CWE-1333": SecuritySeverity.INFO,        # Regular Expression Injection
    "CWE-1336": SecuritySeverity.LOW,        # Improper Neutralization
}


# --------------------------------------------------------------------------
# OWASP to Severity mapping
# --------------------------------------------------------------------------

OWASP_SEVERITY_MAP: Dict[str, str] = {
    "A01": SecuritySeverity.HIGH,    # Broken Access Control
    "A02": SecuritySeverity.HIGH,    # Cryptographic Failures
    "A03": SecuritySeverity.CRITICAL, # Injection
    "A04": SecuritySeverity.MEDIUM,  # Insecure Design
    "A05": SecuritySeverity.MEDIUM,  # Security Misconfiguration
    "A06": SecuritySeverity.HIGH,   # Vulnerable Components
    "A07": SecuritySeverity.HIGH,   # Auth Failures
    "A08": SecuritySeverity.HIGH,   # Software Integrity Failures
    "A09": SecuritySeverity.MEDIUM,  # Logging Failures
    "A10": SecuritySeverity.MEDIUM,  # SSRF
}


# --------------------------------------------------------------------------
# Security types
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SecurityFinding:
    """A security vulnerability detected by a security rule.

    Contains full context for triage, fix guidance, and CI/CD integration.
    """
    rule_id: str              # SEC-001, SEC-010, ...
    severity: str             # SecuritySeverity level
    confidence: float         # 0.0 - 1.0 detection confidence
    cwe_id: str               # CWE-78, CWE-89, ...
    owasp_id: str             # A01, A02, ... (empty string if not mapped)
    cvss_score: float         # 0.0 - 10.0 CVSS base score
    cvss_vector: str          # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    file: str                 # Source file path
    start_line: int           # 1-indexed start line
    end_line: int             # 1-indexed end line
    snippet: str              # Code snippet (max 200 chars)
    problem: str              # One-line description of the vulnerability
    fix_constraints: Tuple[str, ...]   # What MUST be done to fix
    do_not: Tuple[str, ...]            # Common mistakes to avoid
    verify: Tuple[str, ...]             # How to verify the fix
    resources: Tuple[str, ...]           # Links to docs/guides
    can_auto_fix: bool        # Whether auto-fix is conceptually possible
    auto_fix_available: bool  # Whether auto-fix is implemented
    auto_fix_before: Optional[str] = None  # Code before fix
    auto_fix_after: Optional[str] = None   # Code after fix
    auto_fix_diff: Optional[str] = None    # Unified diff

    @property
    def location(self) -> str:
        return f"{self.file}:{self.start_line}"

    @property
    def severity_emoji(self) -> str:
        mapping = {
            SecuritySeverity.CRITICAL: "CRITICAL",
            SecuritySeverity.HIGH: "HIGH",
            SecuritySeverity.MEDIUM: "MEDIUM",
            SecuritySeverity.LOW: "LOW",
            SecuritySeverity.INFO: "INFO",
        }
        return mapping.get(self.severity, self.severity.upper())

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for JSON output."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "owasp_id": self.owasp_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "file": self.file,
            "line": self.start_line,
            "end_line": self.end_line,
            "snippet": self.snippet,
            "problem": self.problem,
            "fix_constraints": list(self.fix_constraints),
            "do_not": list(self.do_not),
            "verify": list(self.verify),
            "resources": list(self.resources),
            "can_auto_fix": self.can_auto_fix,
            "auto_fix_available": self.auto_fix_available,
            "auto_fix_before": self.auto_fix_before,
            "auto_fix_after": self.auto_fix_after,
        }


@dataclass(frozen=True)
class DependencyFinding:
    """A vulnerability found in a project dependency."""
    rule_id: str              # SEC-DEP-001
    severity: str
    package: str              # e.g. "requests"
    version: str              # e.g. "2.24.0"
    ecosystem: str            # "pip", "npm", "maven", ...
    cve_id: Optional[str]     # CVE-2021-1234 (None if only GH Advisory)
    ghsa_id: Optional[str]    # GHSA-xxxx-xxxx-xxxx
    description: str
    fixed_version: Optional[str]
    source: str               # "CVE" | "GitHub-Advisory" | "Both"
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "cve_id": self.cve_id,
            "ghsa_id": self.ghsa_id,
            "description": self.description,
            "fixed_version": self.fixed_version,
            "source": self.source,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class IgnoreEntry:
    """An ignore entry for a security rule at a specific location."""
    rule_id: str
    file: str                  # Exact file path or glob pattern
    line: Optional[int]         # None = entire file
    reason: str
    created_by: str = "cli"    # "cli" | "config"


# --------------------------------------------------------------------------
# Rule execution types
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class RuleRange:
    """Represents a range of lines modified by a rule."""
    rule_name: str
    start_line: int  # 1-indexed
    end_line: int    # inclusive, 1-indexed

    def overlaps(self, other: "RuleRange") -> bool:
        """Check if this range overlaps with another."""
        return not (self.end_line < other.start_line or other.end_line < self.start_line)


@dataclass(frozen=True)
class RuleChange:
    """A change made by a rule to a specific line range."""
    rule_name: str
    description: str
    start_line: int
    end_line: int


@dataclass
class RuleConflict:
    """A conflict between two rules modifying the same lines.

    Attributes:
        rule_a: Name of the first rule.
        rule_b: Name of the second rule.
        line_range: Tuple of (start_line, end_line) that both rules modified.
        severity: Conflict severity — 'high' (same lines), 'medium' (adjacent lines),
                  'low' (shared blank lines). Defaults to 'medium'.
        description: Optional human-readable description of the conflict.
    """
    rule_a: str
    rule_b: str
    line_range: Tuple[int, int]
    severity: str = "medium"  # 'high', 'medium', 'low'
    description: Optional[str] = None

    def __post_init__(self):
        # Auto-compute severity based on rule pair if not provided
        if self.description is None:
            self.description = self._auto_description()

    def _auto_description(self) -> str:
        """Generate a description based on the conflicting rules."""
        conservative = {
            'ImportCleaningRule', 'NamingConventionRule', 'RefactoringRule',
            'CommentCleaner', 'RedundantExpressionRule', 'DeadCodeRule',
        }
        safe = {
            'IsNotNoneRule', 'RangeLenRule', 'SecurityScannerRule',
            'TypingRule', 'CodeQualityRule', 'PerformanceRule',
        }
        if self.rule_a in conservative or self.rule_b in conservative:
            return (
                f"Conservative rule '{self.rule_a}' and safe rule '{self.rule_b}' "
                f"both modified lines {self.line_range[0]}-{self.line_range[1]}. "
                f"Conservative rules run last and may override safe rule changes."
            )
        return (
            f"CONFLICT: '{self.rule_a}' and '{self.rule_b}' "
            f"both modified lines {self.line_range[0]}-{self.line_range[1]}"
        )

    def __str__(self) -> str:
        return self.description or (
            f"CONFLICT: '{self.rule_a}' and '{self.rule_b}' "
            f"both modified lines {self.line_range[0]}-{self.line_range[1]}"
        )

@dataclass(frozen=True)
class CodeFile:
    """Represents a code file with its content and metadata.

    Attributes:
        path: Path to the file on disk.
        content: Raw source code as a string.
        language: Programming language (default: python).
        ast_tree: Parsed AST tree, attached by RuleEngine after first parse.
        cst_tree: Parsed CST (Concrete Syntax Tree), attached by RuleEngine.
    """
    path: Path
    content: str
    language: str = "python"
    ast_tree: Optional[Any] = None
    cst_tree: Optional[Any] = None

    @property
    def filename(self) -> str:
        return self.path.name

@dataclass(frozen=True)
class TransformationResult:
    """Result of a code transformation operation."""
    original: CodeFile
    transformed_content: str
    changes_made: List[str]
    success: bool
    error: Optional[str] = None
    modified_lines: Optional[List[Tuple[int, int]]] = None  # [(start, end), ...]
    # Security-specific fields
    security_findings: List[SecurityFinding] = field(default_factory=list)
    auto_fix_applied: List[str] = field(default_factory=list)
    dependency_findings: List[DependencyFinding] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return len(self.changes_made) > 0

    @property
    def has_security_findings(self) -> bool:
        return len(self.security_findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.security_findings if f.severity == SecuritySeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.security_findings if f.severity == SecuritySeverity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.security_findings if f.severity == SecuritySeverity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.security_findings if f.severity == SecuritySeverity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.security_findings if f.severity == SecuritySeverity.INFO)

    def severity_summary(self) -> Dict[str, int]:
        return {
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
        }

@dataclass(frozen=True)
class RuleConfig:
    """Configuration for a cleaning rule."""
    enabled: bool = True
    params: Dict[str, Any] = None
    priority: int = 100  # Lower number = runs earlier; ties broken by insertion order
    # Node types this rule is allowed to change semantically.
    # E.g. DeadCodeRule sets {"FunctionDef", "AsyncFunctionDef", "ClassDef"}.
    allowed_semantic_nodes: Optional[Set[str]] = None

    def __post_init__(self):
        if self.params is None:
            object.__setattr__(self, 'params', {})
        if self.allowed_semantic_nodes is None:
            object.__setattr__(self, 'allowed_semantic_nodes', set())
