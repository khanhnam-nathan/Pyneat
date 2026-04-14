"""Domain types and data models.

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

For commercial licensing, contact: license@pyneat.dev
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set, ClassVar
from collections import defaultdict
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
    ln_ast: Optional[Any] = None  # Language-Neutral AST from Rust parser

    @property
    def filename(self) -> str:
        return self.path.name

@dataclass(frozen=True)
class AgentMarker:
    """A marker/issue detected by a rule for agent handoff.

    Contains full context for tracking, fixing, and reporting issues.
    Designed for agent-to-agent communication and manifest export.
    """
    marker_id: str                              # Unique identifier, e.g. "PYN-001"
    issue_type: str                             # e.g. "sql_injection", "unused_import"
    rule_id: str                                # e.g. "SecurityScannerRule", "DeadCodeRule"
    severity: str = "medium"                    # "critical", "high", "medium", "low", "info"
    line: int = 1                              # 1-indexed start line
    end_line: Optional[int] = None             # 1-indexed end line (None = same as line)
    column: int = 0                            # 0-indexed column
    hint: Optional[str] = None                 # Suggested fix
    why: Optional[str] = None                 # Why this is a problem
    impact: Optional[str] = None             # Consequences if exploited
    confidence_note: Optional[str] = None     # Why confidence = X (e.g. "regex-only match")
    confidence: float = 1.0                    # 0.0 - 1.0 detection confidence
    can_auto_fix: bool = False                 # Whether auto-fix is conceptually possible
    fix_diff: Optional[str] = None             # Unified diff for the fix
    snippet: Optional[str] = None              # Code snippet (max 200 chars)
    cwe_id: Optional[str] = None               # CWE-89, CWE-79, ...
    auto_fix_available: bool = False           # Whether auto-fix is implemented
    auto_fix_before: Optional[str] = None      # Code before fix
    auto_fix_after: Optional[str] = None       # Code after fix
    requires_user_input: bool = False          # Whether fix needs user confirmation
    related_markers: Tuple[str, ...] = field(default_factory=tuple)  # Related marker IDs
    # New fields
    owasp_id: Optional[str] = None             # OWASP-A03
    cvss_score: Optional[float] = None        # 9.8
    cvss_vector: Optional[str] = None         # CVSS:3.1/AV:N/AC:L/...
    file_path: Optional[str] = None            # Full path đầy đủ
    detected_at: Optional[str] = None          # ISO timestamp
    remediated: bool = False                   # Đã fix chưa
    remediated_at: Optional[str] = None         # Khi nào fix
    fix_constraints: Tuple[str, ...] = field(default_factory=tuple)  # Ràng buộc khi fix
    do_not: Tuple[str, ...] = field(default_factory=tuple)          # Sai lầm thường gặp
    verify: Tuple[str, ...] = field(default_factory=tuple)          # Cách verify fix
    resources: Tuple[str, ...] = field(default_factory=tuple)         # Link tài liệu
    language: Optional[str] = None           # python, javascript, java, go, rust, csharp, php, ruby

    # Supported languages (used for validation)
    SUPPORTED_LANGUAGES: ClassVar[Tuple[str, ...]] = (
        "python", "javascript", "typescript", "java", "go", "rust", "csharp", "php", "ruby"
    )

    def __post_init__(self):
        # Auto-set end_line to line if not provided
        if self.end_line is None:
            object.__setattr__(self, 'end_line', self.line)
        # Validation
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be in [0.0, 1.0], got {self.confidence}")
        valid_severities = SecuritySeverity.all_levels()
        if self.severity not in valid_severities:
            raise ValueError(f"invalid severity: {self.severity}, must be one of {valid_severities}")
        if self.line < 1:
            raise ValueError(f"line must be >= 1, got {self.line}")
        if self.language is not None and self.language not in self.SUPPORTED_LANGUAGES:
            raise ValueError(
                f"invalid language: {self.language}, must be one of {self.SUPPORTED_LANGUAGES}"
            )
        # Auto-normalize tuple fields
        for fname in ("related_markers", "fix_constraints", "do_not", "verify", "resources"):
            val = getattr(self, fname)
            if val is None:
                object.__setattr__(self, fname, ())
            elif not isinstance(val, tuple):
                object.__setattr__(self, fname, tuple(val) if val else ())

    def __lt__(self, other: "AgentMarker") -> bool:
        """So sánh theo severity (critical > high > medium > low > info), rồi theo line."""
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self_order = order.get(self.severity, 5)
        other_order = order.get(other.severity, 5)
        if self_order != other_order:
            return self_order < other_order
        return self.line < other.line

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AgentMarker):
            return False
        return self.marker_id == other.marker_id

    def __hash__(self) -> int:
        return hash(self.marker_id)

    def __repr__(self) -> str:
        return f"AgentMarker({self.marker_id}, {self.issue_type}, line={self.line}, severity={self.severity})"

    @property
    def location(self) -> str:
        return f"line {self.line}" + (f"-{self.end_line}" if self.end_line != self.line else "")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for JSON output."""
        return {
            "marker_id": self.marker_id,
            "issue_type": self.issue_type,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": self.line,
            "end_line": self.end_line,
            "column": self.column,
            "hint": self.hint,
            "why": self.why,
            "impact": self.impact,
            "confidence_note": self.confidence_note,
            "confidence": self.confidence,
            "can_auto_fix": self.can_auto_fix,
            "fix_diff": self.fix_diff,
            "snippet": self.snippet,
            "cwe_id": self.cwe_id,
            "auto_fix_available": self.auto_fix_available,
            "auto_fix_before": self.auto_fix_before,
            "auto_fix_after": self.auto_fix_after,
            "requires_user_input": self.requires_user_input,
            "related_markers": list(self.related_markers),
            "owasp_id": self.owasp_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "file_path": self.file_path,
            "detected_at": self.detected_at,
            "remediated": self.remediated,
            "remediated_at": self.remediated_at,
            "fix_constraints": list(self.fix_constraints),
            "do_not": list(self.do_not),
            "verify": list(self.verify),
            "resources": list(self.resources),
            "language": self.language,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentMarker":
        """Deserialize from dict."""
        # Normalize tuple fields
        tuple_fields = ("related_markers", "fix_constraints", "do_not", "verify", "resources")
        for fname in tuple_fields:
            if fname in data and isinstance(data[fname], list):
                data = {**data, fname: tuple(data[fname])}
        return cls(**data)

    def to_json(self) -> str:
        """Serialize to JSON string."""
        import json
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "AgentMarker":
        """Deserialize from JSON string."""
        import json
        return cls.from_dict(json.loads(json_str))

    def to_comment(self) -> str:
        """Serialize to a PYNAGENT source code comment.

        Format: # PYNAGENT: {"marker_id":"...", "issue_type":"...", ...}
        """
        import json
        data = self.to_dict()
        # Truncate long fields for comment readability
        for key in ("snippet", "fix_diff", "auto_fix_before", "auto_fix_after"):
            if data.get(key) and len(data[key]) > 80:
                data[key] = data[key][:77] + "..."
        json_str = json.dumps(data, ensure_ascii=False)
        return f"# PYNAGENT: {json_str}"


# --------------------------------------------------------------------------
# MarkerIdGenerator - centralized singleton marker ID generation
# --------------------------------------------------------------------------


class MarkerIdGenerator:
    """Centralized marker ID generation ensuring uniqueness and consistency.

    Singleton pattern so counters persist across all rules within a scan session.
    """

    PREFIXES: Dict[str, str] = {
        "security": "PYN-SEC",
        "quality": "PYN-QAL",
        "ai": "PYN-AI",
        "deadcode": "PYN-DC",
        "import": "PYN-IMP",
        "naming": "PYN-NAM",
        "refactor": "PYN-REF",
        "default": "PYN",
    }

    _instance: Optional["MarkerIdGenerator"] = None

    def __new__(cls) -> "MarkerIdGenerator":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._counters: Dict[str, int] = defaultdict(int)
        return cls._instance

    def __init__(self):
        pass

    def generate(self, rule_id: str, category: Optional[str] = None) -> str:
        """Generate a unique marker ID.

        Args:
            rule_id: The rule identifier (e.g. "SEC-001").
            category: Optional category override (security, quality, ai, etc.).

        Returns:
            Unique marker ID string (e.g. "PYN-SEC-0001").
        """
        if category is None:
            category = self._infer_category(rule_id)
        prefix = self.PREFIXES.get(category, "PYN")
        self._counters[category] += 1
        return f"{prefix}-{self._counters[category]:04d}"

    def _infer_category(self, rule_id: str) -> str:
        rule_lower = rule_id.lower()
        if "security" in rule_lower or rule_lower.startswith("sec"):
            return "security"
        if "ai" in rule_lower:
            return "ai"
        if "dead" in rule_lower or "unused" in rule_lower:
            return "deadcode"
        if "import" in rule_lower:
            return "import"
        if "naming" in rule_lower:
            return "naming"
        if "quality" in rule_lower or "refactor" in rule_lower:
            return "refactor"
        return "default"

    def reset(self) -> None:
        """Reset counters (for testing or new scan session)."""
        self._counters.clear()

    def get_counts(self) -> Dict[str, int]:
        return dict(self._counters)


# --------------------------------------------------------------------------
# SecurityFinding -> AgentMarker conversion
# --------------------------------------------------------------------------


def security_finding_to_marker(
    finding: SecurityFinding,
    marker_id: Optional[str] = None,
    language: Optional[str] = None,
    file_path: Optional[str] = None,
) -> AgentMarker:
    """Convert a SecurityFinding to an AgentMarker.

    Args:
        finding: The SecurityFinding to convert.
        marker_id: Optional pre-assigned marker ID; if None, a new one is generated.
        language: Language of the source file (e.g. "python", "javascript").
        file_path: Optional override for file path; defaults to finding.file.

    Returns:
        A fully-populated AgentMarker with all available fields mapped.
    """
    from datetime import datetime as _dt

    if marker_id is None:
        generator = MarkerIdGenerator()
        marker_id = generator.generate(finding.rule_id, "security")

    return AgentMarker(
        marker_id=marker_id,
        issue_type=finding.rule_id.lower().replace("sec-", "security_"),
        rule_id=finding.rule_id,
        severity=finding.severity,
        line=finding.start_line,
        end_line=finding.end_line,
        hint=finding.fix_constraints[0] if finding.fix_constraints else None,
        why=finding.problem,
        confidence=finding.confidence,
        can_auto_fix=finding.can_auto_fix,
        auto_fix_available=finding.auto_fix_available,
        auto_fix_before=finding.auto_fix_before,
        auto_fix_after=finding.auto_fix_after,
        snippet=finding.snippet,
        cwe_id=finding.cwe_id,
        owasp_id=finding.owasp_id,
        cvss_score=finding.cvss_score,
        cvss_vector=finding.cvss_vector,
        file_path=file_path if file_path is not None else finding.file,
        language=language,
        detected_at=_dt.now().isoformat() + "Z",
        fix_constraints=finding.fix_constraints,
        do_not=finding.do_not,
        verify=finding.verify,
        resources=finding.resources,
    )


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
    # Agent marker field
    agent_markers: List[AgentMarker] = field(default_factory=list)

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
