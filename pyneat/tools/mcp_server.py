"""MCP Server for PyNEAT — STDIO JSON-RPC 2.0.

This module implements the Model Context Protocol over stdio, allowing
Cursor and other MCP-compatible editors to invoke PyNEAT scans as tools.

Run as:
    python -m pyneat.tools.mcp_server
    pyneat mcp

JSON-RPC 2.0 error codes:
    -32700  Parse error
    -32600  Invalid request
    -32601  Method not found
    -32602  Invalid params
    -32603  Internal error

Copyright (c) 2026 PyNEAT Authors
Licensed under GNU AGPL v3.
"""

from __future__ import annotations

import sys
import json
import logging
import io
import os
import re
import signal
import threading
import queue
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed

# PyNEAT core imports
from pyneat.core.engine import RuleEngine
from pyneat.core.types import CodeFile, AgentMarker, TransformationResult
from pyneat.core import manifest_schema
from pyneat.core.manifest_schema import PyneatManifest, SeveritySummary, load_manifest_or_fail, diff_manifests, format_diff
from pyneat.rules.imports import ImportCleaningRule
from pyneat.rules.naming import NamingConventionRule
from pyneat.rules.refactoring import RefactoringRule
from pyneat.rules.security import SecurityScannerRule
from pyneat.rules.quality import CodeQualityRule
from pyneat.rules.performance import PerformanceRule
from pyneat.rules.debug import DebugCleaner
from pyneat.rules.comments import CommentCleaner
from pyneat.rules.unused import UnusedImportRule
from pyneat.rules.redundant import RedundantExpressionRule
from pyneat.rules.is_not_none import IsNotNoneRule
from pyneat.rules.magic_numbers import MagicNumberRule
from pyneat.rules.init_protection import InitFileProtectionRule
from pyneat.rules.deadcode import DeadCodeRule
from pyneat.rules.fstring import FStringRule
from pyneat.rules.range_len_pattern import RangeLenRule
from pyneat.rules.typing import TypingRule
from pyneat.rules.match_case import MatchCaseRule
from pyneat.rules.dataclass import DataclassSuggestionRule

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# MCP Protocol constants
# ----------------------------------------------------------------------

MCP_VERSION = "2024-11-05"
SERVER_NAME = "pyneat"
SERVER_VERSION = "3.0.0"

# JSON-RPC 2.0 error codes
ERROR_PARSE_ERROR = -32700
ERROR_INVALID_REQUEST = -32600
ERROR_METHOD_NOT_FOUND = -32601
ERROR_INVALID_PARAMS = -32602
ERROR_INTERNAL_ERROR = -32603

# ----------------------------------------------------------------------
# Tool definitions
# ----------------------------------------------------------------------

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "pyneat_scan",
        "description": (
            "Scan code for security and quality issues, returning AgentMarker[] "
            "with full guidance including fix hints, CWE/OWASP mapping, and "
            "auto-fix diffs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Source code to scan (multiline string).",
                },
                "language": {
                    "type": "string",
                    "description": "Programming language (python, javascript, typescript, java, go, rust, etc.). "
                                  "Defaults to 'python'.",
                    "default": "python",
                },
            },
            "required": ["code"],
        },
    },
    {
        "name": "pyneat_scan_file",
        "description": "Scan an entire file on disk for security and quality issues.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file to scan.",
                },
                "language": {
                    "type": "string",
                    "description": "Programming language override (auto-detected from extension if omitted).",
                },
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "pyneat_explain",
        "description": "Get full rule metadata including description, CWE, OWASP, CVSS, fix guidance, "
                       "and code examples for a specific rule or issue type.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_id": {
                    "type": "string",
                    "description": "Rule ID (e.g., 'SecurityScannerRule', 'DeadCodeRule', 'sql_injection').",
                },
                "issue_type": {
                    "type": "string",
                    "description": "Optional issue type to look up metadata for (e.g., 'sql_injection').",
                },
            },
        },
    },
    {
        "name": "pyneat_auto_fix",
        "description": "Apply the auto-fix for a specific marker identified by marker_id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "marker_id": {
                    "type": "string",
                    "description": "The marker ID to fix (e.g., 'PYN-SEC-0001').",
                },
                "code": {
                    "type": "string",
                    "description": "The source code containing the issue.",
                },
                "language": {
                    "type": "string",
                    "description": "Programming language of the code.",
                    "default": "python",
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "If true, return the diff without applying changes.",
                    "default": False,
                },
            },
            "required": ["marker_id", "code"],
        },
    },
    {
        "name": "pyneat_aggregate",
        "description": "Merge multiple markers into a PyNEAT project manifest (YAML), "
                       "tracking lifecycle, severity summary, and diff against previous scans.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "markers_json": {
                    "type": "string",
                    "description": "JSON array of AgentMarker objects (serialized via marker.to_dict()).",
                },
                "project": {
                    "type": "string",
                    "description": "Project name for the manifest.",
                    "default": "unknown",
                },
                "output_path": {
                    "type": "string",
                    "description": "Optional path to save the manifest YAML file.",
                },
                "previous_manifest_path": {
                    "type": "string",
                    "description": "Optional path to a previous manifest for computing diff.",
                },
            },
            "required": ["markers_json"],
        },
    },
    {
        "name": "pyneat_compare",
        "description": "Compare two PyNEAT manifest files and return a diff report "
                       "showing new, remediated, and unchanged markers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "current_manifest_path": {
                    "type": "string",
                    "description": "Path to the current manifest YAML file.",
                },
                "previous_manifest_path": {
                    "type": "string",
                    "description": "Path to the previous manifest YAML file.",
                },
            },
            "required": ["current_manifest_path", "previous_manifest_path"],
        },
    },
    {
        "name": "pyneat_lint_prompt",
        "description": "Check AI/LLM prompt strings in code for security issues such as "
                       "prompt injection, credential leakage, and unsafe dynamic evaluation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Source code containing AI prompts to audit.",
                },
                "language": {
                    "type": "string",
                    "description": "Programming language of the code.",
                    "default": "python",
                },
            },
            "required": ["code"],
        },
    },
    {
        "name": "pyneat_list_rules",
        "description": "List all available PyNEAT rules with their names, descriptions, "
                       "enabled status, and priorities.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]

# ----------------------------------------------------------------------
# Rule metadata registry
# ----------------------------------------------------------------------

RULE_METADATA: Dict[str, Dict[str, Any]] = {
    "SecurityScannerRule": {
        "description": "Detects security vulnerabilities including SQL injection, XSS, command injection, "
                       "hardcoded secrets, insecure deserialization, and more.",
        "severity_range": "critical - info",
        "cwe_ids": ["CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-94", "CWE-95", "CWE-502",
                    "CWE-601", "CWE-611", "CWE-798", "CWE-918"],
        "owasp_ids": ["A01", "A02", "A03", "A05", "A06", "A07", "A08", "A10"],
        "can_auto_fix": True,
        "auto_fix_types": ["HardcodedSecretReplacement", "InsecureDeserializationFix", "InputValidation"],
        "resources": [
            "https://owasp.org/Top10/",
            "https://cwe.mitre.org/data/definitions/659.html",
        ],
    },
    "DeadCodeRule": {
        "description": "Detects and removes unused imports, variables, functions, and classes.",
        "severity_range": "low",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["UnusedImportRemoval", "UnusedVariableRemoval", "UnusedFunctionRemoval"],
        "resources": [],
    },
    "ImportCleaningRule": {
        "description": "Cleans and organizes import statements, removing duplicates and sorting.",
        "severity_range": "low",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["ImportDeduplication", "ImportSorting"],
        "resources": [],
    },
    "CodeQualityRule": {
        "description": "Enforces code quality standards including line length, complexity limits, "
                       "and proper naming conventions.",
        "severity_range": "low - medium",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["LineLengthTrimming", "ComplexityReduction"],
        "resources": [],
    },
    "PerformanceRule": {
        "description": "Detects common performance anti-patterns such as inefficient loops, "
                       "N+1 queries, and unnecessary list copies.",
        "severity_range": "low - medium",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["LoopOptimization", "ListComprehensionConversion"],
        "resources": [],
    },
    "TypingRule": {
        "description": "Checks for proper type hints and annotations.",
        "severity_range": "low",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["TypeHintAddition"],
        "resources": [],
    },
    "MagicNumberRule": {
        "description": "Detects magic numbers that should be named constants.",
        "severity_range": "low",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["MagicNumberToConstant"],
        "resources": [],
    },
    "FStringRule": {
        "description": "Promotes f-string usage over %-formatting and .format().",
        "severity_range": "low",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["FormatStringToFString"],
        "resources": [],
    },
    "IsNotNoneRule": {
        "description": "Enforces 'if x is not None' over 'if x != None'.",
        "severity_range": "low",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["IsNotNoneCorrection"],
        "resources": [],
    },
    "RangeLenRule": {
        "description": "Enforces 'for x in range(len(seq))' → 'for x in seq' patterns.",
        "severity_range": "low",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["RangeLenToDirectIteration"],
        "resources": [],
    },
    "RedundantExpressionRule": {
        "description": "Detects redundant expressions like 'if x == True' → 'if x'.",
        "severity_range": "low",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["RedundantExpressionRemoval"],
        "resources": [],
    },
    "NamingConventionRule": {
        "description": "Enforces PEP 8 naming conventions for classes, functions, and variables.",
        "severity_range": "low",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["NamingConventionFix"],
        "resources": ["https://peps.python.org/pep-0008/"],
    },
    "UnusedImportRule": {
        "description": "Detects imported names that are never used in the module.",
        "severity_range": "low",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["UnusedImportRemoval"],
        "resources": [],
    },
    "DebugCleaner": {
        "description": "Removes debug print statements and commented-out debug code.",
        "severity_range": "low",
        "cwe_ids": ["CWE-489"],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["DebugStatementRemoval"],
        "resources": [],
    },
    "CommentCleaner": {
        "description": "Cleans up unnecessary comments, fixmes, and TODOs.",
        "severity_range": "low",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": True,
        "auto_fix_types": ["CommentCleanup"],
        "resources": [],
    },
    "InitFileProtectionRule": {
        "description": "Protects __init__.py files from unwanted modifications.",
        "severity_range": "info",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": False,
        "auto_fix_types": [],
        "resources": [],
    },
    "DataclassSuggestionRule": {
        "description": "Suggests converting classes to dataclasses when appropriate.",
        "severity_range": "low",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": False,
        "auto_fix_types": [],
        "resources": ["https://docs.python.org/3/library/dataclasses.html"],
    },
    "MatchCaseRule": {
        "description": "Suggests using match/case statements instead of long if/elif chains.",
        "severity_range": "low",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": False,
        "auto_fix_types": [],
        "resources": ["https://peps.python.org/pep-0634/"],
    },
    "RefactoringRule": {
        "description": "Detects refactoring opportunities such as long functions, deep nesting, "
                       "and complex boolean expressions.",
        "severity_range": "medium",
        "cwe_ids": [],
        "owasp_ids": [],
        "can_auto_fix": False,
        "auto_fix_types": [],
        "resources": [],
    },
}

# Issue-type-level metadata (for generic lookups)
ISSUE_TYPE_METADATA: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "cwe_id": "CWE-89",
        "owasp_id": "A03",
        "severity": "critical",
        "cvss_base": 9.8,
        "problem": "User-controlled data flows into a SQL query without proper sanitization.",
        "fix_constraints": [
            "Use parameterized queries (placeholders) instead of string concatenation",
            "Never insert user input directly into SQL strings",
            "Use an ORM when possible for automatic query parameterization",
        ],
        "do_not": [
            "Don't use string formatting or f-strings for SQL queries",
            "Don't assume input is safe because it comes from a trusted user",
        ],
        "verify": [
            "Confirm all database queries use parameterized statements",
            "Run automated SQL injection test cases",
        ],
        "resources": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },
    "command_injection": {
        "cwe_id": "CWE-78",
        "owasp_id": "A03",
        "severity": "critical",
        "cvss_base": 9.8,
        "problem": "User input is passed to a shell command without sanitization.",
        "fix_constraints": [
            "Use subprocess with a list of arguments instead of shell=True",
            "Avoid shell=True when executing external commands",
            "Validate and sanitize all user input before using in commands",
        ],
        "do_not": [
            "Don't use os.system() or subprocess with shell=True",
            "Don't concatenate user input into command strings",
        ],
        "verify": [
            "Review all subprocess calls for shell=True usage",
            "Audit input validation before command execution",
        ],
        "resources": [
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    },
    "xss": {
        "cwe_id": "CWE-79",
        "owasp_id": "A03",
        "severity": "medium",
        "cvss_base": 6.1,
        "problem": "Unescaped user input is rendered in HTML/JavaScript output.",
        "fix_constraints": [
            "Escape all user input before rendering in HTML",
            "Use templating engines with auto-escaping enabled",
            "Set Content-Security-Policy headers",
        ],
        "do_not": [
            "Don't use innerHTML with user input",
            "Don't use document.write()",
        ],
        "verify": [
            "Test with XSS payloads in all user-input fields",
            "Enable browser XSS auditors",
        ],
        "resources": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },
    "hardcoded_secret": {
        "cwe_id": "CWE-798",
        "owasp_id": "A02",
        "severity": "high",
        "cvss_base": 7.5,
        "problem": "A hardcoded credential (password, API key, token) is present in source code.",
        "fix_constraints": [
            "Move secrets to environment variables",
            "Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)",
            "Never commit secrets to version control",
        ],
        "do_not": [
            "Don't hardcode passwords or API keys in source code",
            "Don't commit .env files with real credentials",
        ],
        "verify": [
            "Search for common secret patterns in code",
            "Run git-secrets or similar tools in CI",
        ],
        "resources": [
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
    },
    "prompt_injection": {
        "cwe_id": "CWE-20",
        "owasp_id": "A03",
        "severity": "high",
        "cvss_base": 8.1,
        "problem": "AI prompt strings contain unsanitized user input, risking prompt injection attacks.",
        "fix_constraints": [
            "Separate system prompts from user data using clear delimiters",
            "Validate and sanitize user input before inserting into prompts",
            "Use structured output parsing instead of regex on LLM responses",
            "Implement input filtering for common injection patterns",
        ],
        "do_not": [
            "Don't concatenate raw user input into system prompts",
            "Don't trust LLM outputs without validation",
            "Don't use prompts as authorization mechanisms",
        ],
        "verify": [
            "Test prompts with injection payloads (e.g., 'Ignore previous instructions')",
            "Review prompt construction for user-input leakage",
        ],
        "resources": [
            "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
            "https://github.com/NVIDIA/gtec/blob/main/papers/prompt-injection-survey.pdf",
        ],
    },
    "insecure_deserialization": {
        "cwe_id": "CWE-502",
        "owasp_id": "A08",
        "severity": "critical",
        "cvss_base": 9.8,
        "problem": "Untrusted data is deserialized without validation, potentially enabling RCE.",
        "fix_constraints": [
            "Use JSON instead of pickle or YAML for cross-process serialization",
            "If pickle is required, use a signed digest to verify payload integrity",
            "Enable type checking on deserialized objects",
        ],
        "do_not": [
            "Don't unpickle untrusted data",
            "Don't use yaml.load() without a safe Loader",
        ],
        "verify": [
            "Audit all deserialize() calls for untrusted data sources",
            "Use bandit or similar SAST tools",
        ],
        "resources": [
            "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
            "https://cwe.mitre.org/data/definitions/502.html",
        ],
    },
    "path_traversal": {
        "cwe_id": "CWE-22",
        "owasp_id": "A01",
        "severity": "critical",
        "cvss_base": 8.6,
        "problem": "File path constructed from user input without validation allows directory traversal.",
        "fix_constraints": [
            "Resolve paths with os.path.realpath() and validate against a root directory",
            "Use allowlists for permitted filenames",
            "Never use user input directly in file paths",
        ],
        "do_not": [
            "Don't use user input directly in os.path.join()",
            "Don't rely on string manipulation to sanitize paths",
        ],
        "verify": [
            "Test with path traversal payloads: ../../../etc/passwd",
            "Audit all file operations using user input",
        ],
        "resources": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    },
    "ssrf": {
        "cwe_id": "CWE-918",
        "owasp_id": "A10",
        "severity": "high",
        "cvss_base": 8.6,
        "problem": "User-supplied URL is fetched without validation, potentially hitting internal services.",
        "fix_constraints": [
            "Validate URLs against an allowlist of permitted domains",
            "Block private IP ranges (10.x, 192.168.x, 172.16-31.x) in URLs",
            "Use URL parsing libraries and check hostname before fetching",
        ],
        "do_not": [
            "Don't fetch URLs without validating the hostname",
            "Don't follow redirects without checking the destination",
        ],
        "verify": [
            "Test with internal URLs: http://169.254.169.254/, http://localhost/",
            "Audit all HTTP requests for user-controlled URLs",
        ],
        "resources": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
    },
}

# ----------------------------------------------------------------------
# RuleEngine factory
# ----------------------------------------------------------------------


def _build_engine() -> RuleEngine:
    """Build a fully-configured RuleEngine with all standard rules."""
    rules = [
        ImportCleaningRule(),
        UnusedImportRule(),
        NamingConventionRule(),
        RefactoringRule(),
        SecurityScannerRule(),
        CodeQualityRule(),
        PerformanceRule(),
        DebugCleaner(),
        CommentCleaner(),
        RedundantExpressionRule(),
        DeadCodeRule(),
        FStringRule(),
        IsNotNoneRule(),
        MagicNumberRule(),
        InitFileProtectionRule(),
        RangeLenRule(),
        TypingRule(),
        MatchCaseRule(),
        DataclassSuggestionRule(),
    ]
    return RuleEngine(rules=rules)


# ----------------------------------------------------------------------
# MCP request/response helpers
# ----------------------------------------------------------------------


def make_response(request_id: Any, result: Any) -> Dict[str, Any]:
    """Build a JSON-RPC 2.0 success response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


def make_error_response(request_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    """Build a JSON-RPC 2.0 error response."""
    resp: Dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }
    if data is not None:
        resp["error"]["data"] = data
    return resp


def _serialize_marker(marker: AgentMarker) -> Dict[str, Any]:
    """Serialize an AgentMarker to a dict for text output."""
    return marker.to_dict()


def _format_marker_text(marker: AgentMarker) -> str:
    """Format a single marker as readable text."""
    lines = [
        f"=== {marker.marker_id} ===",
        f"  Type:      {marker.issue_type}",
        f"  Rule:      {marker.rule_id}",
        f"  Severity:  {marker.severity.upper()}",
        f"  Location:  line {marker.line}" + (f"-{marker.end_line}" if marker.end_line != marker.line else ""),
    ]
    if marker.severity in ("critical", "high"):
        if marker.cwe_id:
            lines.append(f"  CWE:       {marker.cwe_id}")
        if marker.owasp_id:
            lines.append(f"  OWASP:     {marker.owasp_id}")
        if marker.cvss_score:
            lines.append(f"  CVSS:      {marker.cvss_score}")
    if marker.why:
        lines.append(f"  WHY:       {marker.why}")
    if marker.hint:
        lines.append(f"  HINT:      {marker.hint}")
    if marker.impact:
        lines.append(f"  IMPACT:    {marker.impact}")
    if marker.snippet:
        snippet = marker.snippet.replace("\n", "\\n")
        lines.append(f"  SNIPPET:   {snippet[:120]}")
    if marker.confidence < 1.0:
        note = marker.confidence_note or f"{marker.confidence:.0%} confidence"
        lines.append(f"  NOTE:      {note}")
    if marker.can_auto_fix and marker.auto_fix_available:
        lines.append(f"  AUTO-FIX:  available")
        if marker.auto_fix_diff:
            lines.append(f"  DIFF:")
            for diff_line in marker.auto_fix_diff.split("\n")[:6]:
                lines.append(f"    {diff_line}")
    if marker.fix_constraints:
        lines.append(f"  FIX CONSTRAINTS:")
        for fc in marker.fix_constraints[:3]:
            lines.append(f"    - {fc}")
    if marker.do_not:
        lines.append(f"  DO NOT:")
        for dn in marker.do_not[:3]:
            lines.append(f"    - {dn}")
    if marker.verify:
        lines.append(f"  VERIFY:")
        for v in marker.verify[:3]:
            lines.append(f"    - {v}")
    if marker.resources:
        lines.append(f"  RESOURCES:")
        for r in marker.resources[:3]:
            lines.append(f"    - {r}")
    return "\n".join(lines)


def _format_markers_text(markers: List[AgentMarker]) -> str:
    """Format a list of markers as readable text grouped by severity."""
    if not markers:
        return "No issues found."

    severity_order = ["critical", "high", "medium", "low", "info"]
    sections = []

    for sev in severity_order:
        sev_markers = [m for m in markers if m.severity == sev]
        if not sev_markers:
            continue
        sections.append(f"\n## {sev.upper()} severity ({len(sev_markers)} issue(s))\n")
        for m in sev_markers:
            sections.append(_format_marker_text(m))
            sections.append("")

    summary = [
        f"Total: {len(markers)} issue(s)",
        f"  Critical: {len([m for m in markers if m.severity == 'critical'])}",
        f"  High:     {len([m for m in markers if m.severity == 'high'])}",
        f"  Medium:   {len([m for m in markers if m.severity == 'medium'])}",
        f"  Low:      {len([m for m in markers if m.severity == 'low'])}",
        f"  Info:     {len([m for m in markers if m.severity == 'info'])}",
    ]

    return "\n".join(["SCAN SUMMARY", "=" * 60] + summary) + "\n" + "\n".join(sections)


# ----------------------------------------------------------------------
# Tool handlers
# ----------------------------------------------------------------------


def _handle_scan(code: str, language: str = "python") -> str:
    """Scan code and return formatted marker text."""
    engine = _build_engine()
    code_file = CodeFile(path=Path("<input>"), content=code, language=language)
    result: TransformationResult = engine.process_code_file(code_file)

    if not result.agent_markers:
        return "No issues found."

    return _format_markers_text(result.agent_markers)


def _handle_scan_file(file_path: str, language: Optional[str] = None) -> str:
    """Scan a file and return formatted marker text."""
    path = Path(file_path)
    if not path.exists():
        return f"ERROR: File not found: {file_path}"

    engine = _build_engine()
    result = engine.process_file(path, language=language or "auto")

    if not result.agent_markers:
        return f"No issues found in {file_path}."

    return _format_markers_text(result.agent_markers)


def _handle_explain(rule_id: Optional[str] = None, issue_type: Optional[str] = None) -> str:
    """Get full rule metadata as formatted text."""
    # Try rule_id first
    if rule_id:
        rule_meta = RULE_METADATA.get(rule_id)
        if rule_meta:
            lines = [
                f"Rule: {rule_id}",
                "=" * 60,
                f"Description: {rule_meta['description']}",
                f"Severity range: {rule_meta['severity_range']}",
                f"Can auto-fix: {rule_meta['can_auto_fix']}",
            ]
            if rule_meta["cwe_ids"]:
                lines.append(f"CWE IDs: {', '.join(rule_meta['cwe_ids'])}")
            if rule_meta["owasp_ids"]:
                lines.append(f"OWASP IDs: {', '.join(rule_meta['owasp_ids'])}")
            if rule_meta["auto_fix_types"]:
                lines.append(f"Auto-fix types: {', '.join(rule_meta['auto_fix_types'])}")
            if rule_meta["resources"]:
                lines.append("Resources:")
                for r in rule_meta["resources"]:
                    lines.append(f"  - {r}")
            return "\n".join(lines)

    # Try issue_type lookup
    if issue_type:
        key = issue_type.lower().replace(" ", "_").replace("-", "_")
        issue_meta = ISSUE_TYPE_METADATA.get(key)
        if issue_meta:
            lines = [
                f"Issue Type: {issue_type}",
                "=" * 60,
                f"Problem: {issue_meta['problem']}",
                f"Severity: {issue_meta['severity'].upper()}",
                f"CVSS Base: {issue_meta['cvss_base']}",
                f"CWE: {issue_meta['cwe_id']}",
                f"OWASP: {issue_meta['owasp_id']}",
            ]
            lines.append("Fix Constraints:")
            for fc in issue_meta["fix_constraints"]:
                lines.append(f"  - {fc}")
            lines.append("Common Mistakes to Avoid:")
            for dn in issue_meta["do_not"]:
                lines.append(f"  - {dn}")
            lines.append("Verification Steps:")
            for v in issue_meta["verify"]:
                lines.append(f"  - {v}")
            lines.append("Resources:")
            for r in issue_meta["resources"]:
                lines.append(f"  - {r}")
            return "\n".join(lines)

    # Fallback: list all available rules
    lines = ["Available rules:"]
    for name, meta in sorted(RULE_METADATA.items()):
        lines.append(f"  {name}: {meta['description'][:80]}...")
    return "\n".join(lines)


def _handle_auto_fix(marker_id: str, code: str, language: str = "python", dry_run: bool = False) -> str:
    """Apply auto-fix for a marker."""
    engine = _build_engine()
    code_file = CodeFile(path=Path("<input>"), content=code, language=language)
    result = engine.process_code_file(code_file)

    # Find the marker
    target = None
    for m in result.agent_markers:
        if m.marker_id == marker_id:
            target = m
            break

    if target is None:
        return f"ERROR: Marker '{marker_id}' not found in scan results."

    if not target.auto_fix_available:
        return (
            f"Marker {marker_id} is not auto-fixable.\n"
            f"HINT: {target.hint or 'No hint available.'}\n"
            f"WHY: {target.why or 'No explanation available.'}"
        )

    if target.auto_fix_before and target.auto_fix_after:
        diff = f"--- before\n+++ after\n{marker_id}: {target.auto_fix_after}"
        if dry_run:
            return f"[DRY RUN] Auto-fix diff for {marker_id}:\n{diff}"
        else:
            return (
                f"[DRY RUN] Auto-fix available for {marker_id}:\n{diff}\n\n"
                f"Note: For safety, pyneat_auto_fix performs dry-run by default.\n"
                f"Apply the fix manually or use the CLI: pyneat fix <file>"
            )

    return (
        f"Auto-fix for {marker_id} is available but the fix diff was not pre-computed.\n"
        f"Use the CLI to apply: pyneat fix --marker {marker_id} <file>"
    )


def _handle_aggregate(
    markers_json: str,
    project: str = "unknown",
    output_path: Optional[str] = None,
    previous_manifest_path: Optional[str] = None,
) -> str:
    """Aggregate markers into a manifest."""
    try:
        markers_data = json.loads(markers_json)
    except json.JSONDecodeError as e:
        return f"ERROR: Invalid JSON in markers_json: {e}"

    if not isinstance(markers_data, list):
        return "ERROR: markers_json must be a JSON array of AgentMarker objects."

    markers = []
    for m_dict in markers_data:
        try:
            markers.append(AgentMarker.from_dict(m_dict))
        except Exception as e:
            return f"ERROR: Failed to parse marker: {e}"

    # Build manifest
    manifest = PyneatManifest(
        project=project,
        tool_version="3.0.0",
        markers=[m.to_dict() for m in markers],
        files_scanned=["<aggregated>"],
        total_files=1,
        summary=SeveritySummary.from_markers(markers),
    )

    # Diff against previous manifest if provided
    diff_text = ""
    if previous_manifest_path:
        try:
            prev_manifest = load_manifest_or_fail(Path(previous_manifest_path))
            manifest.mark_previous(prev_manifest)
            diff = manifest.compute_diff(prev_manifest)
            diff_text = "\n\n" + format_diff(diff)
        except FileNotFoundError:
            diff_text = f"\n\nWARNING: Previous manifest not found: {previous_manifest_path}"

    result = [
        "PyNEAT Manifest",
        "=" * 60,
        f"Version:     {manifest.version}",
        f"Scan ID:     {manifest.scan_id}",
        f"Project:     {manifest.project}",
        f"Created:     {manifest.created_at}",
        f"Score:       {manifest.score:.1f} ({manifest.grade})",
        f"Total:       {len(markers)} findings",
        f"  Critical:  {manifest.summary.critical}",
        f"  High:      {manifest.summary.high}",
        f"  Medium:    {manifest.summary.medium}",
        f"  Low:       {manifest.summary.low}",
        f"  Info:      {manifest.summary.info}",
    ]

    # Save if output path provided
    if output_path:
        try:
            manifest.save(Path(output_path))
            result.append(f"\nSaved to: {output_path}")
        except Exception as e:
            result.append(f"\nWARNING: Could not save manifest: {e}")
    else:
        result.append("\n(No output path provided; manifest not saved.)")

    result.append(diff_text)
    return "\n".join(result)


def _handle_compare(current_manifest_path: str, previous_manifest_path: str) -> str:
    """Compare two manifests."""
    try:
        current = load_manifest_or_fail(Path(current_manifest_path))
    except FileNotFoundError:
        return f"ERROR: Current manifest not found: {current_manifest_path}"
    except Exception as e:
        return f"ERROR: Failed to load current manifest: {e}"

    try:
        previous = load_manifest_or_fail(Path(previous_manifest_path))
    except FileNotFoundError:
        return f"ERROR: Previous manifest not found: {previous_manifest_path}"
    except Exception as e:
        return f"ERROR: Failed to load previous manifest: {e}"

    diff = diff_manifests(current, previous)
    return format_diff(diff)


def _handle_lint_prompt(code: str, language: str = "python") -> str:
    """Lint AI prompts for security issues."""
    engine = _build_engine()
    code_file = CodeFile(path=Path("<input>"), content=code, language=language)
    result = engine.process_code_file(code_file)

    # Filter for AI/prompt-related markers
    ai_markers = [
        m for m in result.agent_markers
        if "prompt" in m.issue_type.lower()
        or "ai" in m.issue_type.lower()
        or m.rule_id in ("SecurityScannerRule",)
        or (m.cwe_id and m.cwe_id in ("CWE-20", "CWE-78", "CWE-79", "CWE-89"))
    ]

    # Additional heuristic scan for prompt patterns
    issues: List[str] = []
    prompt_patterns = [
        (r'["\'](system|user|assistant)["\']\s*[:=]', "Likely LLM prompt dict key"),
        (r'f["\'][^"\']*\{[^}]*(input|user|request)[^}]*\}[^"\']*["\']', "f-string with user input in prompt"),
        (r'format\s*\([^)]*(input|user|request)[^)]*\)', ".format() with user input in prompt"),
        (r'["\'].*ignore.*instruction.*["\']', "Possible prompt injection payload"),
        (r'["\'].*forget.*all.*previous.*["\']', "Possible prompt injection payload"),
        (r'["\'].*new.*instruction.*["\']', "Possible prompt injection payload"),
        (r'os\.environ\[', "Environment variable in prompt (check for secret leakage)"),
        (r'os\.getenv\(', "Environment variable in prompt (check for secret leakage)"),
    ]

    for line_no, line in enumerate(code.splitlines(), 1):
        for pattern, desc in prompt_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                snippet = line.strip()[:80]
                issues.append(
                    f"[LINE {line_no}] {desc}\n"
                    f"  Code: {snippet}"
                )

    if not ai_markers and not issues:
        return "No prompt security issues detected."

    output = ["AI Prompt Security Audit", "=" * 60]

    if ai_markers:
        output.append(f"\nPyNEAT detected {len(ai_markers)} issue(s):")
        for m in ai_markers:
            output.append(_format_marker_text(m))

    if issues:
        output.append(f"\nHeuristic detection found {len(issues)} potential issue(s):")
        for issue in issues:
            output.append(issue)

    return "\n".join(output)


def _handle_list_rules() -> str:
    """List all available rules."""
    engine = _build_engine()
    stats = engine.get_rule_stats()

    lines = ["PyNEAT Rules", "=" * 60]
    lines.append(f"Total rules: {stats['total_rules']} | Enabled: {stats['enabled_rules']}")
    lines.append("")

    for rule_info in stats["rules"]:
        enabled = "ON" if rule_info["enabled"] else "OFF"
        lines.append(f"  [{enabled}] {rule_info['name']}")
        desc = rule_info["description"] or ""
        if desc:
            lines.append(f"         {desc[:80]}")
        lines.append(f"         priority={rule_info['priority']}")
        lines.append("")

    return "\n".join(lines)


# ----------------------------------------------------------------------
# JSON-RPC 2.0 dispatcher
# ----------------------------------------------------------------------


def _dispatch_method(method: str, params: Dict[str, Any]) -> Tuple[Any, Optional[int], Optional[str]]:
    """Dispatch a method call and return (result, error_code, error_message).

    On success, returns (result, None, None).
    On error, returns (None, error_code, error_message).
    """
    if method == "initialize":
        return {
            "protocolVersion": MCP_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }, None, None

    elif method == "tools/list":
        return {"tools": TOOLS}, None, None

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}

        if not tool_name:
            return None, ERROR_INVALID_PARAMS, "Missing required parameter: name"

        try:
            if tool_name == "pyneat_scan":
                code = arguments.get("code", "")
                language = arguments.get("language", "python")
                if not code:
                    return None, ERROR_INVALID_PARAMS, "Missing required parameter: code"
                return _handle_scan(code, language), None, None

            elif tool_name == "pyneat_scan_file":
                file_path = arguments.get("file_path", "")
                language = arguments.get("language")
                if not file_path:
                    return None, ERROR_INVALID_PARAMS, "Missing required parameter: file_path"
                return _handle_scan_file(file_path, language), None, None

            elif tool_name == "pyneat_explain":
                rule_id = arguments.get("rule_id")
                issue_type = arguments.get("issue_type")
                return _handle_explain(rule_id, issue_type), None, None

            elif tool_name == "pyneat_auto_fix":
                marker_id = arguments.get("marker_id", "")
                code = arguments.get("code", "")
                language = arguments.get("language", "python")
                dry_run = arguments.get("dry_run", False)
                if not marker_id:
                    return None, ERROR_INVALID_PARAMS, "Missing required parameter: marker_id"
                if not code:
                    return None, ERROR_INVALID_PARAMS, "Missing required parameter: code"
                return _handle_auto_fix(marker_id, code, language, dry_run), None, None

            elif tool_name == "pyneat_aggregate":
                markers_json = arguments.get("markers_json", "[]")
                project = arguments.get("project", "unknown")
                output_path = arguments.get("output_path")
                previous_manifest_path = arguments.get("previous_manifest_path")
                if not markers_json:
                    return None, ERROR_INVALID_PARAMS, "Missing required parameter: markers_json"
                return _handle_aggregate(
                    markers_json, project, output_path, previous_manifest_path
                ), None, None

            elif tool_name == "pyneat_compare":
                current = arguments.get("current_manifest_path", "")
                previous = arguments.get("previous_manifest_path", "")
                if not current or not previous:
                    return None, ERROR_INVALID_PARAMS, "Missing both current_manifest_path and previous_manifest_path"
                return _handle_compare(current, previous), None, None

            elif tool_name == "pyneat_lint_prompt":
                code = arguments.get("code", "")
                language = arguments.get("language", "python")
                if not code:
                    return None, ERROR_INVALID_PARAMS, "Missing required parameter: code"
                return _handle_lint_prompt(code, language), None, None

            elif tool_name == "pyneat_list_rules":
                return _handle_list_rules(), None, None

            else:
                return None, ERROR_METHOD_NOT_FOUND, f"Unknown tool: {tool_name}"

        except Exception as e:
            logger.exception("Error handling tool %s", tool_name)
            return None, ERROR_INTERNAL_ERROR, f"Internal error in {tool_name}: {str(e)}"

    else:
        return None, ERROR_METHOD_NOT_FOUND, f"Method not found: {method}"


# ----------------------------------------------------------------------
# MCP content format helpers
# ----------------------------------------------------------------------


def _build_tool_content(text: str) -> List[Dict[str, Any]]:
    """Build MCP tool content array from text result."""
    return [
        {
            "type": "text",
            "text": text,
        }
    ]


def _build_call_result(tool_name: str, text: str, is_error: bool = False) -> Dict[str, Any]:
    """Build a tools/call result in MCP format."""
    return {
        "content": _build_tool_content(text),
        "isError": is_error,
    }


# ----------------------------------------------------------------------
# STDIO reader — threaded non-blocking approach
# ----------------------------------------------------------------------


class _StdinReader:
    """Non-blocking stdin reader using a background thread.

    Uses sys.stdin.buffer (raw binary) to read chunks, decodes them,
    and splits on newlines. Complete lines are put in a queue for the
    main loop to process without blocking.

    This approach avoids issues with TextIOWrapper buffering that can
    occur when iterating over sys.stdin in a background thread, especially
    when stdin is redirected from a subprocess.
    """

    def __init__(self):
        self._q: queue.Queue = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._stopped = False
        self._buffer = b""

    def _reader_loop(self) -> None:
        """Background thread: read binary stdin in chunks and extract lines."""
        try:
            # Get raw binary stdin buffer
            stdin_buffer = getattr(sys.stdin, "buffer", None)
            if stdin_buffer is None:
                self._stopped = True
                self._q.put(_EOF_SENTINEL)
                return

            while not self._stopped:
                try:
                    chunk = stdin_buffer.read(4096)
                except (OSError, IOError):
                    break

                if not chunk:
                    # EOF — process any remaining data in buffer
                    break

                self._buffer += chunk

                # Extract complete lines
                while b"\n" in self._buffer:
                    line_bytes, self._buffer = self._buffer.split(b"\n", 1)
                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    if line:
                        self._q.put(line)

            # Flush any remaining data after EOF
            if self._buffer.strip():
                line = self._buffer.decode("utf-8", errors="replace").strip()
                if line:
                    self._q.put(line)

        except Exception:
            pass
        finally:
            self._q.put(_EOF_SENTINEL)

    def start(self) -> None:
        """Start the background reader thread."""
        self._thread = threading.Thread(target=self._reader_loop, daemon=True, name="mcp-stdin")
        self._thread.start()

    def read_messages(self) -> List[str]:
        """Read all currently-available messages from the queue.

        Returns a list of raw JSON strings (still JSON-encoded).
        Empty list means no complete messages available yet.
        """
        messages = []
        while True:
            try:
                item = self._q.get_nowait()
                if item is _EOF_SENTINEL:
                    self._stopped = True
                    return messages
                messages.append(item)
            except queue.Empty:
                return messages

    @property
    def eof(self) -> bool:
        return self._stopped or (self._thread is not None and not self._thread.is_alive())


_EOF_SENTINEL = object()


# ----------------------------------------------------------------------
# Main server loop
# ----------------------------------------------------------------------


def _write_message(message: Dict[str, Any]) -> None:
    """Write a JSON-RPC message to stdout."""
    try:
        line = json.dumps(message, ensure_ascii=False)
        if hasattr(sys.stdout, "buffer"):
            sys.stdout.buffer.write((line + "\n").encode("utf-8"))
            sys.stdout.buffer.flush()
        else:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
    except Exception as e:
        logger.error("Failed to write to stdout: %s", e)


def _process_message(raw_message: str, initialized: bool) -> Optional[Dict[str, Any]]:
    """Process a single JSON-RPC message.

    Args:
        raw_message: Raw JSON string of the request.
        initialized: Whether the server has been initialized.

    Returns:
        A JSON-RPC response dict, or None for notifications (no response needed).
    """
    try:
        request = json.loads(raw_message)
    except json.JSONDecodeError as e:
        return make_error_response(None, ERROR_PARSE_ERROR, f"Parse error: {e}")

    # Handle batch requests
    if isinstance(request, list):
        responses = []
        for item in request:
            resp = _process_single(item, initialized)
            if resp is not None:
                responses.append(resp)
        if responses:
            return responses
        return None

    return _process_single(request, initialized)


def _process_single(request: Dict[str, Any], initialized: bool) -> Optional[Dict[str, Any]]:
    """Process a single JSON-RPC request."""
    # Validate request structure
    if not isinstance(request, dict):
        return make_error_response(
            request.get("id") if isinstance(request, dict) else None,
            ERROR_INVALID_REQUEST,
            "Request must be a JSON object"
        )

    method = request.get("method")

    # Notifications (no id) don't get a response
    if method is None:
        return None

    request_id = request.get("id")

    # Check initialization
    if method != "initialize" and not initialized:
        return make_error_response(
            request_id, ERROR_INVALID_REQUEST,
            "Server not initialized. Send 'initialize' request first."
        )

    # Extract params
    params = request.get("params") or {}

    # Dispatch
    if method == "tools/call":
        result, err_code, err_msg = _dispatch_method(method, params)
        if err_code is not None:
            return make_error_response(request_id, err_code, err_msg)

        tool_name = params.get("name", "unknown")
        # tools/call returns a structured result with content array
        return make_response(request_id, _build_call_result(tool_name, result))

    else:
        result, err_code, err_msg = _dispatch_method(method, params)
        if err_code is not None:
            return make_error_response(request_id, err_code, err_msg)
        return make_response(request_id, result)


def main() -> None:
    """Run the MCP server over stdio."""
    # Set up logging to stderr so it doesn't corrupt stdout
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    # Suppress noisy library loggers
    for lib in ("urllib3", "requests", "charset_normalizer"):
        logging.getLogger(lib).setLevel(logging.CRITICAL)

    reader = _StdinReader()
    reader.start()
    initialized = False

    while True:
        try:
            messages = reader.read_messages()

            if reader.eof:
                # stdin closed; drain any remaining queued messages first
                remaining = reader.read_messages()
                if remaining:
                    messages.extend(remaining)
                if not messages:
                    break

            if not messages:
                # No complete messages yet, sleep briefly to avoid busy loop
                time.sleep(0.01)
                continue

            for raw_message in messages:
                response = _process_message(raw_message, initialized)

                if response is None:
                    continue

                # Handle batch responses
                if isinstance(response, list):
                    for r in response:
                        _write_message(r)
                else:
                    _write_message(response)

                # Mark initialized after successful initialize
                if isinstance(response, dict):
                    result = response.get("result", {})
                    if isinstance(result, dict) and result.get("protocolVersion"):
                        initialized = True

        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.exception("Unhandled exception in MCP server loop")
            _write_message(make_error_response(None, ERROR_INTERNAL_ERROR, f"Server error: {e}"))

    # Clean exit
    sys.exit(0)


if __name__ == "__main__":
    main()
