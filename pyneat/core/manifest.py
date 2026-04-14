"""Enhanced SARIF 2.1.0 export with complete CWE/OWASP/CVSS mapping.

Copyright (C) 2026 PyNEAT Authors

This module provides comprehensive SARIF 2.1.0 export with:
- Full CWE database mapping
- OWASP Top 10 2021 mapping
- CVSS 3.1 scoring
- GitHub Code Scanning compatible output
- Multiple runs support
"""

import json
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from dataclasses import dataclass, field

from .types import AgentMarker

from collections import defaultdict


# --------------------------------------------------------------------------
# CWE Database (subset of most common vulnerabilities)
# --------------------------------------------------------------------------

CWE_DATABASE: Dict[str, Dict[str, str]] = {
    "CWE-78": {
        "name": "OS Command Injection",
        "description": "The software constructs all or part of an OS command using externally-influenced input.",
        "weakness_abstraction": "Variant",
    },
    "CWE-79": {
        "name": "Cross-site Scripting",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input.",
        "weakness_abstraction": "Variant",
    },
    "CWE-89": {
        "name": "SQL Injection",
        "description": "The software constructs all or part of an SQL command using externally-influenced input.",
        "weakness_abstraction": "Variant",
    },
    "CWE-90": {
        "name": "LDAP Injection",
        "description": "The software constructs all or part of an LDAP command using externally-influenced input.",
        "weakness_abstraction": "Variant",
    },
    "CWE-94": {
        "name": "Code Injection",
        "description": "The software constructs all or part of a code segment using externally-influenced input.",
        "weakness_abstraction": "Variant",
    },
    "CWE-95": {
        "name": "Eval Injection",
        "description": "The software constructs all or part of an eval statement using externally-influenced input.",
        "weakness_abstraction": "Variant",
    },
    "CWE-22": {
        "name": "Path Traversal",
        "description": "The software uses external input to construct a pathname without proper validation.",
        "weakness_abstraction": "Variant",
    },
    "CWE-23": {
        "name": "Relative Path Traversal",
        "description": "The software uses external input to construct a pathname that should be within a restricted directory.",
        "weakness_abstraction": "Variant",
    },
    "CWE-259": {
        "name": "Hard-coded Password",
        "description": "The software contains a hard-coded password, which it uses for its own inbound authentication.",
        "weakness_abstraction": "Variant",
    },
    "CWE-321": {
        "name": "Use of Hard-coded Cryptographic Key",
        "description": "A hard-coded cryptographic key is used in the software.",
        "weakness_abstraction": "Variant",
    },
    "CWE-322": {
        "name": "Key Exchange without Entity Authentication",
        "description": "The software performs a key exchange without entity authentication.",
        "weakness_abstraction": "Variant",
    },
    "CWE-324": {
        "name": "Use of a Key Past its Expiration Date",
        "description": "The use of a key past its expiration date.",
        "weakness_abstraction": "Variant",
    },
    "CWE-326": {
        "name": "Inadequate Encryption Strength",
        "description": "The software stores or transmits sensitive data using encryption that is too weak.",
        "weakness_abstraction": "Variant",
    },
    "CWE-327": {
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "description": "The software uses a broken or risky cryptographic algorithm.",
        "weakness_abstraction": "Variant",
    },
    "CWE-329": {
        "name": "Not Using a Random IV with CBC Mode",
        "description": "The software does not use a random initialization vector (IV) with CBC mode.",
        "weakness_abstraction": "Variant",
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "The web application does not, or can not, sufficiently verify whether a request was intentionally initiated.",
        "weakness_abstraction": "Variant",
    },
    "CWE-434": {
        "name": "Unrestricted Upload of File with Dangerous Type",
        "description": "The software allows the upload or transfer of files without checking for dangerous types.",
        "weakness_abstraction": "Variant",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": "The software deserializes untrusted data without sufficient validation.",
        "weakness_abstraction": "Variant",
    },
    "CWE-601": {
        "name": "URL Redirection to Untrusted Site",
        "description": "The web application redirects users to untrusted sites.",
        "weakness_abstraction": "Variant",
    },
    "CWE-611": {
        "name": "Information Exposure Through XML External Entity Reference",
        "description": "The software processes an XML document that can reference external entities.",
        "weakness_abstraction": "Variant",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery",
        "description": "The web application fetches a remote resource without validating the user-controlled URL.",
        "weakness_abstraction": "Variant",
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "description": "The software does not validate or incorrectly validates input.",
        "weakness_abstraction": "Base",
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "description": "The product exposes sensitive information to an actor that is not explicitly authorized.",
        "weakness_abstraction": "Base",
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "description": "When an actor claims to have a given identity, the software does not verify it.",
        "weakness_abstraction": "Base",
    },
    "CWE-862": {
        "name": "Missing Authorization",
        "description": "The product does not perform an authorization check when an actor attempts to access a resource.",
        "weakness_abstraction": "Base",
    },
    "CWE-863": {
        "name": "Incorrect Authorization",
        "description": "The product performs an authorization check but the check is incorrect.",
        "weakness_abstraction": "Base",
    },
}


# --------------------------------------------------------------------------
# OWASP Top 10 2021 Mapping
# --------------------------------------------------------------------------

OWASP_TOP10_2021: Dict[str, Dict[str, str]] = {
    "A01": {
        "name": "Broken Access Control",
        "description": "Access control enforces policy such that users cannot act outside of their intended permissions.",
        "impact": "Attackers can access unauthorized functionality and data, such as accessing other users' accounts.",
        "cwe_ids": ["CWE-200", "CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863"],
    },
    "A02": {
        "name": "Cryptographic Failures",
        "description": "The first thing is to determine the protection needs of data in transit and at rest.",
        "impact": "Attackers can steal or modify weakly protected data.",
        "cwe_ids": ["CWE-259", "CWE-295", "CWE-321", "CWE-326", "CWE-327"],
    },
    "A03": {
        "name": "Injection",
        "description": "Some of the more common injections are SQL, NoSQL, OS command, and LDAP injection.",
        "impact": "Attackers can execute arbitrary commands or access data without authorization.",
        "cwe_ids": ["CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-94", "CWE-95"],
    },
    "A04": {
        "name": "Insecure Design",
        "description": "Insecure design is a broad category representing different weaknesses expressed as missing or ineffective control design.",
        "impact": "Attackers can exploit design weaknesses to compromise the application.",
        "cwe_ids": ["CWE-22", "CWE-256", "CWE-269", "CWE-287"],
    },
    "A05": {
        "name": "Security Misconfiguration",
        "description": "The application might be vulnerable if the application server is misconfigured.",
        "impact": "Attackers can exploit misconfigurations to gain unauthorized access.",
        "cwe_ids": ["CWE-16", "CWE-548", "CWE-611"],
    },
    "A06": {
        "name": "Vulnerable and Outdated Components",
        "description": "You are likely vulnerable if you do not know the versions of all components you use.",
        "impact": "Attackers can exploit known vulnerabilities in outdated components.",
        "cwe_ids": ["CWE-1024", "CWE-1035", "CWE-1104"],
    },
    "A07": {
        "name": "Identification and Authentication Failures",
        "description": "Confirmation of the user identity, authentication, and session management is critical.",
        "impact": "Attackers can compromise passwords, keys, session tokens, or exploit implementation flaws.",
        "cwe_ids": ["CWE-287", "CWE-307", "CWE-804", "CWE-836"],
    },
    "A08": {
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations.",
        "impact": "Attackers can modify software, data, or CI/CD configuration.",
        "cwe_ids": ["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502"],
    },
    "A09": {
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, detection, monitoring and active response occurs in most incidents.",
        "impact": "Attackers can maintain persistence, pivot to other systems, and tamper, extract, or destroy data.",
        "cwe_ids": ["CWE-117", "CWE-223", "CWE-778"],
    },
    "A10": {
        "name": "Server-Side Request Forgery",
        "description": "SSRF flaws occur when fetching a remote resource without validating the user-supplied URL.",
        "impact": "Attackers can force the application to send crafted requests to unexpected destinations.",
        "cwe_ids": ["CWE-918"],
    },
}


# --------------------------------------------------------------------------
# Severity to SARIF Level / CVSS Mapping
# --------------------------------------------------------------------------

SEVERITY_TO_SARIF_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

SEVERITY_TO_CVSS: Dict[str, str] = {
    "critical": "9.8",
    "high": "7.8",
    "medium": "5.0",
    "low": "2.0",
    "info": "0.0",
}

SEVERITY_ORDER: List[str] = ["critical", "high", "medium", "low", "info"]


# --------------------------------------------------------------------------
# Enhanced SARIF Export
# --------------------------------------------------------------------------

@dataclass
class SarifRuleDescriptor:
    """Descriptor for a SARIF rule."""
    id: str
    name: str
    short_description: str
    full_description: str
    help: str
    properties: Dict[str, Any]


@dataclass
class SarifResultDescriptor:
    """Descriptor for a SARIF result."""
    rule_id: str
    level: str
    message: str
    file_path: str
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    snippet: str = ""
    cwe_id: Optional[str] = None
    owasp_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[str] = None
    fix_hint: Optional[str] = None
    can_auto_fix: bool = False


def export_to_sarif(
    markers: List[AgentMarker],
    source_file: Path,
    tool_name: str = "PyNEAT",
    tool_version: str = "3.0.0",
    include_driver_info: bool = True,
    include_rules: bool = True,
) -> Dict[str, Any]:
    """Export markers to SARIF 2.1.0 format with full CWE/OWASP/CVSS mapping.

    This is an enhanced version of export_to_sarif() with:
    - Complete CWE database lookup
    - OWASP Top 10 2021 mapping
    - CVSS 3.1 scoring
    - Full rule definitions in tool.driver.rules
    - GitHub Code Scanning compatibility

    Args:
        markers: List of AgentMarker objects to export.
        source_file: The source file being analyzed.
        tool_name: Name of the scanning tool.
        tool_version: Version of the scanning tool.
        include_driver_info: Include full driver information.
        include_rules: Include rule definitions in output.

    Returns:
        SARIF-compliant dictionary (empty dict if no markers).
    """
    if not markers:
        return {}

    # Build rule descriptors (deduplicated)
    rule_map: Dict[str, SarifRuleDescriptor] = {}
    results: List[Dict[str, Any]] = []

    for marker in markers:
        rule_id = f"PYNEAT/{marker.rule_id}/{marker.marker_id}"

        # Get CWE info
        cwe_info = None
        if marker.cwe_id:
            cwe_info = CWE_DATABASE.get(marker.cwe_id, {})

        # Get OWASP mapping
        owasp_ids: List[str] = []
        for owasp_id, owasp_info in OWASP_TOP10_2021.items():
            if marker.cwe_id and marker.cwe_id in owasp_info.get("cwe_ids", []):
                owasp_ids.append(f"OWASP-A{owasp_id[1:]}")

        # Determine SARIF level
        level = SEVERITY_TO_SARIF_LEVEL.get(marker.severity, "warning")
        cvss = SEVERITY_TO_CVSS.get(marker.severity, "5.0")

        # Build rule descriptor
        if rule_id not in rule_map:
            cwe_name = cwe_info.get("name", marker.rule_id) if cwe_info else marker.rule_id
            cwe_desc = cwe_info.get("description", marker.hint or marker.why or "") if cwe_info else (marker.hint or marker.why or "")

            # Build tags
            tags = []
            if marker.cwe_id:
                tags.append(f"CWE-{marker.cwe_id.replace('CWE-', '')}")
            tags.extend(owasp_ids)
            if marker.can_auto_fix:
                tags.append("auto-fixable")

            rule_map[rule_id] = SarifRuleDescriptor(
                id=rule_id,
                name=marker.rule_id,
                short_description=cwe_name,
                full_description=cwe_desc,
                help=f"{marker.hint or marker.why or ''}\n\nFix: {marker.hint or 'No auto-fix available'}",
                properties={
                    "tags": tags,
                    "precision": "very-high",
                    "security-severity": cvss,
                    "problem.severity": marker.severity,
                    "custom": {
                        "issue_type": marker.issue_type,
                        "confidence": marker.confidence,
                        "cwe_id": marker.cwe_id,
                        "can_auto_fix": marker.can_auto_fix,
                        "owasp_ids": owasp_ids,
                    }
                }
            )

        # Build result
        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": marker.hint or marker.why or f"Issue: {marker.issue_type}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(source_file),
                    },
                    "region": {
                        "startLine": marker.line,
                        "endLine": marker.end_line or marker.line,
                        "startColumn": marker.column or 1,
                    },
                },
            }],
            "properties": {
                "issue_type": marker.issue_type,
                "confidence": marker.confidence,
                "cwe_id": marker.cwe_id,
                "can_auto_fix": marker.can_auto_fix,
                "tags": list(rule_map[rule_id].properties.get("tags", [])),
            },
        }

        # Add snippet if available
        if marker.location:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": marker.location
            }

        results.append(result)

    # Build rule definitions
    rules: List[Dict[str, Any]] = []
    if include_rules:
        for rule_id, desc in rule_map.items():
            rules.append({
                "id": desc.id,
                "name": desc.name,
                "shortDescription": {
                    "text": desc.short_description,
                },
                "fullDescription": {
                    "text": desc.full_description,
                },
                "help": {
                    "text": desc.help,
                    "markdown": f"## {desc.name}\n\n{desc.help}",
                },
                "properties": desc.properties,
                "defaultConfiguration": {
                    "enabled": True,
                    "level": "warning",
                    "rank": -1.0,
                },
            })

    # Build driver info
    driver: Dict[str, Any] = {
        "name": tool_name,
        "version": tool_version,
        "informationUri": "https://github.com/pyneat/pyneat",
        "rules": rules,
    }

    # Build SARIF run
    run: Dict[str, Any] = {
        "tool": {
            "driver": driver,
        },
        "results": results,
        "properties": {
            "filename": str(source_file),
            "scan_started": datetime.now().isoformat() + "Z",
            "total_findings": len(results),
        },
    }

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [run],
    }


def export_to_sarif_batch(
    findings_by_file: Dict[str, List[AgentMarker]],
    tool_name: str = "PyNEAT",
    tool_version: str = "3.0.0",
) -> Dict[str, Any]:
    """Export multiple files' findings to SARIF with multiple runs.

    Args:
        findings_by_file: Dict mapping file paths to markers.
        tool_name: Name of the scanning tool.
        tool_version: Version of the scanning tool.

    Returns:
        SARIF report with multiple runs (one per file).
    """
    runs: List[Dict[str, Any]] = []

    for file_path, markers in findings_by_file.items():
        if not markers:
            continue

        sarif = export_to_sarif(
            markers,
            Path(file_path),
            tool_name=tool_name,
            tool_version=tool_version,
        )

        if sarif and "runs" in sarif:
            runs.extend(sarif["runs"])

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": runs,
    }


def get_cwe_info(cwe_id: str) -> Optional[Dict[str, str]]:
    """Get CWE information from the database.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-89").

    Returns:
        Dict with name, description, or None if not found.
    """
    return CWE_DATABASE.get(cwe_id)


def get_owasp_mapping(cwe_id: str) -> List[str]:
    """Get OWASP Top 10 2021 mappings for a CWE.

    Args:
        cwe_id: CWE identifier.

    Returns:
        List of OWASP IDs (e.g., ["OWASP-A03"]).
    """
    results = []
    for owasp_id, info in OWASP_TOP10_2021.items():
        if cwe_id in info.get("cwe_ids", []):
            results.append(f"OWASP-A{owasp_id[1:]}")
    return results


# --------------------------------------------------------------------------
# Legacy export functions (kept for backward compatibility)
# --------------------------------------------------------------------------

def export_to_sarif_legacy(
    markers: List[AgentMarker],
    source_file: Path,
) -> Dict[str, Any]:
    """Legacy SARIF export for backward compatibility.

    This is the original export_to_sarif() function preserved for
    backward compatibility with existing code.

    Args:
        markers: List of AgentMarker objects to export.
        source_file: The source file being analyzed.

    Returns:
        SARIF-compliant dictionary (empty dict if no markers).
    """
    if not markers:
        return {}

    results = []
    for marker in markers:
        results.append({
            "ruleId": f"PYNEAT/{marker.rule_id}/{marker.marker_id}",
            "level": SEVERITY_TO_SARIF_LEVEL.get(marker.severity, "warning"),
            "message": {
                "text": marker.hint or marker.why or f"Issue: {marker.issue_type}",
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(source_file),
                    },
                    "region": {
                        "startLine": marker.line,
                        "endLine": marker.end_line or marker.line,
                        "startColumn": marker.column or 1,
                    },
                },
            }],
            "properties": {
                "issue_type": marker.issue_type,
                "confidence": marker.confidence,
                "cwe_id": marker.cwe_id,
                "can_auto_fix": marker.can_auto_fix,
            },
        })

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PyNEAT",
                    "version": "2.3.0",
                    "informationUri": "https://github.com/pyneat/pyneat",
                    "rules": [],
                },
            },
            "results": results,
        }],
    }


# --------------------------------------------------------------------------
# CodeClimate and Markdown export stubs
# --------------------------------------------------------------------------

def export_to_codeclimate(markers: List[AgentMarker], source_file: Path) -> List[Dict[str, Any]]:
    """Export markers to Code Climate format."""
    results = []
    for m in markers:
        sev = getattr(m, "severity", "info")
        results.append({
            "type": "ISSUE",
            "check_name": f"pyneat.{getattr(m, 'rule_id', 'unknown')}",
            "content": {"body": getattr(m, "hint", "")},
            "categories": ["Security"],
            "severity": sev if sev in ("blocker", "critical", "major", "minor", "info") else "major",
            "location": {
                "path": source_file.name,
                "lines": {"begin": getattr(m, "line", 0)},
            },
        })
    return results


def export_to_markdown(
    markers: List[AgentMarker],
    source_file: Path,
    title: str = "PyNEAT Report",
) -> str:
    """Export markers to Markdown format."""
    if not markers:
        return f"# {title}\n\nNo issues found.\n"
    lines = [f"# {title}\n", f"**Source:** {source_file.name}\n", f"**Total Issues:** {len(markers)}\n\n"]
    lines.append("| ID | Severity | Issue Type | Rule | Line | Description |")
    lines.append("|---|---|---|---|---|---|")
    for m in markers:
        lines.append(
            f"| {getattr(m, 'marker_id', '')} "
            f"| {getattr(m, 'severity', 'info')} "
            f"| {getattr(m, 'issue_type', '')} "
            f"| {getattr(m, 'rule_id', '')} "
            f"| {getattr(m, 'line', 0)} "
            f"| {getattr(m, 'hint', '')} |"
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# MarkerAggregator - helper class for analyzing and grouping markers
# --------------------------------------------------------------------------


class MarkerAggregator:
    """Aggregates and analyzes AgentMarker collections.

    Provides grouping, filtering, and summarization utilities.
    """

    def __init__(self, markers: List[AgentMarker]):
        self.markers = markers

    def by_severity(self) -> Dict[str, List[AgentMarker]]:
        result: Dict[str, List[AgentMarker]] = defaultdict(list)
        for m in self.markers:
            result[m.severity].append(m)
        return dict(result)

    def by_rule(self) -> Dict[str, List[AgentMarker]]:
        result: Dict[str, List[AgentMarker]] = defaultdict(list)
        for m in self.markers:
            result[m.rule_id].append(m)
        return dict(result)

    def by_file(self) -> Dict[str, List[AgentMarker]]:
        result: Dict[str, List[AgentMarker]] = defaultdict(list)
        for m in self.markers:
            path = m.file_path or "unknown"
            result[path].append(m)
        return dict(result)

    def prioritized(self) -> List[AgentMarker]:
        """Sort by priority: critical > high > ... > line."""
        return sorted(self.markers)

    def auto_fixable(self) -> List[AgentMarker]:
        return [m for m in self.markers if m.auto_fix_available]

    def unremediated(self) -> List[AgentMarker]:
        return [m for m in self.markers if not m.remediated]

    def summary(self) -> Dict[str, int]:
        return {
            "total": len(self.markers),
            "critical": len([m for m in self.markers if m.severity == "critical"]),
            "high": len([m for m in self.markers if m.severity == "high"]),
            "medium": len([m for m in self.markers if m.severity == "medium"]),
            "low": len([m for m in self.markers if m.severity == "low"]),
            "info": len([m for m in self.markers if m.severity == "info"]),
            "auto_fixable": len(self.auto_fixable()),
        }


# --------------------------------------------------------------------------
# JUnit XML Export
# --------------------------------------------------------------------------

def _severity_to_junit_level(severity: str) -> str:
    """Map PyNEAT severity to JUnit testcase status."""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "failure",
        "low": "warning",
        "info": "warning",
    }
    return mapping.get(severity, "warning")


def export_to_junit_xml(
    markers: List[AgentMarker],
    source_file: Optional[Path] = None,
    test_name: str = "PyNEAT Scan",
) -> str:
    """Export markers to JUnit XML format for CI/CD pipelines.

    Args:
        markers: List of AgentMarker objects to export.
        source_file: Optional source file path for context.
        test_name: Name for the root test suite.

    Returns:
        JUnit XML string.
    """
    import xml.etree.ElementTree as ET
    from xml.dom import minidom

    testsuite = ET.Element("testsuite", {
        "name": test_name,
        "tests": str(len(markers)),
        "failures": str(len([m for m in markers if m.severity in ("medium", "high", "critical")])),
        "errors": str(len([m for m in markers if m.severity in ("critical", "high")])),
    })

    if source_file:
        testsuite.set("hostname", str(source_file))

    for idx, m in enumerate(markers):
        case = ET.SubElement(testsuite, "testcase", {
            "classname": f"{getattr(m, 'rule_id', 'unknown') or 'unknown'}",
            "name": f"{m.marker_id} - {m.issue_type}",
            "line": str(m.line),
        })
        status = _severity_to_junit_level(m.severity)
        if status in ("error", "failure"):
            failure = ET.SubElement(case, status, {
                "type": getattr(m, 'cwe_id', 'UNKNOWN') or 'UNKNOWN',
                "message": m.hint or m.why or m.issue_type,
            })
            failure.text = _build_junit_message(m)
        elif status == "warning":
            skipped = ET.SubElement(case, "skipped", {
                "type": getattr(m, 'cwe_id', 'UNKNOWN') or 'UNKNOWN',
                "message": m.hint or m.why or m.issue_type,
            })
            skipped.text = _build_junit_message(m)

    rough = ET.ElementTree(testsuite)
    ET.indent(rough, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(testsuite, encoding="unicode")


def _build_junit_message(m: AgentMarker) -> str:
    parts = []
    if m.why:
        parts.append(f"Problem: {m.why}")
    if m.hint:
        parts.append(f"Fix: {m.hint}")
    if m.cwe_id:
        parts.append(f"CWE: {m.cwe_id}")
    if m.owasp_id:
        parts.append(f"OWASP: {m.owasp_id}")
    return "\n".join(parts)


# --------------------------------------------------------------------------
# GitLab SAST Export
# --------------------------------------------------------------------------

def export_to_gitlab_sast(
    markers: List[AgentMarker],
    project: str = "unknown",
) -> Dict[str, Any]:
    """Export markers to GitLab SAST (Static Application Security Testing) format.

    Args:
        markers: List of AgentMarker objects to export.
        project: Project identifier.

    Returns:
        Dict ready for GitLab SAST API consumption.
    """
    results = []
    for m in markers:
        results.append({
            "id": m.marker_id,
            "cve": m.cwe_id,
            "file": m.file_path or "",
            "line": m.line,
            "message": m.hint or m.why or m.issue_type,
            "severity": m.severity,
            "confidence": str(m.confidence),
            "check_name": m.rule_id,
        })
    return {
        "version": "14.0.0",
        "vulnerabilities": results,
        "scan_type": "PyNEAT",
        "project": project,
    }


# --------------------------------------------------------------------------
# SonarQube Generic Issue Export
# --------------------------------------------------------------------------

def _severity_to_sonar(severity: str) -> str:
    mapping = {
        "critical": "BLOCKER",
        "high": "CRITICAL",
        "medium": "MAJOR",
        "low": "MINOR",
        "info": "INFO",
    }
    return mapping.get(severity, "MAJOR")


def _issue_type_from_severity(severity: str) -> str:
    if severity in ("critical", "high"):
        return "VULNERABILITY"
    return "CODE_SMELL"


def export_to_sonarqube(
    markers: List[AgentMarker],
    source_file: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Export markers to SonarQube Generic Issue Import format.

    Args:
        markers: List of AgentMarker objects to export.
        source_file: Optional source file path for context.

    Returns:
        List of SonarQube issue dicts ready for import.
    """
    results = []
    for m in markers:
        file_path = str(source_file) if source_file else (m.file_path or "unknown")
        results.append({
            "engineId": "PyNEAT",
            "ruleId": m.rule_id,
            "severity": _severity_to_sonar(m.severity),
            "type": _issue_type_from_severity(m.severity),
            "message": m.hint or m.why or m.issue_type,
            "line": m.line,
            "file": file_path,
        })
    return results


# --------------------------------------------------------------------------
# HTML Report Export
# --------------------------------------------------------------------------

def export_to_html_report(
    markers: List[AgentMarker],
    title: str = "PyNEAT Security Report",
    template: Optional[Path] = None,
) -> str:
    """Export markers to a self-contained HTML report.

    Args:
        markers: List of AgentMarker objects to export.
        title: Report title.
        template: Optional path to an HTML template file.

    Returns:
        Complete HTML string.
    """
    if template and template.exists():
        return template.read_text()

    severity_colors = {
        "critical": "#b91c1c",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#16a34a",
        "info": "#2563eb",
    }

    grouped = MarkerAggregator(markers).by_severity()
    total = len(markers)

    rows_by_sev = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        items = grouped.get(sev, [])
        if not items:
            continue
        color = severity_colors.get(sev, "#6b7280")
        for m in sorted(items):
            rows_by_sev.append(
                f'<tr style="border-left: 4px solid {color}">'
                f'<td><span class="badge" style="background:{color}">{sev.upper()}</span></td>'
                f'<td><code>{m.marker_id}</code></td>'
                f'<td>{_esc_html(m.issue_type)}</td>'
                f'<td>{_esc_html(m.rule_id)}</td>'
                f'<td>{m.line}</td>'
                f'<td>{_esc_html(m.hint or m.why or "")}</td>'
                f'</tr>'
            )

    rows_html = "\n".join(rows_by_sev) if rows_by_sev else '<tr><td colspan="6">No issues found.</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc_html(title)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 2rem; background: #f9fafb; color: #111827; }}
  .header {{ background: #1f2937; color: #fff; padding: 1.5rem 2rem; border-radius: 8px; margin-bottom: 2rem; }}
  .header h1 {{ margin: 0 0 0.5rem; font-size: 1.5rem; }}
  .summary {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .summary-card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .summary-card .count {{ font-size: 2rem; font-weight: 700; }}
  .summary-card .label {{ font-size: 0.875rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 2rem; }}
  th {{ background: #f3f4f6; padding: 0.75rem 1rem; text-align: left; font-size: 0.875rem; font-weight: 600; color: #374151; }}
  td {{ padding: 0.75rem 1rem; font-size: 0.875rem; border-top: 1px solid #f3f4f6; vertical-align: top; }}
  tr:hover {{ background: #f9fafb; }}
  code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>{_esc_html(title)}</h1>
  <p>Scanned with PyNEAT &bull; {total} issue(s) found &bull; Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>
<div class="summary">
  <div class="summary-card"><div class="count">{total}</div><div class="label">Total</div></div>
  <div class="summary-card"><div class="count" style="color:{severity_colors['critical']}">{len(grouped.get('critical',[]))}</div><div class="label">Critical</div></div>
  <div class="summary-card"><div class="count" style="color:{severity_colors['high']}">{len(grouped.get('high',[]))}</div><div class="label">High</div></div>
  <div class="summary-card"><div class="count" style="color:{severity_colors['medium']}">{len(grouped.get('medium',[]))}</div><div class="label">Medium</div></div>
  <div class="summary-card"><div class="count" style="color:{severity_colors['low']}">{len(grouped.get('low',[]))}</div><div class="label">Low</div></div>
  <div class="summary-card"><div class="count" style="color:{severity_colors['info']}">{len(grouped.get('info',[]))}</div><div class="label">Info</div></div>
</div>
<table>
<thead>
  <tr>
    <th>Severity</th>
    <th>ID</th>
    <th>Issue Type</th>
    <th>Rule</th>
    <th>Line</th>
    <th>Description</th>
  </tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>
</body>
</html>"""
    return html


def _esc_html(s: str) -> str:
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#39;"))


# --------------------------------------------------------------------------
# Module exports
# --------------------------------------------------------------------------

__all__ = [
    'Manifest',
    'ManifestExporter',
    'MarkerParser',
    'MarkerAggregator',
    'export_to_sarif',
    'export_to_sarif_batch',
    'export_to_sarif_legacy',
    'export_to_codeclimate',
    'export_to_markdown',
    'export_to_junit_xml',
    'export_to_gitlab_sast',
    'export_to_sonarqube',
    'export_to_html_report',
    'get_cwe_info',
    'get_owasp_mapping',
    'CWE_DATABASE',
    'OWASP_TOP10_2021',
    'SEVERITY_TO_SARIF_LEVEL',
    'SEVERITY_TO_CVSS',
    'SEVERITY_ORDER',
    'SarifRuleDescriptor',
    'SarifResultDescriptor',
]


# --------------------------------------------------------------------------
# ManifestExporter - collects and writes PYNAGENT markers to manifest files
# --------------------------------------------------------------------------


@dataclass
class Manifest:
    """Manifest data structure for PYNAGENT markers."""
    version: str = "1.0"
    source_file: str = ""
    total_issues: int = 0
    markers: List[Dict[str, Any]] = field(default_factory=list)


class ManifestExporter:
    """Collects PYNAGENT markers and writes them to manifest files."""

    def __init__(self):
        self._markers: Dict[str, List[Dict[str, Any]]] = {}

    def add_marker(self, marker, source_file: Path, source_code: str):
        """Add a PYNAGENT marker for a source file."""
        key = str(source_file)
        if key not in self._markers:
            self._markers[key] = []
        marker_data = {
            "marker_id": getattr(marker, "marker_id", "unknown"),
            "issue_type": getattr(marker, "issue_type", "unknown"),
            "rule_id": getattr(marker, "rule_id", "unknown"),
            "severity": getattr(marker, "severity", "info"),
            "line": getattr(marker, "line", 0),
            "hint": getattr(marker, "hint", ""),
            "why": getattr(marker, "why", ""),
            "confidence": getattr(marker, "confidence", 0.0),
            "snippet": getattr(marker, "snippet", ""),
        }
        self._markers[key].append(marker_data)

    def write(self, source_file: Path) -> Optional[Path]:
        """Write all markers to a manifest JSON file."""
        key = str(source_file)
        if key not in self._markers or not self._markers[key]:
            return None
        manifest_path = source_file.with_suffix(source_file.suffix + ".pyneat.manifest.json")
        manifest_data = {
            "version": "1.0",
            "source_file": source_file.name,
            "total_issues": len(self._markers[key]),
            "markers": self._markers[key],
        }
        import json as _json
        manifest_path.write_text(_json.dumps(manifest_data, indent=2))
        return manifest_path


# --------------------------------------------------------------------------
# MarkerParser - parses PYNAGENT markers from source and manifest files
# --------------------------------------------------------------------------


class MarkerParser:
    """Parses PYNAGENT markers from source code or manifest files.

    Supports multiple comment syntaxes:
      - Python/Shell:   # PYNAGENT: {...}
      - JS/TS:          // PYNAGENT: {...}
      - C/Go/Java/...:  /* PYNAGENT: {...} */
      - SQL:            -- PYNAGENT: {...}
      - HTML:           <!-- PYNAGENT: {...} -->
    """

    # Match # PYNAGENT: or # PYNAGENT: (with optional variant spelling)
    _PYTHON_PATTERN = __import__('re').compile(
        r'#\s*PYNAGENT:\s*(.+)', __import__('re').MULTILINE
    )
    # C-style block comment
    _BLOCK_PATTERN = __import__('re').compile(
        r'/\*\s*PYNAGENT:\s*(.+?)\s*\*/', __import__('re').DOTALL
    )
    # C-style single-line comment (// PYNAGENT:)
    _SLASH_PATTERN = __import__('re').compile(
        r'//\s*PYNAGENT:\s*(.+)', __import__('re').MULTILINE
    )
    # SQL single-line comment
    _SQL_PATTERN = __import__('re').compile(
        r'--\s*PYNAGENT:\s*(.+)', __import__('re').MULTILINE
    )
    # HTML comment
    _HTML_PATTERN = __import__('re').compile(
        r'<!--\s*PYNAGENT:\s*(.+?)\s*-->', __import__('re').DOTALL
    )

    _ALL_PATTERNS = None  # lazily built

    @classmethod
    def _patterns(cls):
        if cls._ALL_PATTERNS is None:
            cls._ALL_PATTERNS = [
                cls._PYTHON_PATTERN,
                cls._SLASH_PATTERN,
                cls._BLOCK_PATTERN,
                cls._SQL_PATTERN,
                cls._HTML_PATTERN,
            ]
        return cls._ALL_PATTERNS

    @staticmethod
    def from_source(source: str) -> List[AgentMarker]:
        """Parse PYNAGENT markers from source code comments."""
        import json as _json

        markers = []
        all_text = []
        for pat in MarkerParser._patterns():
            all_text.extend(pat.findall(source))

        for raw in all_text:
            raw = raw.strip()
            if not raw:
                continue
            # Handle both JSON objects and plain text values
            if raw.startswith("{") and raw.endswith("}"):
                try:
                    data = _json.loads(raw)
                    line = source[:source.find(raw.rstrip("}"))].count("\n") + 1
                    marker = AgentMarker(
                        marker_id=data.get("marker_id", ""),
                        issue_type=data.get("issue_type", ""),
                        rule_id=data.get("rule_id", ""),
                        severity=data.get("severity", "info"),
                        line=line,
                        hint=data.get("hint", ""),
                        why=data.get("why", ""),
                        impact=data.get("impact"),
                        confidence_note=data.get("confidence_note"),
                        confidence=data.get("confidence", 0.0),
                        snippet=data.get("snippet", ""),
                        cwe_id=data.get("cwe_id"),
                        owasp_id=data.get("owasp_id"),
                        cvss_score=data.get("cvss_score"),
                        cvss_vector=data.get("cvss_vector"),
                        file_path=data.get("file_path"),
                        detected_at=data.get("detected_at"),
                        remediated=data.get("remediated", False),
                        remediated_at=data.get("remediated_at"),
                        language=data.get("language"),
                    )
                    markers.append(marker)
                except Exception:
                    pass
        return markers

    @staticmethod
    def from_manifest(manifest_file: Path) -> List[AgentMarker]:
        """Load PYNAGENT markers from a manifest JSON file."""
        if not manifest_file.exists():
            return []
        try:
            import json as _json
            data = _json.loads(manifest_file.read_text())
            markers = []
            for m in data.get("markers", []):
                markers.append(AgentMarker(
                    marker_id=m.get("marker_id", ""),
                    issue_type=m.get("issue_type", ""),
                    rule_id=m.get("rule_id", ""),
                    severity=m.get("severity", "info"),
                    line=m.get("line", 0),
                    hint=m.get("hint", ""),
                    why=m.get("why", ""),
                    impact=m.get("impact"),
                    confidence_note=m.get("confidence_note"),
                    confidence=m.get("confidence", 0.0),
                    snippet=m.get("snippet", ""),
                    cwe_id=m.get("cwe_id"),
                    owasp_id=m.get("owasp_id"),
                    cvss_score=m.get("cvss_score"),
                    cvss_vector=m.get("cvss_vector"),
                    file_path=m.get("file_path"),
                    detected_at=m.get("detected_at"),
                    remediated=m.get("remediated", False),
                    remediated_at=m.get("remediated_at"),
                    language=m.get("language"),
                ))
            return markers
        except Exception:
            return []

    @staticmethod
    def find_manifest(source_file: Path) -> Optional[Path]:
        """Find the manifest file for a source file."""
        manifest = source_file.with_suffix(source_file.suffix + ".pyneat.manifest.json")
        return manifest if manifest.exists() else None

