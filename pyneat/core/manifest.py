"""Manifest export and marker parsing functionality.

This module provides:
- ManifestExporter: Exports markers to .pyneat.manifest.json
- export_to_sarif: Export markers to SARIF format for GitHub Security
- export_to_codeclimate: Export markers to Code Climate format
- export_to_markdown: Export markers to Markdown report
- MarkerParser: Parse PYNAGENT markers from source code and manifest files
"""

import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime
from dataclasses import dataclass, field

from .types import AgentMarker


@dataclass
class Manifest:
    """A manifest file containing all markers for a source file.

    This is a simple data container that mirrors the manifest JSON structure.
    """
    version: str = "1.0"
    source_file: str = ""
    generated_at: str = ""
    total_issues: int = 0
    markers: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Manifest":
        return cls(
            version=data.get("version", "1.0"),
            source_file=data.get("source_file", ""),
            generated_at=data.get("generated_at", ""),
            total_issues=data.get("total_issues", 0),
            markers=data.get("markers", []),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "source_file": self.source_file,
            "generated_at": self.generated_at,
            "total_issues": self.total_issues,
            "markers": self.markers,
        }


# --------------------------------------------------------------------------
# SARIF Export
# --------------------------------------------------------------------------

def export_to_sarif(markers: List[AgentMarker], source_file: Path) -> Dict[str, Any]:
    """Export markers to SARIF 2.1.0 format.

    SARIF is used by GitHub Security tab, Azure DevOps, and other tools.

    Args:
        markers: List of AgentMarker objects to export.
        source_file: The source file being analyzed.

    Returns:
        SARIF-compliant dictionary.
    """
    if not markers:
        return {}

    results = []
    for marker in markers:
        severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }

        results.append({
            "ruleId": f"PYNEAT/{marker.rule_id}/{marker.marker_id}",
            "level": severity_map.get(marker.severity, "warning"),
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
                        "endLine": marker.end_line,
                        "startColumn": marker.column,
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
                    "rules": [
                        {
                            "id": f"PYNEAT/{m.rule_id}/{m.marker_id}",
                            "name": m.rule_id,
                            "shortDescription": {
                                "text": m.issue_type,
                            },
                            "fullDescription": {
                                "text": m.hint or m.why or "",
                            },
                        }
                        for m in markers
                    ],
                },
            },
            "results": results,
        }],
    }


# --------------------------------------------------------------------------
# Code Climate Export
# --------------------------------------------------------------------------

def export_to_codeclimate(markers: List[AgentMarker], source_file: Path) -> List[Dict[str, Any]]:
    """Export markers to Code Climate format.

    Code Climate format is used by the Code Climate CI integration.

    Args:
        markers: List of AgentMarker objects to export.
        source_file: The source file being analyzed.

    Returns:
        List of Code Climate-formatted issues.
    """
    if not markers:
        return []

    severity_map = {
        "critical": "blocker",
        "high": "critical",
        "medium": "major",
        "low": "minor",
        "info": "info",
    }

    results = []
    for marker in markers:
        results.append({
            "type": "ISSUE",
            "check_name": f"pyneat.{marker.rule_id}",
            "description": marker.hint or marker.why or f"Issue: {marker.issue_type}",
            "categories": ["Complexity"],
            "severity": severity_map.get(marker.severity, "major"),
            "location": {
                "path": str(source_file),
                "lines": {
                    "begin": marker.line,
                },
            },
            "remediation_points": 50000 if marker.severity in ("critical", "high") else 10000,
        })

    return results


# --------------------------------------------------------------------------
# Markdown Export
# --------------------------------------------------------------------------

def export_to_markdown(
    markers: List[AgentMarker],
    source_file: Path,
    title: str = "PyNEAT Report",
) -> str:
    """Export markers to a human-readable Markdown report.

    Args:
        markers: List of AgentMarker objects to export.
        source_file: The source file being analyzed.
        title: Title for the report.

    Returns:
        Markdown-formatted report as a string.
    """
    if not markers:
        return f"# {title}\n\nNo issues found.\n"

    severity_emoji = {
        "critical": "[CRITICAL]",
        "high": "[HIGH]",
        "medium": "[MEDIUM]",
        "low": "[LOW]",
        "info": "[INFO]",
    }

    lines = [
        f"# {title}",
        f"\n**File:** `{source_file}`",
        f"**Total Issues:** {len(markers)}",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Issues",
        "",
    ]

    # Group by severity
    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for marker in markers:
        by_severity.get(marker.severity, by_severity["info"]).append(marker)

    for severity in ["critical", "high", "medium", "low", "info"]:
        group = by_severity[severity]
        if not group:
            continue

        lines.append(f"### {severity_emoji.get(severity, '')} {severity.upper()} ({len(group)} issues)")
        lines.append("")

        for marker in group:
            lines.append(f"#### `{marker.marker_id}` - {marker.issue_type}")
            lines.append("")
            if marker.hint:
                lines.append(f"**Hint:** {marker.hint}")
            if marker.why:
                lines.append(f"**Why:** {marker.why}")
            lines.append(f"**Line:** {marker.location}")
            lines.append(f"**Rule:** {marker.rule_id}")
            if marker.cwe_id:
                lines.append(f"**CWE:** {marker.cwe_id}")
            if marker.can_auto_fix:
                lines.append(f"**Auto-fix:** Available")
            lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------
# Manifest Exporter
# --------------------------------------------------------------------------

class ManifestExporter:
    """Export markers to .pyneat.manifest.json files.

    Each manifest file stores all issues detected in a source file,
    allowing tracking over time and CI/CD integration.
    """

    def __init__(self):
        self._markers: List[tuple[AgentMarker, Path, str]] = []

    def add_marker(self, marker: AgentMarker, source_file: Path, source_content: str) -> None:
        """Register a marker for export.

        Args:
            marker: The AgentMarker to add.
            source_file: The source file path.
            source_content: The source file content.
        """
        self._markers.append((marker, source_file, source_content))

    def write(self, source_file: Path) -> Optional[Path]:
        """Write all registered markers to a manifest file.

        Args:
            source_file: The source file (used for naming the manifest).

        Returns:
            Path to the manifest file, or None if no markers registered.
        """
        if not self._markers:
            return None

        manifest_path = source_file.with_suffix(source_file.suffix + ".pyneat.manifest.json")

        manifest_data = {
            "version": "1.0",
            "source_file": str(source_file),
            "generated_at": datetime.now().isoformat(),
            "total_issues": len(self._markers),
            "markers": [marker.to_dict() for marker, _, _ in self._markers],
        }

        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest_data, f, indent=2, ensure_ascii=False)

        return manifest_path

    def clear(self) -> None:
        """Clear all registered markers."""
        self._markers.clear()


# --------------------------------------------------------------------------
# Marker Parser
# --------------------------------------------------------------------------

class MarkerParser:
    """Parse PYNAGENT markers from source code and manifest files."""

    @staticmethod
    def from_source(source: str) -> List[AgentMarker]:
        """Parse PYNAGENT markers from source code.

        Looks for comments in the format: # PYNAGENT: {...json...}

        Args:
            source: The source code content.

        Returns:
            List of AgentMarker objects found in the source.
        """
        import re

        markers = []
        pattern = re.compile(r'#\s*PYNAGENT:\s*(\{.*\})')

        for line_num, line in enumerate(source.splitlines(), start=1):
            match = pattern.search(line)
            if match:
                try:
                    marker_data = json.loads(match.group(1))
                    # Use the actual line number where the marker appears,
                    # NOT the line stored in the JSON (which is the original issue line)
                    marker_data['line'] = line_num
                    marker = AgentMarker.from_dict(marker_data)
                    markers.append(marker)
                except (json.JSONDecodeError, TypeError):
                    # Malformed marker - skip
                    pass

        return markers

    @staticmethod
    def from_manifest(manifest_file: Path) -> List[AgentMarker]:
        """Load markers from a manifest file.

        Args:
            manifest_file: Path to the .pyneat.manifest.json file.

        Returns:
            List of AgentMarker objects loaded from the manifest.
        """
        if not manifest_file.exists():
            return []

        try:
            with open(manifest_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            markers = []
            for marker_data in data.get("markers", []):
                try:
                    marker = AgentMarker.from_dict(marker_data)
                    markers.append(marker)
                except (TypeError, KeyError):
                    pass

            return markers
        except (json.JSONDecodeError, IOError):
            return []

    @staticmethod
    def find_manifest(source_file: Path) -> Optional[Path]:
        """Find the manifest file for a source file.

        Args:
            source_file: Path to the source file.

        Returns:
            Path to the manifest file if it exists, None otherwise.
        """
        manifest_path = source_file.with_suffix(source_file.suffix + ".pyneat.manifest.json")
        return manifest_path if manifest_path.exists() else None


# --------------------------------------------------------------------------
# Module exports
# --------------------------------------------------------------------------

__all__ = [
    'ManifestExporter',
    'MarkerParser',
    'export_to_sarif',
    'export_to_codeclimate',
    'export_to_markdown',
]
