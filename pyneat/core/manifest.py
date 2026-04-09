"""Agent-to-Agent marker system for AI editor handoff.

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

For commercial licensing, contact: n.khanhnam@gmail.com
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

from pyneat.core.types import AgentMarker


# --------------------------------------------------------------------------
# Manifest — collection of markers for one source file
# --------------------------------------------------------------------------

@dataclass
class Manifest:
    """A manifest containing all AgentMarkers for a source file.

    Written alongside the source file as <filename>.pyneat.manifest.json
    """
    version: str = "1.0"
    source_file: str = ""
    source_hash: str = ""  # MD5 of source content at scan time
    generated_at: str = ""
    tool: str = "PyNEAT"
    tool_version: str = "2.0.0"
    total_issues: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    markers: List[Dict[str, Any]] = field(default_factory=list)

    def add_marker(self, marker: AgentMarker) -> None:
        """Add a marker and update summary fields."""
        self.markers.append(marker.to_dict())
        self.total_issues = len(self.markers)
        self.by_severity[marker.severity] = self.by_severity.get(marker.severity, 0) + 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# ManifestExporter — writes manifests to disk
# --------------------------------------------------------------------------

class ManifestExporter:
    """Exports AgentMarkers to .pyneat.manifest.json sidecar files.

    Usage:
        exporter = ManifestExporter()
        exporter.add_marker(marker, source_file=Path("app.py"))
        exporter.write(Path("app.py"))
    """

    def __init__(self):
        self._markers_by_file: Dict[str, List[AgentMarker]] = {}
        self._source_hashes: Dict[str, str] = {}

    def add_marker(self, marker: AgentMarker, source_file: Path, source_content: str = "") -> None:
        """Register a marker for a source file."""
        import hashlib
        key = str(source_file.resolve())
        if key not in self._markers_by_file:
            self._markers_by_file[key] = []
        self._markers_by_file[key].append(marker)
        if source_content:
            self._source_hashes[key] = hashlib.md5(source_content.encode()).hexdigest()

    def write(self, source_file: Path) -> Optional[Path]:
        """Write manifest JSON file next to source file.

        Returns the manifest file path, or None if no markers.
        """
        key = str(source_file.resolve())
        markers = self._markers_by_file.get(key, [])
        if not markers:
            return None

        from pyneat import __version__
        import hashlib

        manifest = Manifest(
            version="1.0",
            source_file=str(source_file),
            source_hash=self._source_hashes.get(key, ""),
            generated_at=datetime.now().isoformat() + "Z",
            tool="PyNEAT",
            tool_version=__version__,
            total_issues=len(markers),
            by_severity={},
            markers=[],
        )

        for m in markers:
            manifest.add_marker(m)

        manifest_path = source_file.with_suffix(source_file.suffix + ".pyneat.manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest.to_dict(), f, indent=2, ensure_ascii=False)

        return manifest_path

    def write_all(self) -> List[Path]:
        """Write all pending manifest files.

        Returns list of written manifest paths.
        """
        paths = []
        for source_str in list(self._markers_by_file.keys()):
            source_path = Path(source_str)
            p = self.write(source_path)
            if p:
                paths.append(p)
        return paths

    def clear(self) -> None:
        """Clear all pending markers."""
        self._markers_by_file.clear()
        self._source_hashes.clear()


# --------------------------------------------------------------------------
# MarkerParser — read markers back from source code or manifest
# --------------------------------------------------------------------------

class MarkerParser:
    """Parse PYNAGENT markers from source code or manifest files."""

    PYNAGENT_RE = __import__('re').compile(
        r'#\s*PYNAGENT:\s*(\{.*\})'
    )

    @classmethod
    def from_source(cls, source: str) -> List[AgentMarker]:
        """Extract all PYNAGENT markers from source code."""
        markers = []
        for line_no, line in enumerate(source.splitlines(), start=1):
            match = cls.PYNAGENT_RE.search(line)
            if match:
                try:
                    marker = AgentMarker.from_json(match.group(1))
                    object.__setattr__(marker, 'line', line_no)
                    markers.append(marker)
                except Exception:
                    pass
        return markers

    @classmethod
    def from_manifest(cls, manifest_path: Path) -> List[AgentMarker]:
        """Load markers from a .pyneat.manifest.json file."""
        if not manifest_path.exists():
            return []
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            return [AgentMarker.from_dict(m) for m in data.get("markers", [])]
        except Exception:
            return []

    @classmethod
    def find_manifest(cls, source_file: Path) -> Optional[Path]:
        """Find the manifest file corresponding to a source file."""
        manifest = source_file.with_suffix(source_file.suffix + ".pyneat.manifest.json")
        return manifest if manifest.exists() else None


# --------------------------------------------------------------------------
# Multi-format exporters — SARIF, CodeClimate, Markdown, GJSON
# All use Manifest or List[AgentMarker] as input for stability.
# --------------------------------------------------------------------------

def _severity_to_sarif_level(severity: str) -> str:
    """Map PyNEAT severity to SARIF level."""
    return {"critical": "error", "high": "error", "medium": "warning",
            "low": "note", "info": "note"}.get(severity, "warning")


def _marker_to_sarif_location(marker: AgentMarker, base_path: str) -> Dict[str, Any]:
    """Build SARIF Location dict from an AgentMarker."""
    return {
        "physicalLocation": {
            "artifactLocation": {
                "uri": base_path,
                "uriBaseId": "%SRCROOT%",
            },
            "region": {
                "startLine": marker.line,
                "endLine": marker.line,
                "snippet": {"text": marker.snippet} if marker.snippet else None,
            },
        },
    }


def export_to_sarif(
    markers: List[AgentMarker],
    source_file: Path,
    tool_version: str = "2.0.0",
    include_fix: bool = True,
) -> Dict[str, Any]:
    """Export markers to SARIF 2.1.0 format.

    Compatible with: GitHub Code Scanning, Azure DevOps, GitLab SAST,
    Semgrep CI, and any SARIF-compatible viewer.

    Args:
        markers: List of AgentMarkers to export.
        source_file: Path to the source file (used for location URI).
        tool_version: PyNEAT version string.
        include_fix: Include fix guidance in the help.text field.

    Returns:
        A SARIF 2.1.0-compatible dict ready for json.dump.
    """
    if not markers:
        return {}

    base_path = str(source_file)
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for m in markers:
        rule_id = f"PYNEAT/{m.rule_id}/{m.marker_id}"
        if rule_id not in rules:
            help_text = ""
            if include_fix and m.hint:
                help_text = f"Hint: {m.hint}"
            if m.cwe_id:
                help_text += f"\nCWE: {m.cwe_id}"
            if m.why:
                help_text += f"\nWhy: {m.why}"

            rules[rule_id] = {
                "id": rule_id,
                "name": m.rule_id,
                "shortDescription": {"text": f"[{m.severity.upper()}] {m.issue_type}: {m.hint}"},
                "fullDescription": {"text": m.why or m.issue_type},
                "defaultConfiguration": {"level": _severity_to_sarif_level(m.severity)},
                "help": {
                    "text": help_text,
                    "markdown": f"## {m.marker_id}: {m.issue_type}\n\n**Severity:** {m.severity}\n\n**Hint:** {m.hint}\n\n**Why:** {m.why}\n\n**Confidence:** {m.confidence:.0%}\n\n**Auto-fix available:** {m.auto_fix_available}",
                },
                "properties": {
                    "tags": [m.severity, m.issue_type, f"pyneat:{m.rule_id}"],
                    "precision": "high" if m.confidence >= 0.9 else "medium" if m.confidence >= 0.7 else "low",
                    "security-severity": {
                        "critical": "9.0", "high": "7.0", "medium": "4.0",
                        "low": "2.0", "info": "0.1",
                    }.get(m.severity, "4.0"),
                },
            }

        message_parts = [f"{m.issue_type} at line {m.line}"]
        if m.hint:
            message_parts.append(f"Fix: {m.hint}")
        if m.cwe_id:
            message_parts.append(f"CWE-{m.cwe_id}")

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(m.severity),
            "message": {"text": " | ".join(message_parts)},
            "locations": [_marker_to_sarif_location(m, base_path)],
        }

        if m.auto_fix_available and include_fix:
            edit_changes = []
            if m.auto_fix_after:
                line_text = f"Line {m.line}: replace with: {m.auto_fix_after}"
            elif m.can_auto_fix:
                line_text = f"Line {m.line}: auto-fix available via PyNEAT"
            else:
                line_text = f"Line {m.line}: manual fix required"

            result["suggestions"] = [{
                "description": {"text": m.hint or f"Fix {m.issue_type}"},
                "actions": [{
                    "description": {"text": line_text},
                    "kind": "quickfix",
                }],
            }]

        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PyNEAT",
                    "version": tool_version,
                    "informationUri": "https://github.com/pyneat/pyneat",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
            "properties": {
                "tool": "PyNEAT",
                "version": tool_version,
                "fileCount": 1,
                "markerCount": len(markers),
            },
        }],
    }


def export_to_codeclimate(
    markers: List[AgentMarker],
    source_file: Path,
    include_body: bool = True,
) -> List[Dict[str, Any]]:
    """Export markers to Code Climate format.

    Compatible with: Code Climate Quality, GitHub PR Reviews,
    any tool that accepts the Code Climate issues format.

    Format: https://github.com/codeclimate/platform/blob/master/spec/
       _analyzers/SPEC.md

    Args:
        markers: List of AgentMarkers to export.
        source_file: Path to the source file.
        include_body: Include fix hint and explanation in the body field.

    Returns:
        List of Code Climate issue dicts.
    """
    categories_map = {
        "unused_function": "Dead Code",
        "unused_class": "Dead Code",
        "unused_param": "Dead Code",
        "unused_import": "Style",
        "security_issue": "Security",
        "magic_number": "Style",
        "redundant_expr": "Style",
        "empty_except": "Error Prevention",
        "unused_variable": "Dead Code",
    }

    results: List[Dict[str, Any]] = []

    for m in markers:
        cc_type = "ISSUE"
        severity = {"critical": "blocker", "high": "critical",
                     "medium": "major", "low": "minor", "info": "info"}.get(
            m.severity, "minor")

        content_blocks = []
        if m.hint:
            content_blocks.append(f"**Fix hint:** {m.hint}")
        if m.why:
            content_blocks.append(f"**Why:** {m.why}")
        if m.cwe_id:
            content_blocks.append(f"**CWE:** {m.cwe_id}")
        if m.auto_fix_available:
            content_blocks.append("**Auto-fix:** available")
        content_blocks.append(f"**Confidence:** {m.confidence:.0%}")

        issue: Dict[str, Any] = {
            "type": cc_type,
            "check_name": f"pyneat.{m.rule_id}",
            "description": f"[{m.severity.upper()}] {m.issue_type}: {m.hint or m.why}"[:255],
            "categories": [categories_map.get(m.issue_type, "Complexity")],
            "severity": severity,
            "location": {
                "path": str(source_file),
                "lines": {"begin": m.line},
            },
            "fingerprint": f"pyneat-{m.marker_id}",
        }

        if include_body and content_blocks:
            issue["content"] = "\n\n".join(content_blocks)

        if m.confidence < 1.0:
            issue["trust_rating"] = max(1, int(m.confidence * 3))

        results.append(issue)

    return results


def export_to_markdown(
    markers: List[AgentMarker],
    source_file: Path,
    title: str = "",
    include_snippet: bool = True,
    include_diff: bool = True,
) -> str:
    """Export markers to a human-readable Markdown table.

    Suitable for: PR comments, PR body, Slack notifications,
    email digests, and developer documentation.

    Args:
        markers: List of AgentMarkers to export.
        source_file: Path to the source file.
        title: Optional table title.
        include_snippet: Show code snippet column.
        include_diff: Show before/after diff if available.

    Returns:
        Markdown string.
    """
    import hashlib

    lines: List[str] = []

    if title:
        lines.append(f"## {title}\n")
    else:
        lines.append(f"## PyNEAT Issues Report — `{source_file.name}`\n")

    lines.append(f"**Total issues:** {len(markers)} | **Source:** `{source_file}`\n")

    severity_counts: Dict[str, int] = {}
    for m in markers:
        severity_counts[m.severity] = severity_counts.get(m.severity, 0) + 1

    severity_badge = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🔵 LOW",
        "info": "⚪ INFO",
    }

    badge_parts = [f"{severity_badge.get(s, s)}: {c}"
                   for s, c in sorted(severity_counts.items(),
                                      key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0])
                                      if x[0] in ["critical", "high", "medium", "low", "info"] else 4)]
    lines.append(" | ".join(badge_parts) + "\n")

    if not markers:
        lines.append("✅ No issues found.\n")
        return "\n".join(lines)

    lines.append("### Issues\n")

    for i, m in enumerate(markers, 1):
        severity_icon = severity_badge.get(m.severity, f"[{m.severity.upper()}]")
        lines.append(f"#### {i}. {severity_icon} {m.issue_type}\n")
        lines.append(f"- **ID:** `{m.marker_id}`")
        lines.append(f"- **Rule:** `{m.rule_id}`")
        lines.append(f"- **Location:** `{source_file.name}:{m.line}`")
        if m.param:
            lines.append(f"- **Param:** `{m.param}`")
        lines.append(f"- **Confidence:** {m.confidence:.0%}")

        if m.hint:
            lines.append(f"- **Hint:** {m.hint}")
        if m.why:
            lines.append(f"- **Why:** {m.why}")
        if m.cwe_id:
            lines.append(f"- **CWE:** [{m.cwe_id}](https://cwe.mitre.org/data/definitions/{m.cwe_id.replace('CWE-', '')}.html)")

        lines.append(f"- **Auto-fix:** {'✅ Yes' if m.auto_fix_available else '❌ Manual'}")

        if include_snippet and m.snippet:
            lines.append(f"\n```python\n# Line {m.line}\n{m.snippet}\n```\n")

        if include_diff and m.auto_fix_available and m.auto_fix_after:
            lines.append(f"\n```diff\n- {m.auto_fix_before or m.snippet}\n+ {m.auto_fix_after}\n```\n")

        lines.append("---\n")

    lines.append(f"\n*Generated by [PyNEAT](https://github.com/pyneat/pyneat) v2.0.0*\n")

    return "".join(lines)


# GJSON — Graph JSON for LSP/native editor integration
# Compact, navigation-friendly, zero-allocation where possible.


def export_to_gjson(
    markers: List[AgentMarker],
    source_file: Path,
    include_diagnostics: bool = True,
    include_navigation: bool = True,
    include_fix_preview: bool = True,
) -> Dict[str, Any]:
    """Export markers to GJSON (Graph JSON) — LSP-native format.

    Optimized for:
    - Direct LSP consumption (no file I/O needed by the client)
    - IDE navigation (go-to-definition, find-references)
    - Quick-fix rendering (pre-computed ranges)
    - Incremental diff computation

    GJSON schema:
    {
        "version": "1.0",
        "file": "app.py",
        "markers": [
            {
                "id": "PYN-D001",
                "type": "unused_param",
                "severity": "medium",
                "line": 12, "col": 4,
                "endLine": 12, "endCol": 15,
                "label": "unused param 'b' — hint: return a + b",
                "actions": [
                    {"type": "quickfix", "title": "Remove param", "apply": "..."},
                    {"type": "ignore", "title": "Ignore this marker"},
                ],
                "edges": {"calls": [], "definedBy": []},
                "autoFix": {"before": "def foo(a, b):", "after": "def foo(a):"}
            }
        ],
        "diagnostics": [...],   # LSP Diagnostic objects (optional)
        "stats": {"total": 5, "bySeverity": {...}}
    }

    Args:
        markers: List of AgentMarkers to export.
        source_file: Path to the source file.
        include_diagnostics: Include pre-built LSP Diagnostic objects.
        include_navigation: Include navigation edges (calls, definitions).
        include_fix_preview: Include pre-computed auto-fix snippets.

    Returns:
        GJSON dict ready for json.dump.
    """
    if not markers:
        return {
            "version": "1.0",
            "file": str(source_file),
            "markers": [],
            "stats": {"total": 0, "bySeverity": {}},
        }

    severity_order = ["critical", "high", "medium", "low", "info"]
    by_severity: Dict[str, int] = {}
    gjson_markers: List[Dict[str, Any]] = []

    for m in markers:
        by_severity[m.severity] = by_severity.get(m.severity, 0) + 1

        gm: Dict[str, Any] = {
            "id": m.marker_id,
            "type": m.issue_type,
            "rule": m.rule_id,
            "severity": m.severity,
            "severityRank": severity_order.index(m.severity) if m.severity in severity_order else 99,
            "line": m.line,
            "col": m.column or 0,
            "endLine": m.line,
            "endCol": (m.column or 0) + len(m.param or m.snippet or ""),
            "confidence": m.confidence,
            "hint": m.hint,
            "why": m.why,
            "cweId": m.cwe_id,
            "snippet": m.snippet[:100] if m.snippet else "",
        }

        # Actions (quick-fix, ignore, explain)
        actions: List[Dict[str, Any]] = []
        if m.auto_fix_available and m.auto_fix_after:
            actions.append({
                "type": "quickfix",
                "title": f"Fix: {m.hint or m.issue_type}",
                "isPreferred": m.severity in ("critical", "high"),
                "apply": {
                    "newText": m.auto_fix_after,
                    "range": {
                        "start": {"line": m.line - 1, "character": 0},
                        "end": {"line": m.line, "character": 0},
                    },
                },
            })
        elif m.can_auto_fix:
            actions.append({
                "type": "quickfix",
                "title": f"Run PyNEAT fix for {m.issue_type}",
                "isPreferred": False,
                "command": {
                    "title": f"pyneat fix {m.marker_id}",
                    "command": "pyneat.fix",
                    "arguments": [str(source_file), m.marker_id],
                },
            })

        actions.append({
            "type": "explain",
            "title": f"Explain {m.marker_id}",
            "command": {
                "command": "pyneat.explain",
                "arguments": [m.rule_id, str(source_file), m.line],
            },
        })
        actions.append({
            "type": "ignore",
            "title": f"Ignore {m.marker_id}",
            "command": {
                "command": "pyneat.ignore",
                "arguments": [m.rule_id, str(source_file), m.line],
            },
        })
        gm["actions"] = actions

        # Navigation edges (empty by default, populated by LSP context)
        if include_navigation:
            gm["edges"] = {"calls": [], "definedBy": [], "references": []}
        else:
            gm["edges"] = {}

        # Pre-computed auto-fix
        if include_fix_preview and m.auto_fix_available:
            gm["autoFix"] = {
                "available": True,
                "before": m.auto_fix_before or m.snippet or "",
                "after": m.auto_fix_after or "",
                "confidence": m.confidence,
            }
        elif m.can_auto_fix:
            gm["autoFix"] = {"available": False, "hint": m.hint}

        gjson_markers.append(gm)

    gjson: Dict[str, Any] = {
        "version": "1.0",
        "file": str(source_file),
        "markers": gjson_markers,
        "stats": {
            "total": len(markers),
            "bySeverity": by_severity,
            "autoFixable": sum(1 for m in markers if m.auto_fix_available),
            "criticalCount": by_severity.get("critical", 0),
        },
    }

    # Pre-built LSP diagnostics for zero-computation client rendering
    if include_diagnostics:
        gjson["diagnostics"] = [
            {
                "range": {
                    "start": {"line": m.line - 1, "character": m.column or 0},
                    "end": {
                        "line": m.line - 1,
                        "character": (m.column or 0) + len(m.param or m.snippet or ""),
                    },
                },
                "severity": {"critical": 1, "high": 1, "medium": 2,
                             "low": 3, "info": 4}.get(m.severity, 2),
                "code": m.marker_id,
                "source": "PyNEAT",
                "message": m.hint or m.why or m.issue_type,
                "tags": [m.issue_type, m.severity] + ([f"cwe:{m.cwe_id}"] if m.cwe_id else []),
                "data": {
                    "markerId": m.marker_id,
                    "ruleId": m.rule_id,
                    "confidence": m.confidence,
                    "autoFixAvailable": m.auto_fix_available,
                },
            }
            for m in markers
        ]

    return gjson
