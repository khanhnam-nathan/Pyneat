"""PyNEAT Manifest V2 schema — lifecycle tracking for AgentMarkers.

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

For commercial licensing, contact: khanhname.copywriting@gmail.com
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

import yaml


# --------------------------------------------------------------------------
# Severity Summary
# --------------------------------------------------------------------------


@dataclass
class SeveritySummary:
    """Counts of findings by severity level."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info

    @classmethod
    def from_markers(cls, markers: list) -> "SeveritySummary":
        s = cls()
        for m in markers:
            sev = getattr(m, 'severity', 'info') or 'info'
            if hasattr(s, sev):
                setattr(s, sev, getattr(s, sev) + 1)
        return s

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------
# Dependency & SBOM
# --------------------------------------------------------------------------


@dataclass
class DependencyInfo:
    """A single dependency entry."""
    name: str
    version: str
    ecosystem: str = "pypi"
    license: Optional[str] = None
    is_direct: bool = True


@dataclass
class DependencyFinding:
    """A vulnerability found in a dependency."""
    package: str
    version: str
    severity: str
    cve_id: Optional[str] = None
    ghsa_id: Optional[str] = None
    description: str = ""
    fixed_version: Optional[str] = None


# --------------------------------------------------------------------------
# PyneatManifest — the core lifecycle document
# --------------------------------------------------------------------------

@dataclass
class PyneatManifest:
    """PyNEAT Manifest V2 — tracks scan lifecycle, marker history, and diffs.

    This is the canonical format for persisting and comparing scan results
    across time. It captures the full state of a scan including all markers,
    and supports comparison with previous scans to track remediation progress.
    """
    version: str = "2.0"

    # Identity
    scan_id: str = field(default_factory=lambda: f"scan-{uuid.uuid4().hex[:12]}")
    project: str = ""
    language: Optional[str] = None

    # Tool info
    tool: str = "pyneat"
    tool_version: str = "1.0.0"

    # Timing
    created_at: str = field(default_factory=lambda: datetime.now().isoformat() + "Z")
    scan_duration_seconds: float = 0.0

    # Scope
    total_files: int = 0
    files_scanned: List[str] = field(default_factory=list)

    # Summary
    summary: SeveritySummary = field(default_factory=SeveritySummary)

    # Markers
    markers: List[Dict[str, Any]] = field(default_factory=list)

    # Dependencies
    dependencies: List[Dict[str, Any]] = field(default_factory=list)
    dependency_findings: List[Dict[str, Any]] = field(default_factory=list)

    # Lifecycle: previous scan for comparison
    previous_scan_id: Optional[str] = None
    previous_scan_path: Optional[str] = None

    # Rules that were enabled during this scan
    rules_enabled: List[str] = field(default_factory=list)

    # --------------------------------------------------------------------------
    # Serialization
    # --------------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a plain dict for serialization."""
        d = asdict(self)
        d['summary'] = self.summary.to_dict()
        return d

    def save(self, path: Path) -> None:
        """Save manifest to a YAML file."""
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)

    @classmethod
    def load(cls, path: Path) -> "PyneatManifest":
        """Load a manifest from a YAML file."""
        with open(path, encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PyneatManifest":
        """Reconstruct a manifest from a dict."""
        if data is None:
            return cls()
        summary_data = data.pop('summary', None)
        summary = SeveritySummary(**summary_data) if summary_data else SeveritySummary()
        manifest = cls(**data)
        manifest.summary = summary
        return manifest

    # --------------------------------------------------------------------------
    # Lifecycle helpers
    # --------------------------------------------------------------------------

    def mark_previous(self, previous: "PyneatManifest") -> None:
        """Record a previous scan for diff comparison."""
        self.previous_scan_id = previous.scan_id
        self.previous_scan_path = getattr(previous, '_path', None)

    def compute_diff(self, previous: "PyneatManifest") -> Dict[str, Any]:
        """Compute the diff between this manifest and a previous one.

        Returns a summary of new, remediated, and unchanged markers.
        """
        prev_markers = {(m.get('marker_id'), m.get('file_path'), m.get('line'))
                         for m in previous.markers}
        curr_markers = {(m.get('marker_id'), m.get('file_path'), m.get('line'))
                        for m in self.markers}

        new_markers = []
        remediated_markers = []
        unchanged_markers = []

        for m in self.markers:
            key = (m.get('marker_id'), m.get('file_path'), m.get('line'))
            if key not in prev_markers:
                new_markers.append(m)
            else:
                unchanged_markers.append(m)

        for m in previous.markers:
            key = (m.get('marker_id'), m.get('file_path'), m.get('line'))
            if key not in curr_markers:
                remediated_markers.append(m)

        # Severity breakdown
        def sev_breakdown(mkrs):
            return {
                'critical': len([m for m in mkrs if m.get('severity') == 'critical']),
                'high': len([m for m in mkrs if m.get('severity') == 'high']),
                'medium': len([m for m in mkrs if m.get('severity') == 'medium']),
                'low': len([m for m in mkrs if m.get('severity') == 'low']),
                'info': len([m for m in mkrs if m.get('severity') == 'info']),
            }

        prev_summary = SeveritySummary.from_markers(previous.markers)
        curr_summary = SeveritySummary.from_markers(self.markers)

        return {
            'current_scan_id': self.scan_id,
            'previous_scan_id': previous.scan_id,
            'total': {
                'current': len(self.markers),
                'previous': len(previous.markers),
                'new': len(new_markers),
                'remediated': len(remediated_markers),
                'unchanged': len(unchanged_markers),
            },
            'by_severity': {
                'current': sev_breakdown(self.markers),
                'previous': sev_breakdown(previous.markers),
                'new': sev_breakdown(new_markers),
                'remediated': sev_breakdown(remediated_markers),
            },
            'remediation_rate': (
                round(len(remediated_markers) / len(previous.markers) * 100, 1)
                if previous.markers else 0.0
            ),
            'new_markers': new_markers[:20],  # limit output
            'remediated_markers': remediated_markers[:20],
        }

    def compute_scan_hash(self) -> str:
        """Compute a content hash of all markers for deduplication."""
        marker_strs = sorted(
            f"{m.get('marker_id', '')}:{m.get('file_path', '')}:{m.get('line', '')}:{m.get('severity', '')}"
            for m in self.markers
        )
        return hashlib.sha256("|".join(marker_strs).encode()).hexdigest()[:12]

    @property
    def score(self) -> float:
        """Security score: 100 minus weighted severity sum."""
        weights = {'critical': 20, 'high': 10, 'medium': 5, 'low': 1, 'info': 0}
        penalty = sum(weights.get(m.get('severity', 'info'), 0) for m in self.markers)
        return max(0.0, 100.0 - penalty)

    @property
    def grade(self) -> str:
        """Letter grade based on security score."""
        s = self.score
        if s >= 95: return "A"
        if s >= 85: return "B"
        if s >= 70: return "C"
        if s >= 50: return "D"
        return "F"

    def summary_text(self, verbose: bool = False) -> str:
        """Human-readable scan summary."""
        lines = [
            f"Scan ID:    {self.scan_id}",
            f"Project:    {self.project}",
            f"Tool:      {self.tool} v{self.tool_version}",
            f"Scanned:   {self.total_files} files",
            f"Score:     {self.score:.1f} ({self.grade})",
            f"Findings:  {self.summary.total} total",
            f"  Critical: {self.summary.critical}",
            f"  High:     {self.summary.high}",
            f"  Medium:  {self.summary.medium}",
            f"  Low:     {self.summary.low}",
            f"  Info:    {self.summary.info}",
        ]
        if verbose and self.markers:
            lines.append(f"\nTop 5 findings:")
            for m in sorted(self.markers,
                            key=lambda x: {'critical': 0, 'high': 1, 'medium': 2,
                                          'low': 3, 'info': 4}.get(x.get('severity', 'info'), 5))[:5]:
                sev = m.get('severity') or '?'
                lines.append(f"  [{sev.upper()}] {m.get('marker_id')} "
                           f"— {(m.get('why') or m.get('issue_type') or '?')[:60]}")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Manifest comparison CLI helper
# --------------------------------------------------------------------------

def load_manifest_or_fail(path: Path) -> PyneatManifest:
    """Load a manifest file, raising a clear error if it doesn't exist."""
    if not path.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")
    return PyneatManifest.load(path)


def diff_manifests(current: PyneatManifest, previous: PyneatManifest) -> Dict[str, Any]:
    """Compute diff between two manifests."""
    return current.compute_diff(previous)


def format_diff(diff: Dict[str, Any]) -> str:
    """Format a manifest diff for human-readable output."""
    total = diff['total']
    by_sev = diff['by_severity']
    lines = [
        "",
        "=" * 60,
        f"PyNEAT Scan Diff",
        "=" * 60,
        f"Current scan:  {diff['current_scan_id']}",
        f"Previous scan: {diff['previous_scan_id']}",
        "",
        "SUMMARY",
        "-" * 40,
        f"  Previous:   {total['previous']} findings",
        f"  Current:    {total['current']} findings",
        f"  New:        {total['new']} findings  ▲",
        f"  Remediated: {total['remediated']} findings  ▼",
        f"  Unchanged:  {total['unchanged']} findings",
        f"  Rate:       {diff['remediation_rate']:.1f}% remediated",
        "",
        "SEVERITY BREAKDOWN",
        "-" * 40,
        f"  {'Severity':<10} {'Previous':>10} {'Current':>10} {'New':>10} {'Fixed':>10}",
    ]

    for sev in ('critical', 'high', 'medium', 'low', 'info'):
        p = by_sev['previous'].get(sev, 0)
        c = by_sev['current'].get(sev, 0)
        n = by_sev['new'].get(sev, 0)
        r = by_sev['remediated'].get(sev, 0)
        lines.append(f"  {sev.capitalize():<10} {p:>10} {c:>10} {n:>10} {r:>10}")

    if diff['new_markers']:
        lines.append("")
        lines.append("NEW FINDINGS (top 10)")
        lines.append("-" * 40)
        for m in diff['new_markers'][:10]:
            sev = m.get('severity') or '?'
            lines.append(f"  [{sev.upper()}] {m.get('marker_id')} "
                        f"— {(m.get('why') or m.get('issue_type') or '')[:60]}")

    lines.append("=" * 60)
    return "\n".join(lines)
