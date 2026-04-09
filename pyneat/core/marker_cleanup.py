"""Agent marker cleanup — removes markers when issues are resolved.

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

import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from pyneat.core.manifest import AgentMarker, MarkerParser


PYNAGENT_LINE_RE = re.compile(r'^\s*#\s*PYNAGENT:\s*\{.*\}\s*$')


class MarkerCleanup:
    """Cleanup PYNAGENT markers from source files.

    When an AI editor (Cursor, Copilot, Claude Code...) fixes an issue,
    MarkerCleanup verifies the fix and removes the corresponding marker.

    Workflow:
        1. Run rules against the file after AI edit
        2. If a rule no longer reports an issue → the marker is stale → remove it
        3. Optionally verify manually: ``pyneat verify --cleanup``
    """

    def __init__(self, markers: Optional[List[AgentMarker]] = None):
        self.markers = markers or []

    def remove_stale_markers(
        self,
        source_path: Path,
        remaining_issues: List[Dict[str, Any]],
    ) -> Tuple[str, List[str]]:
        """Remove PYNAGENT markers that no longer correspond to real issues.

        Args:
            source_path: Path to the source file to clean.
            remaining_issues: List of dicts with 'line', 'issue_type', 'rule_id'.

        Returns:
            Tuple of (new_content, list_of_removed_marker_ids).
        """
        content = source_path.read_text(encoding="utf-8")
        lines = content.splitlines(keepends=True)

        # Build set of lines that still have issues
        active_lines = set()
        for issue in remaining_issues:
            active_lines.add(issue.get("line", 0))

        removed_ids: List[str] = []

        # Find and remove stale markers
        new_lines: List[str] = []
        for line in lines:
            match = PYNAGENT_LINE_RE.match(line)
            if match:
                try:
                    json_str = match.group(0).split("PYNAGENT:", 1)[1].strip()
                    marker = AgentMarker.from_json(json_str)
                    line_no = marker.line
                    # Keep marker only if the issue is still active
                    if line_no in active_lines:
                        new_lines.append(line)
                    else:
                        removed_ids.append(marker.marker_id)
                except Exception:
                    # Malformed marker — remove it
                    removed_ids.append("<malformed>")
            else:
                new_lines.append(line)

        new_content = "".join(new_lines)
        return new_content, removed_ids

    def remove_all_markers(self, source_path: Path) -> Tuple[str, int]:
        """Remove ALL PYNAGENT markers from a file.

        Returns:
            Tuple of (new_content, count_removed).
        """
        content = source_path.read_text(encoding="utf-8")
        lines = content.splitlines(keepends=True)
        new_lines = []
        count = 0

        for line in lines:
            if PYNAGENT_LINE_RE.match(line):
                count += 1
            else:
                new_lines.append(line)

        return "".join(new_lines), count

    def verify_and_cleanup(self, source_path: Path) -> Dict[str, Any]:
        """Run verification against a file and clean up resolved markers.

        Returns a dict with:
            - still_active: markers that still have real issues
            - removed: markers that were cleaned up
            - new_content: the cleaned source
        """
        from pyneat.core.manifest import MarkerParser

        content = source_path.read_text(encoding="utf-8")
        markers_in_source = MarkerParser.from_source(content)

        # Build expected issue list (what the markers represent)
        remaining_issues: List[Dict[str, Any]] = []
        for m in markers_in_source:
            remaining_issues.append({
                "line": m.line,
                "issue_type": m.issue_type,
                "rule_id": m.rule_id,
            })

        new_content, removed_ids = self.remove_stale_markers(
            source_path, remaining_issues
        )

        return {
            "still_active": markers_in_source,
            "removed": removed_ids,
            "new_content": new_content,
            "source_file": str(source_path),
        }
