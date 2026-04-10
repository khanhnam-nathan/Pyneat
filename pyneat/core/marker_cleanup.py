"""Marker cleanup functionality.

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

This module provides MarkerCleanup class to remove PYNAGENT markers
from source code after issues have been fixed.
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from .types import AgentMarker


class MarkerCleanup:
    """Remove PYNAGENT markers from source code.

    This class helps clean up markers that were added for tracking issues
    that have since been fixed. It can:
    - Remove stale markers (issues that no longer exist)
    - Remove all markers from a file
    - Handle malformed markers gracefully
    """

    # Pattern to match PYNAGENT comments
    _PATTERN = re.compile(r'#\s*PYNAGENT:\s*(\{[^}]+\})')

    def remove_stale_markers(
        self,
        source_file: Path,
        remaining_issues: List[Dict[str, Any]],
    ) -> Tuple[str, List[str]]:
        """Remove markers for issues that have been fixed.

        Compares markers in the source with remaining issues and removes
        markers that are no longer active.

        Args:
            source_file: Path to the source file.
            remaining_issues: List of dicts with 'line', 'issue_type', 'rule_id'.
                             Empty list means all issues were fixed.

        Returns:
            Tuple of (new_content, list_of_removed_marker_ids).
        """
        content = source_file.read_text(encoding='utf-8')
        lines = content.splitlines()

        # Build set of active issue keys
        active_keys = set()
        for issue in remaining_issues:
            key = self._issue_key(issue.get('line', 0), issue.get('issue_type', ''), issue.get('rule_id', ''))
            active_keys.add(key)

        removed_ids = []
        new_lines = []

        for line in lines:
            # Check if this line contains a PYNAGENT marker
            match = self._PATTERN.search(line)
            if match:
                try:
                    import json
                    marker_data = json.loads(match.group(1))
                    marker_id = marker_data.get('marker_id', '<malformed>')

                    # Determine if this marker should be kept
                    line_num = marker_data.get('line', 0)
                    issue_type = marker_data.get('issue_type', '')
                    rule_id = marker_data.get('rule_id', '')

                    issue_key = self._issue_key(line_num, issue_type, rule_id)

                    if remaining_issues and issue_key in active_keys:
                        # Issue still exists, keep the marker
                        new_lines.append(line)
                    else:
                        # Issue was fixed or no remaining issues, remove marker
                        removed_ids.append(marker_id)
                        # Remove the comment line entirely
                        continue
                except (json.JSONDecodeError, TypeError):
                    # Malformed marker - remove it
                    removed_ids.append('<malformed>')
                    continue
            else:
                new_lines.append(line)

        return '\n'.join(new_lines) + ('\n' if content.endswith('\n') else ''), removed_ids

    def remove_all_markers(self, source_file: Path) -> Tuple[str, int]:
        """Remove all PYNAGENT markers from a file.

        Args:
            source_file: Path to the source file.

        Returns:
            Tuple of (new_content, count_of_markers_removed).
        """
        content = source_file.read_text(encoding='utf-8')
        lines = content.splitlines()

        removed_count = 0
        new_lines = []

        for line in lines:
            if self._PATTERN.search(line):
                removed_count += 1
                continue
            new_lines.append(line)

        return '\n'.join(new_lines) + ('\n' if content.endswith('\n') else ''), removed_count

    def cleanup_file(self, source_file: Path, remaining_issues: List[Dict[str, Any]]) -> Tuple[str, List[str]]:
        """Remove stale markers from a file (alias for remove_stale_markers).

        Args:
            source_file: Path to the source file.
            remaining_issues: List of dicts representing remaining issues.

        Returns:
            Tuple of (new_content, list_of_removed_marker_ids).
        """
        return self.remove_stale_markers(source_file, remaining_issues)

    @staticmethod
    def _issue_key(line: int, issue_type: str, rule_id: str) -> str:
        """Create a unique key for an issue."""
        return f"{line}:{issue_type}:{rule_id}"


# --------------------------------------------------------------------------
# Module exports
# --------------------------------------------------------------------------

__all__ = ['MarkerCleanup']