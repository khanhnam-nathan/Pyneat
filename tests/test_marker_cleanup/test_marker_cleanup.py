"""Tests for marker cleanup functionality."""

import pytest
from pathlib import Path
from pyneat.core.types import AgentMarker
from pyneat.core.marker_cleanup import MarkerCleanup


class TestMarkerCleanup:
    """Test MarkerCleanup class."""

    def test_remove_stale_markers(self, tmp_path):
        """Test removing markers for fixed issues."""
        # Create source file with a stale marker
        source_file = tmp_path / "test.py"
        source_file.write_text(
            'import os\n'
            '# PYNAGENT: {"marker_id":"PYN-001","issue_type":"unused_import","rule_id":"UnusedImportRule","line":1,"hint":"Remove"}\n'
            'x = 1\n'
        )

        cleanup = MarkerCleanup()
        # Simulate the issue was fixed (no remaining issues at line 1)
        remaining_issues = []  # Issue was fixed

        new_content, removed = cleanup.remove_stale_markers(source_file, remaining_issues)

        assert "# PYNAGENT" not in new_content
        assert "PYN-001" in removed

    def test_keep_active_markers(self, tmp_path):
        """Test keeping markers for active issues."""
        source_file = tmp_path / "test.py"
        source_file.write_text(
            'import os\n'
            '# PYNAGENT: {"marker_id":"PYN-001","issue_type":"unused_import","rule_id":"UnusedImportRule","line":1,"hint":"Remove"}\n'
            'x = 1\n'
        )

        cleanup = MarkerCleanup()
        # Issue is still active
        remaining_issues = [{"line": 1, "issue_type": "unused_import", "rule_id": "UnusedImportRule"}]

        new_content, removed = cleanup.remove_stale_markers(source_file, remaining_issues)

        assert "# PYNAGENT" in new_content
        assert len(removed) == 0

    def test_remove_all_markers(self, tmp_path):
        """Test removing all markers from a file."""
        source_file = tmp_path / "test.py"
        source_file.write_text(
            'import os\n'
            '# PYNAGENT: {"marker_id":"PYN-001","issue_type":"unused_import","rule_id":"UnusedImportRule","line":1}\n'
            'import sys\n'
            '# PYNAGENT: {"marker_id":"PYN-002","issue_type":"unused_import","rule_id":"UnusedImportRule","line":3}\n'
            'x = 1\n'
        )

        cleanup = MarkerCleanup()
        new_content, count = cleanup.remove_all_markers(source_file)

        assert "# PYNAGENT" not in new_content
        assert count == 2
        assert "import os" in new_content
        assert "import sys" in new_content

    def test_no_markers_in_source(self, tmp_path):
        """Test cleanup when source has no markers."""
        source_file = tmp_path / "test.py"
        source_file.write_text("x = 1\n")

        cleanup = MarkerCleanup()
        new_content, removed = cleanup.remove_stale_markers(source_file, [])

        assert new_content == "x = 1\n"
        assert len(removed) == 0

    def test_malformed_marker_removed(self, tmp_path):
        """Test that malformed markers are removed."""
        source_file = tmp_path / "test.py"
        source_file.write_text(
            'import os\n'
            '# PYNAGENT: {invalid json here}\n'
            'x = 1\n'
        )

        cleanup = MarkerCleanup()
        remaining_issues = []

        new_content, removed = cleanup.remove_stale_markers(source_file, remaining_issues)

        assert "# PYNAGENT" not in new_content
        assert "<malformed>" in removed

    def test_partial_cleanup(self, tmp_path):
        """Test removing some markers while keeping others."""
        source_file = tmp_path / "test.py"
        source_file.write_text(
            'import os\n'
            '# PYNAGENT: {"marker_id":"PYN-001","issue_type":"unused_import","rule_id":"UnusedImportRule","line":1}\n'
            'import sys\n'
            '# PYNAGENT: {"marker_id":"PYN-002","issue_type":"dead_code","rule_id":"DeadCodeRule","line":3}\n'
            'def unused(): pass\n'
        )

        cleanup = MarkerCleanup()
        # Only the first issue is fixed
        remaining_issues = [{"line": 3, "issue_type": "dead_code", "rule_id": "DeadCodeRule"}]

        new_content, removed = cleanup.remove_stale_markers(source_file, remaining_issues)

        assert "# PYNAGENT" in new_content  # PYN-002 kept
        assert "PYN-001" in removed  # PYN-001 removed
        assert "PYN-002" not in removed  # PYN-002 kept
