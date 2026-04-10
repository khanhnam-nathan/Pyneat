"""Tests for AgentMarker data structure."""

import pytest
from pyneat.core.types import AgentMarker


class TestAgentMarkerSerialization:
    """Test AgentMarker serialization and deserialization."""

    def test_marker_to_json_full(self):
        """Test full marker serialization to JSON."""
        marker = AgentMarker(
            marker_id="PYN-001",
            issue_type="unused_import",
            rule_id="UnusedImportRule",
            severity="medium",
            line=10,
            end_line=10,
            column=0,
            hint="Remove unused import",
            why="Unused imports increase cognitive load",
            confidence=0.95,
            can_auto_fix=True,
            fix_diff="remove line 10",
            snippet="import os",
            cwe_id=None,
            auto_fix_available=True,
            auto_fix_before="import os",
            auto_fix_after="",
            requires_user_input=True,  # Non-default value
            related_markers=("PYN-002",),
        )

        json_str = marker.to_json()
        assert "PYN-001" in json_str
        assert "unused_import" in json_str
        assert "end_line" in json_str
        assert "requires_user_input" in json_str
        assert "related_markers" in json_str

    def test_marker_roundtrip(self):
        """Test JSON roundtrip serialization."""
        original = AgentMarker(
            marker_id="PYN-SEC-001",
            issue_type="sql_injection",
            rule_id="SecurityScannerRule",
            severity="critical",
            line=25,
            end_line=25,
            hint="Use parameterized queries",
            why="String concatenation creates SQL injection risk",
            confidence=0.90,
            can_auto_fix=False,
            snippet="cursor.execute('SELECT * FROM t WHERE id=' + id)",
            cwe_id="CWE-89",
            requires_user_input=False,
            related_markers=(),
        )

        # Serialize
        json_str = original.to_json()
        # Deserialize
        marker = AgentMarker.from_json(json_str)

        assert marker.marker_id == original.marker_id
        assert marker.issue_type == original.issue_type
        assert marker.rule_id == original.rule_id
        assert marker.severity == original.severity
        assert marker.line == original.line
        assert marker.end_line == original.end_line
        assert marker.hint == original.hint
        assert marker.why == original.why
        assert marker.confidence == original.confidence
        assert marker.can_auto_fix == original.can_auto_fix
        assert marker.snippet == original.snippet
        assert marker.cwe_id == original.cwe_id
        assert marker.requires_user_input == original.requires_user_input
        assert marker.related_markers == original.related_markers

    def test_marker_to_dict(self):
        """Test marker to_dict conversion."""
        marker = AgentMarker(
            marker_id="PYN-002",
            issue_type="magic_number",
            rule_id="MagicNumberRule",
            line=5,
        )

        d = marker.to_dict()
        assert d["marker_id"] == "PYN-002"
        assert d["issue_type"] == "magic_number"
        assert "line" in d

    def test_marker_to_comment(self):
        """Test marker to source code comment format."""
        marker = AgentMarker(
            marker_id="PYN-003",
            issue_type="dead_code",
            rule_id="DeadCodeRule",
            line=15,
            hint="Remove unused function",
        )

        comment = marker.to_comment()
        assert comment.startswith("# PYNAGENT:")
        assert "PYN-003" in comment
        assert "dead_code" in comment

    def test_marker_from_dict(self):
        """Test marker creation from dict."""
        data = {
            "marker_id": "PYN-004",
            "issue_type": "empty_except",
            "rule_id": "RefactoringRule",
            "line": 20,
            "end_line": 22,
            "requires_user_input": True,
            "related_markers": ["PYN-001", "PYN-002"],
        }

        marker = AgentMarker.from_dict(data)
        assert marker.marker_id == "PYN-004"
        assert marker.issue_type == "empty_except"
        assert marker.line == 20
        assert marker.end_line == 22
        assert marker.requires_user_input is True
        assert marker.related_markers == ("PYN-001", "PYN-002",)

    def test_marker_minimal_required_fields(self):
        """Test marker with only required fields."""
        marker = AgentMarker(
            marker_id="PYN-005",
            issue_type="test",
            rule_id="TestRule",
        )

        json_str = marker.to_json()
        assert "PYN-005" in json_str
        assert marker.line == 1  # default
        assert marker.severity == "medium"  # default


class TestRequiresUserInput:
    """Test requires_user_input field."""

    def test_requires_user_input_true(self):
        """Test requires_user_input set to True."""
        marker = AgentMarker(
            marker_id="PYN-101",
            issue_type="race_condition",
            rule_id="ConcurrencyRule",
            line=1,
            requires_user_input=True,
        )
        assert marker.requires_user_input is True

    def test_requires_user_input_false(self):
        """Test requires_user_input set to False."""
        marker = AgentMarker(
            marker_id="PYN-102",
            issue_type="unused_import",
            rule_id="UnusedImportRule",
            line=1,
            requires_user_input=False,
        )
        assert marker.requires_user_input is False


class TestRelatedMarkers:
    """Test related_markers field."""

    def test_related_markers_multiple(self):
        """Test related_markers with multiple IDs."""
        marker = AgentMarker(
            marker_id="PYN-201",
            issue_type="unused_function",
            rule_id="DeadCodeRule",
            line=1,
            related_markers=("PYN-202", "PYN-203", "PYN-204"),
        )
        assert len(marker.related_markers) == 3
        assert "PYN-202" in marker.related_markers

    def test_related_markers_empty(self):
        """Test related_markers when empty."""
        marker = AgentMarker(
            marker_id="PYN-205",
            issue_type="style",
            rule_id="StyleRule",
            line=1,
            related_markers=(),
        )
        assert len(marker.related_markers) == 0


class TestEndLine:
    """Test end_line field for multi-line markers."""

    def test_end_line_default(self):
        """Test end_line defaults to line number."""
        marker = AgentMarker(
            marker_id="PYN-301",
            issue_type="test",
            rule_id="TestRule",
            line=10,
        )
        assert marker.end_line == 10

    def test_end_line_multi_line(self):
        """Test end_line for multi-line issues."""
        marker = AgentMarker(
            marker_id="PYN-302",
            issue_type="arrow_antipattern",
            rule_id="RefactoringRule",
            line=5,
            end_line=15,
        )
        assert marker.end_line == 15
        assert marker.end_line > marker.line
