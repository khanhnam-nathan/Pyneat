"""Tests for manifest exporters (JSON, SARIF, Markdown, CodeClimate)."""

import json
import pytest
from pathlib import Path
from pyneat.core.types import AgentMarker
from pyneat.core.manifest import (
    Manifest, ManifestExporter, MarkerParser,
    export_to_sarif, export_to_codeclimate, export_to_markdown,
)


class TestManifestExporter:
    """Test ManifestExporter."""

    def test_write_creates_manifest_file(self, tmp_path):
        """Test that write() creates a manifest file."""
        exporter = ManifestExporter()

        marker = AgentMarker(
            marker_id="PYN-001",
            issue_type="unused_import",
            rule_id="UnusedImportRule",
            line=10,
            hint="Remove unused import",
        )

        source_file = tmp_path / "test.py"
        source_file.write_text("import os\n")

        exporter.add_marker(marker, source_file, "import os\n")
        manifest_path = exporter.write(source_file)

        assert manifest_path is not None
        assert manifest_path.exists()

    def test_write_empty_markers_returns_none(self, tmp_path):
        """Test that write() returns None when no markers."""
        exporter = ManifestExporter()
        source_file = tmp_path / "test.py"
        source_file.write_text("x = 1\n")

        manifest_path = exporter.write(source_file)
        assert manifest_path is None

    def test_manifest_contains_all_markers(self, tmp_path):
        """Test that manifest contains all registered markers."""
        exporter = ManifestExporter()

        marker1 = AgentMarker(
            marker_id="PYN-001",
            issue_type="unused_import",
            rule_id="UnusedImportRule",
            line=5,
        )
        marker2 = AgentMarker(
            marker_id="PYN-002",
            issue_type="dead_code",
            rule_id="DeadCodeRule",
            line=10,
        )

        source_file = tmp_path / "test.py"
        source_file.write_text("import os\ndef unused(): pass\n")

        exporter.add_marker(marker1, source_file, "")
        exporter.add_marker(marker2, source_file, "")
        manifest_path = exporter.write(source_file)

        assert manifest_path is not None
        data = json.loads(manifest_path.read_text())
        assert data["total_issues"] == 2
        assert len(data["markers"]) == 2


class TestExportToSarif:
    """Test SARIF export."""

    def test_sarif_basic_structure(self, tmp_path):
        """Test SARIF export produces valid structure."""
        markers = [
            AgentMarker(
                marker_id="PYN-SEC-001",
                issue_type="sql_injection",
                rule_id="SecurityScannerRule",
                severity="critical",
                line=15,
                hint="Use parameterized queries",
                why="String concatenation creates SQL injection risk",
                confidence=0.90,
                snippet="cursor.execute('SELECT * FROM t WHERE id=' + id)",
                cwe_id="CWE-89",
            )
        ]

        source_file = tmp_path / "app.py"
        source_file.write_text("x = 1\n")

        sarif = export_to_sarif(markers, source_file)

        assert "runs" in sarif
        assert len(sarif["runs"]) == 1
        assert sarif["version"] == "2.1.0"
        assert "tool" in sarif["runs"][0]
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "PyNEAT"

    def test_sarif_results(self, tmp_path):
        """Test SARIF results structure."""
        markers = [
            AgentMarker(
                marker_id="PYN-001",
                issue_type="eval_exec",
                rule_id="SecurityScannerRule",
                severity="high",
                line=20,
                hint="Replace eval with ast.literal_eval",
                confidence=0.95,
            )
        ]

        source_file = tmp_path / "test.py"
        sarif = export_to_sarif(markers, source_file)

        assert len(sarif["runs"][0]["results"]) == 1
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "PYNEAT/SecurityScannerRule/PYN-001"
        assert result["level"] == "error"

    def test_sarif_empty_markers(self, tmp_path):
        """Test SARIF export with no markers."""
        source_file = tmp_path / "empty.py"
        sarif = export_to_sarif([], source_file)
        assert sarif == {}


class TestExportToCodeClimate:
    """Test Code Climate export."""

    def test_codeclimate_basic_structure(self, tmp_path):
        """Test Code Climate export produces valid structure."""
        markers = [
            AgentMarker(
                marker_id="PYN-001",
                issue_type="unused_import",
                rule_id="UnusedImportRule",
                severity="medium",
                line=10,
                hint="Remove unused import",
            )
        ]

        source_file = tmp_path / "app.py"
        results = export_to_codeclimate(markers, source_file)

        assert len(results) == 1
        assert results[0]["type"] == "ISSUE"
        assert results[0]["check_name"] == "pyneat.UnusedImportRule"
        assert results[0]["severity"] == "major"  # medium -> major

    def test_codeclimate_empty_markers(self, tmp_path):
        """Test Code Climate export with no markers."""
        source_file = tmp_path / "empty.py"
        results = export_to_codeclimate([], source_file)
        assert results == []


class TestExportToMarkdown:
    """Test Markdown export."""

    def test_markdown_basic_structure(self, tmp_path):
        """Test Markdown export produces table format."""
        markers = [
            AgentMarker(
                marker_id="PYN-001",
                issue_type="dead_code",
                rule_id="DeadCodeRule",
                severity="high",
                line=5,
                hint="Remove unused function",
            ),
            AgentMarker(
                marker_id="PYN-002",
                issue_type="unused_import",
                rule_id="UnusedImportRule",
                severity="medium",
                line=10,
                hint="Remove unused import",
            ),
        ]

        source_file = tmp_path / "app.py"
        md = export_to_markdown(markers, source_file, title="PyNEAT Report")

        assert "PyNEAT Report" in md
        assert "PYN-001" in md
        assert "PYN-002" in md
        assert "dead_code" in md
        assert "unused_import" in md

    def test_markdown_empty_markers(self, tmp_path):
        """Test Markdown export with no markers."""
        source_file = tmp_path / "empty.py"
        md = export_to_markdown([], source_file)
        assert "no issues" in md.lower() or md.strip() == ""


class TestMarkerParser:
    """Test MarkerParser."""

    def test_from_source_basic(self):
        """Test parsing PYNAGENT markers from source."""
        source = '''import os
# PYNAGENT: {"marker_id":"PYN-001","issue_type":"unused_import","rule_id":"UnusedImportRule","severity":"medium","line":1,"hint":"Remove unused import"}
def main():
    pass
'''

        markers = MarkerParser.from_source(source)
        assert len(markers) == 1
        assert markers[0].marker_id == "PYN-001"
        assert markers[0].issue_type == "unused_import"
        assert markers[0].line == 2  # Marker is on line 2

    def test_from_source_multiple(self):
        """Test parsing multiple PYNAGENT markers."""
        source = '''import os
# PYNAGENT: {"marker_id":"PYN-001","issue_type":"unused_import","rule_id":"UnusedImportRule","line":1}
import sys
# PYNAGENT: {"marker_id":"PYN-002","issue_type":"dead_code","rule_id":"DeadCodeRule","line":3}
def unused(): pass
'''

        markers = MarkerParser.from_source(source)
        assert len(markers) == 2

    def test_from_source_empty(self):
        """Test parsing source with no markers."""
        source = '''import os
def main():
    pass
'''
        markers = MarkerParser.from_source(source)
        assert len(markers) == 0

    def test_from_manifest(self, tmp_path):
        """Test loading markers from manifest file."""
        manifest_data = {
            "version": "1.0",
            "source_file": "test.py",
            "total_issues": 1,
            "markers": [
                {
                    "marker_id": "PYN-001",
                    "issue_type": "unused_import",
                    "rule_id": "UnusedImportRule",
                    "line": 10,
                }
            ]
        }

        manifest_file = tmp_path / "test.py.pyneat.manifest.json"
        manifest_file.write_text(json.dumps(manifest_data))

        markers = MarkerParser.from_manifest(manifest_file)
        assert len(markers) == 1
        assert markers[0].marker_id == "PYN-001"

    def test_from_manifest_not_exists(self, tmp_path):
        """Test loading from non-existent manifest."""
        manifest_file = tmp_path / "nonexistent.json"
        markers = MarkerParser.from_manifest(manifest_file)
        assert markers == []

    def test_find_manifest(self, tmp_path):
        """Test finding manifest file for source."""
        source_file = tmp_path / "app.py"
        source_file.write_text("x = 1\n")

        manifest_file = source_file.with_suffix(".py.pyneat.manifest.json")
        manifest_file.write_text("{}")

        found = MarkerParser.find_manifest(source_file)
        assert found == manifest_file

    def test_find_manifest_not_exists(self, tmp_path):
        """Test finding manifest when it doesn't exist."""
        source_file = tmp_path / "app.py"
        source_file.write_text("x = 1\n")

        found = MarkerParser.find_manifest(source_file)
        assert found is None
