"""Tests for manifest exporters (JSON, SARIF, Markdown, CodeClimate, JUnit, GitLab SAST, SonarQube, HTML)."""

import json
import pytest
from pathlib import Path
from pyneat.core.types import AgentMarker
from pyneat.core.manifest import (
    Manifest, ManifestExporter, MarkerParser, MarkerAggregator,
    export_to_sarif, export_to_codeclimate, export_to_markdown,
    export_to_junit_xml, export_to_gitlab_sast, export_to_sonarqube,
    export_to_html_report,
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
# PYNAGENT: {"marker_id":"PYN-001","issue_type":"unused_import","rule_id":"UnusedImportRule","severity":"medium","line":2,"hint":"Remove unused import"}
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


class TestMarkerAggregator:
    """Test MarkerAggregator helper class."""

    def test_by_severity(self):
        markers = [
            AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", severity="critical", line=5),
            AgentMarker(marker_id="PYN-002", issue_type="b", rule_id="R", severity="high", line=10),
            AgentMarker(marker_id="PYN-003", issue_type="c", rule_id="R", severity="critical", line=20),
        ]
        agg = MarkerAggregator(markers)
        grouped = agg.by_severity()
        assert len(grouped["critical"]) == 2
        assert len(grouped["high"]) == 1
        assert "medium" not in grouped

    def test_by_rule(self):
        markers = [
            AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="RuleA", severity="low", line=1),
            AgentMarker(marker_id="PYN-002", issue_type="b", rule_id="RuleB", severity="low", line=1),
            AgentMarker(marker_id="PYN-003", issue_type="c", rule_id="RuleA", severity="low", line=1),
        ]
        agg = MarkerAggregator(markers)
        grouped = agg.by_rule()
        assert len(grouped["RuleA"]) == 2
        assert len(grouped["RuleB"]) == 1

    def test_by_file(self):
        markers = [
            AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", line=1, file_path="/src/a.py"),
            AgentMarker(marker_id="PYN-002", issue_type="b", rule_id="R", line=1, file_path="/src/b.py"),
            AgentMarker(marker_id="PYN-003", issue_type="c", rule_id="R", line=1, file_path="/src/a.py"),
        ]
        agg = MarkerAggregator(markers)
        grouped = agg.by_file()
        assert len(grouped["/src/a.py"]) == 2
        assert len(grouped["/src/b.py"]) == 1

    def test_by_file_unknown_path(self):
        markers = [
            AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", line=1),
            AgentMarker(marker_id="PYN-002", issue_type="b", rule_id="R", line=1),
        ]
        agg = MarkerAggregator(markers)
        grouped = agg.by_file()
        assert len(grouped["unknown"]) == 2

    def test_prioritized(self):
        markers = [
            AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", severity="low", line=5),
            AgentMarker(marker_id="PYN-002", issue_type="b", rule_id="R", severity="critical", line=10),
            AgentMarker(marker_id="PYN-003", issue_type="c", rule_id="R", severity="high", line=1),
        ]
        agg = MarkerAggregator(markers)
        prioritized = agg.prioritized()
        assert prioritized[0].marker_id == "PYN-002"
        assert prioritized[1].marker_id == "PYN-003"
        assert prioritized[2].marker_id == "PYN-001"

    def test_auto_fixable(self):
        markers = [
            AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", line=1, auto_fix_available=True),
            AgentMarker(marker_id="PYN-002", issue_type="b", rule_id="R", line=1, auto_fix_available=False),
        ]
        agg = MarkerAggregator(markers)
        fixable = agg.auto_fixable()
        assert len(fixable) == 1
        assert fixable[0].marker_id == "PYN-001"

    def test_unremediated(self):
        markers = [
            AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", line=1, remediated=False),
            AgentMarker(marker_id="PYN-002", issue_type="b", rule_id="R", line=1, remediated=True),
        ]
        agg = MarkerAggregator(markers)
        unremed = agg.unremediated()
        assert len(unremed) == 1
        assert unremed[0].marker_id == "PYN-001"

    def test_summary(self):
        markers = [
            AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", severity="critical", line=1),
            AgentMarker(marker_id="PYN-002", issue_type="b", rule_id="R", severity="high", line=1, auto_fix_available=True),
            AgentMarker(marker_id="PYN-003", issue_type="c", rule_id="R", severity="medium", line=1),
        ]
        agg = MarkerAggregator(markers)
        summary = agg.summary()
        assert summary["total"] == 3
        assert summary["critical"] == 1
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["auto_fixable"] == 1


class TestExportToJUnitXml:
    """Test JUnit XML export."""

    def test_junit_xml_structure(self, tmp_path):
        markers = [
            AgentMarker(
                marker_id="PYN-001",
                issue_type="sql_injection",
                rule_id="SecurityRule",
                severity="critical",
                line=10,
                hint="Use parameterized queries",
                why="SQL injection risk",
                cwe_id="CWE-89",
            )
        ]
        source_file = tmp_path / "app.py"
        xml_str = export_to_junit_xml(markers, source_file, test_name="PyNEAT")
        assert '<?xml version="1.0" encoding="UTF-8"?>' in xml_str
        assert "<testsuite" in xml_str
        assert 'name="PyNEAT"' in xml_str
        assert "<testcase" in xml_str
        assert "<error" in xml_str or "<failure" in xml_str

    def test_junit_xml_empty_markers(self, tmp_path):
        source_file = tmp_path / "empty.py"
        xml_str = export_to_junit_xml([], source_file)
        assert "<testsuite" in xml_str
        assert 'tests="0"' in xml_str


class TestExportToGitLabSAST:
    """Test GitLab SAST export."""

    def test_gitlab_sast_structure(self, tmp_path):
        markers = [
            AgentMarker(
                marker_id="PYN-SEC-001",
                issue_type="sql_injection",
                rule_id="SecurityRule",
                severity="critical",
                line=10,
                hint="Use parameterized queries",
                cwe_id="CWE-89",
                file_path="/src/app.py",
            )
        ]
        source_file = tmp_path / "app.py"
        result = export_to_gitlab_sast(markers, project="my-project")
        assert "vulnerabilities" in result
        assert result["project"] == "my-project"
        assert len(result["vulnerabilities"]) == 1
        vuln = result["vulnerabilities"][0]
        assert vuln["id"] == "PYN-SEC-001"
        assert vuln["cve"] == "CWE-89"
        assert vuln["severity"] == "critical"
        assert vuln["line"] == 10

    def test_gitlab_sast_empty(self, tmp_path):
        source_file = tmp_path / "empty.py"
        result = export_to_gitlab_sast([])
        assert result["vulnerabilities"] == []


class TestExportToSonarQube:
    """Test SonarQube Generic Issue Export."""

    def test_sonarqube_structure(self, tmp_path):
        markers = [
            AgentMarker(
                marker_id="PYN-001",
                issue_type="sql_injection",
                rule_id="SecurityRule",
                severity="critical",
                line=10,
                hint="Use parameterized queries",
            )
        ]
        source_file = tmp_path / "app.py"
        issues = export_to_sonarqube(markers, source_file)
        assert len(issues) == 1
        issue = issues[0]
        assert issue["engineId"] == "PyNEAT"
        assert issue["ruleId"] == "SecurityRule"
        assert issue["severity"] == "BLOCKER"
        assert issue["type"] == "VULNERABILITY"
        assert issue["line"] == 10

    def test_sonarqube_low_becomes_code_smell(self, tmp_path):
        markers = [
            AgentMarker(
                marker_id="PYN-001",
                issue_type="unused_import",
                rule_id="ImportRule",
                severity="low",
                line=5,
            )
        ]
        source_file = tmp_path / "app.py"
        issues = export_to_sonarqube(markers, source_file)
        assert issues[0]["type"] == "CODE_SMELL"

    def test_sonarqube_empty(self, tmp_path):
        source_file = tmp_path / "empty.py"
        issues = export_to_sonarqube([], source_file)
        assert issues == []


class TestExportToHtmlReport:
    """Test HTML report export."""

    def test_html_report_structure(self, tmp_path):
        markers = [
            AgentMarker(
                marker_id="PYN-001",
                issue_type="sql_injection",
                rule_id="SecurityRule",
                severity="critical",
                line=10,
                hint="Use parameterized queries",
            ),
            AgentMarker(
                marker_id="PYN-002",
                issue_type="unused_import",
                rule_id="ImportRule",
                severity="medium",
                line=5,
                hint="Remove import",
            ),
        ]
        source_file = tmp_path / "app.py"
        html = export_to_html_report(markers, title="Test Report")
        assert "<!DOCTYPE html>" in html
        assert "Test Report" in html
        assert "PYN-001" in html
        assert "PYN-002" in html
        assert "critical" in html.lower()
        assert "sql_injection" in html

    def test_html_report_empty(self, tmp_path):
        source_file = tmp_path / "empty.py"
        html = export_to_html_report([])
        assert "<!DOCTYPE html>" in html
        assert "No issues found" in html

    def test_html_report_with_summary(self, tmp_path):
        markers = [
            AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", severity="critical", line=1),
            AgentMarker(marker_id="PYN-002", issue_type="b", rule_id="R", severity="high", line=1),
            AgentMarker(marker_id="PYN-003", issue_type="c", rule_id="R", severity="low", line=1),
        ]
        html = export_to_html_report(markers)
        assert "3" in html  # total count


class TestMarkerParserMultiLanguage:
    """Test MarkerParser multi-language comment support."""

    def test_parse_js_single_line(self):
        source = """function test() {
// PYNAGENT: {"marker_id":"PYN-JS-001","issue_type":"unused_var","rule_id":"JSRule","line":2}
}"""
        markers = MarkerParser.from_source(source)
        assert len(markers) == 1
        assert markers[0].marker_id == "PYN-JS-001"

    def test_parse_c_block_comment(self):
        source = """int main() {
/* PYNAGENT: {"marker_id":"PYN-C-001","issue_type":"buffer_risk","rule_id":"CRule","line":2} */
return 0;
}"""
        markers = MarkerParser.from_source(source)
        assert len(markers) == 1
        assert markers[0].marker_id == "PYN-C-001"

    def test_parse_sql_single_line(self):
        source = """SELECT *
-- PYNAGENT: {"marker_id":"PYN-SQL-001","issue_type":"sql_risk","rule_id":"SQLRule","line":2}
FROM users"""
        markers = MarkerParser.from_source(source)
        assert len(markers) == 1
        assert markers[0].marker_id == "PYN-SQL-001"

    def test_parse_html_comment(self):
        source = """<div>
<!-- PYNAGENT: {"marker_id":"PYN-HTML-001","issue_type":"html_risk","rule_id":"HTMLRule","line":2} -->
</div>"""
        markers = MarkerParser.from_source(source)
        assert len(markers) == 1
        assert markers[0].marker_id == "PYN-HTML-001"

    def test_parse_python_and_js_mixed(self):
        source = """# PYNAGENT: {"marker_id":"PYN-PY-001","issue_type":"py_risk","rule_id":"PyRule","line":1}
def test():
// PYNAGENT: {"marker_id":"PYN-JS-001","issue_type":"js_risk","rule_id":"JSRule","line":3}
"""
        markers = MarkerParser.from_source(source)
        assert len(markers) == 2
        ids = {m.marker_id for m in markers}
        assert "PYN-PY-001" in ids
        assert "PYN-JS-001" in ids
