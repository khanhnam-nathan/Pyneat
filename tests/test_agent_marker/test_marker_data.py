"""Tests for AgentMarker data structure."""

import pytest
from pyneat.core.types import (
    AgentMarker,
    SecurityFinding,
    MarkerIdGenerator,
    security_finding_to_marker,
    SecuritySeverity,
)


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
            impact="Attacker can execute arbitrary SQL commands on the database",
            confidence=0.90,
            confidence_note="regex-only match on string concatenation patterns",
            can_auto_fix=False,
            snippet="cursor.execute('SELECT * FROM t WHERE id=' + id)",
            cwe_id="CWE-89",
            owasp_id="A03",
            requires_user_input=False,
            related_markers=(),
            file_path="/src/db.py",
            language="python",
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
        assert marker.impact == original.impact
        assert marker.confidence == original.confidence
        assert marker.confidence_note == original.confidence_note
        assert marker.can_auto_fix == original.can_auto_fix
        assert marker.snippet == original.snippet
        assert marker.cwe_id == original.cwe_id
        assert marker.owasp_id == original.owasp_id
        assert marker.requires_user_input == original.requires_user_input
        assert marker.related_markers == original.related_markers
        assert marker.file_path == original.file_path
        assert marker.language == original.language

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


class TestAgentMarkerValidation:
    """Test AgentMarker field validation via __post_init__."""

    def test_confidence_out_of_range_high(self):
        with pytest.raises(ValueError, match="confidence must be in"):
            AgentMarker(
                marker_id="PYN-V001",
                issue_type="test",
                rule_id="TestRule",
                confidence=1.5,
            )

    def test_confidence_out_of_range_negative(self):
        with pytest.raises(ValueError, match="confidence must be in"):
            AgentMarker(
                marker_id="PYN-V002",
                issue_type="test",
                rule_id="TestRule",
                confidence=-0.1,
            )

    def test_invalid_severity(self):
        with pytest.raises(ValueError, match="invalid severity"):
            AgentMarker(
                marker_id="PYN-V003",
                issue_type="test",
                rule_id="TestRule",
                severity="invalid",
            )

    def test_line_less_than_one(self):
        with pytest.raises(ValueError, match="line must be >= 1"):
            AgentMarker(
                marker_id="PYN-V004",
                issue_type="test",
                rule_id="TestRule",
                line=0,
            )

    def test_invalid_language(self):
        with pytest.raises(ValueError, match="invalid language"):
            AgentMarker(
                marker_id="PYN-V004b",
                issue_type="test",
                rule_id="TestRule",
                language="cobol",
            )

    def test_valid_all_supported_languages(self):
        for lang in AgentMarker.SUPPORTED_LANGUAGES:
            marker = AgentMarker(
                marker_id="PYN-LANG-001",
                issue_type="test",
                rule_id="TestRule",
                language=lang,
            )
            assert marker.language == lang

    def test_valid_confidence_boundary_low(self):
        marker = AgentMarker(
            marker_id="PYN-V005",
            issue_type="test",
            rule_id="TestRule",
            confidence=0.0,
        )
        assert marker.confidence == 0.0

    def test_valid_confidence_boundary_high(self):
        marker = AgentMarker(
            marker_id="PYN-V006",
            issue_type="test",
            rule_id="TestRule",
            confidence=1.0,
        )
        assert marker.confidence == 1.0


class TestAgentMarkerComparison:
    """Test AgentMarker comparison and sorting."""

    def test_sort_by_severity_then_line(self):
        m1 = AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", severity="info", line=5)
        m2 = AgentMarker(marker_id="PYN-002", issue_type="b", rule_id="R", severity="critical", line=5)
        m3 = AgentMarker(marker_id="PYN-003", issue_type="c", rule_id="R", severity="high", line=5)
        sorted_markers = sorted([m1, m2, m3])
        assert sorted_markers[0].marker_id == "PYN-002"
        assert sorted_markers[1].marker_id == "PYN-003"
        assert sorted_markers[2].marker_id == "PYN-001"

    def test_sort_by_line_with_same_severity(self):
        m1 = AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", severity="high", line=20)
        m2 = AgentMarker(marker_id="PYN-002", issue_type="b", rule_id="R", severity="high", line=5)
        sorted_markers = sorted([m1, m2])
        assert sorted_markers[0].marker_id == "PYN-002"
        assert sorted_markers[1].marker_id == "PYN-001"

    def test_eq_same_marker_id(self):
        m1 = AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", line=5)
        m2 = AgentMarker(marker_id="PYN-001", issue_type="b", rule_id="S", line=10)
        assert m1 == m2

    def test_ne_different_marker_id(self):
        m1 = AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", line=5)
        m2 = AgentMarker(marker_id="PYN-002", issue_type="a", rule_id="R", line=5)
        assert m1 != m2

    def test_eq_not_implemented_for_non_marker(self):
        m1 = AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", line=5)
        result = m1 == "PYN-001"
        assert result is False  # Should not equal a string

    def test_hash_same_marker_id(self):
        m1 = AgentMarker(marker_id="PYN-001", issue_type="a", rule_id="R", line=5)
        m2 = AgentMarker(marker_id="PYN-001", issue_type="b", rule_id="S", line=10)
        assert hash(m1) == hash(m2)

    def test_repr(self):
        marker = AgentMarker(
            marker_id="PYN-001",
            issue_type="sql_injection",
            rule_id="SecurityRule",
            line=10,
            severity="critical",
        )
        r = repr(marker)
        assert "PYN-001" in r
        assert "sql_injection" in r
        assert "line=10" in r
        assert "severity=critical" in r


class TestMarkerIdGenerator:
    """Test MarkerIdGenerator singleton and generation logic."""

    def test_singleton_same_instance(self):
        gen1 = MarkerIdGenerator()
        gen2 = MarkerIdGenerator()
        assert gen1 is gen2

    def test_generate_security_prefix(self):
        gen = MarkerIdGenerator()
        gen.reset()
        mid = gen.generate("SEC-001", "security")
        assert mid.startswith("PYN-SEC-")

    def test_generate_quality_prefix(self):
        gen = MarkerIdGenerator()
        gen.reset()
        mid = gen.generate("QAL-001", "quality")
        assert mid.startswith("PYN-QAL-")

    def test_generate_ai_prefix(self):
        gen = MarkerIdGenerator()
        gen.reset()
        mid = gen.generate("AI-001", "ai")
        assert mid.startswith("PYN-AI-")

    def test_generate_deadcode_prefix(self):
        gen = MarkerIdGenerator()
        gen.reset()
        mid = gen.generate("dead_code", "deadcode")
        assert mid.startswith("PYN-DC-")

    def test_generate_infers_security_from_rule_id(self):
        gen = MarkerIdGenerator()
        gen.reset()
        mid = gen.generate("SEC-042")
        assert mid.startswith("PYN-SEC-")

    def test_generate_infers_deadcode_from_rule_id(self):
        gen = MarkerIdGenerator()
        gen.reset()
        mid = gen.generate("DeadCodeRule")
        assert mid.startswith("PYN-DC-")

    def test_generate_increments_counter(self):
        gen = MarkerIdGenerator()
        gen.reset()
        id1 = gen.generate("SEC-001", "security")
        id2 = gen.generate("SEC-002", "security")
        assert id1 != id2
        assert gen.get_counts()["security"] == 2

    def test_reset_clears_counters(self):
        gen = MarkerIdGenerator()
        gen.reset()
        gen.generate("SEC-001", "security")
        gen.reset()
        assert gen.get_counts() == {}
        id1 = gen.generate("SEC-001", "security")
        assert id1.endswith("-0001")


class TestSecurityFindingToMarker:
    """Test conversion from SecurityFinding to AgentMarker."""

    def test_basic_conversion(self):
        finding = SecurityFinding(
            rule_id="SEC-001",
            severity=SecuritySeverity.CRITICAL,
            confidence=0.95,
            cwe_id="CWE-89",
            owasp_id="A03",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            file="/src/app.py",
            start_line=10,
            end_line=10,
            snippet="cursor.execute('SELECT * FROM t WHERE id=' + id)",
            problem="SQL injection via string concatenation",
            fix_constraints=("Use parameterized queries",),
            do_not=("Don't concatenate strings",),
            verify=("Run unit tests",),
            resources=("https://example.com/sql-injection",),
            can_auto_fix=False,
            auto_fix_available=False,
        )

        marker = security_finding_to_marker(finding)
        assert marker.marker_id.startswith("PYN-SEC-")
        assert marker.issue_type == "security_001"
        assert marker.rule_id == "SEC-001"
        assert marker.severity == SecuritySeverity.CRITICAL
        assert marker.line == 10
        assert marker.end_line == 10
        assert marker.hint == "Use parameterized queries"
        assert marker.why == "SQL injection via string concatenation"
        assert marker.confidence == 0.95
        assert marker.cwe_id == "CWE-89"
        assert marker.owasp_id == "A03"
        assert marker.cvss_score == 9.8
        assert marker.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert marker.file_path == "/src/app.py"
        assert marker.detected_at is not None
        assert marker.fix_constraints == ("Use parameterized queries",)
        assert marker.do_not == ("Don't concatenate strings",)
        assert marker.verify == ("Run unit tests",)
        assert marker.resources == ("https://example.com/sql-injection",)
        assert marker.can_auto_fix is False
        assert marker.auto_fix_available is False

    def test_conversion_with_preassigned_id(self):
        finding = SecurityFinding(
            rule_id="SEC-001",
            severity=SecuritySeverity.HIGH,
            confidence=0.9,
            cwe_id="CWE-798",
            owasp_id="A02",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            file="/src/config.py",
            start_line=5,
            end_line=5,
            snippet="password = 'secret'",
            problem="Hardcoded password",
            fix_constraints=("Use environment variable",),
            do_not=(),
            verify=(),
            resources=(),
            can_auto_fix=True,
            auto_fix_available=True,
        )

        marker = security_finding_to_marker(finding, marker_id="PYN-SEC-9999")
        assert marker.marker_id == "PYN-SEC-9999"

    def test_conversion_with_language_and_filepath(self):
        finding = SecurityFinding(
            rule_id="SEC-001",
            severity=SecuritySeverity.CRITICAL,
            confidence=0.9,
            cwe_id="CWE-89",
            owasp_id="A03",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            file="/default/path.py",
            start_line=1,
            end_line=1,
            snippet="cursor.execute",
            problem="SQL injection",
            fix_constraints=(),
            do_not=(),
            verify=(),
            resources=(),
            can_auto_fix=False,
            auto_fix_available=False,
        )

        marker = security_finding_to_marker(
            finding,
            language="javascript",
            file_path="/override/app.js",
        )
        assert marker.language == "javascript"
        assert marker.file_path == "/override/app.js"
        # file_path override takes precedence
        assert marker.file_path != finding.file


class TestAgentMarkerNewFields:
    """Test new fields added to AgentMarker."""

    def test_all_new_fields(self):
        marker = AgentMarker(
            marker_id="PYN-NEW-001",
            issue_type="test",
            rule_id="TestRule",
            severity="high",
            line=1,
            owasp_id="A03",
            cvss_score=8.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            file_path="/src/app.py",
            detected_at="2026-01-01T00:00:00Z",
            remediated=True,
            remediated_at="2026-01-15T00:00:00Z",
            fix_constraints=("Constraint 1", "Constraint 2"),
            do_not=("Mistake 1",),
            verify=("Verify 1", "Verify 2"),
            resources=("https://example.com",),
            impact="Attacker can execute arbitrary code",
            confidence_note="AST-based detection confirmed",
            language="python",
        )
        assert marker.owasp_id == "A03"
        assert marker.cvss_score == 8.5
        assert marker.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        assert marker.file_path == "/src/app.py"
        assert marker.detected_at == "2026-01-01T00:00:00Z"
        assert marker.remediated is True
        assert marker.remediated_at == "2026-01-15T00:00:00Z"
        assert marker.fix_constraints == ("Constraint 1", "Constraint 2")
        assert marker.do_not == ("Mistake 1",)
        assert marker.verify == ("Verify 1", "Verify 2")
        assert marker.resources == ("https://example.com",)
        assert marker.impact == "Attacker can execute arbitrary code"
        assert marker.confidence_note == "AST-based detection confirmed"
        assert marker.language == "python"

    def test_new_fields_default_values(self):
        marker = AgentMarker(
            marker_id="PYN-DEF-001",
            issue_type="test",
            rule_id="TestRule",
        )
        assert marker.owasp_id is None
        assert marker.cvss_score is None
        assert marker.cvss_vector is None
        assert marker.file_path is None
        assert marker.detected_at is None
        assert marker.remediated is False
        assert marker.remediated_at is None
        assert marker.fix_constraints == ()
        assert marker.do_not == ()
        assert marker.verify == ()
        assert marker.resources == ()
        assert marker.impact is None
        assert marker.confidence_note is None
        assert marker.language is None

    def test_to_dict_includes_new_fields(self):
        marker = AgentMarker(
            marker_id="PYN-DICT-001",
            issue_type="test",
            rule_id="TestRule",
            owasp_id="A01",
            cvss_score=7.0,
            file_path="/src/main.py",
            remediated=True,
            impact="Data exfiltration possible",
            confidence_note="regex-only match",
            language="javascript",
        )
        d = marker.to_dict()
        assert d["owasp_id"] == "A01"
        assert d["cvss_score"] == 7.0
        assert d["file_path"] == "/src/main.py"
        assert d["remediated"] is True
        assert "fix_constraints" in d
        assert "do_not" in d
        assert "verify" in d
        assert "resources" in d
        assert d["impact"] == "Data exfiltration possible"
        assert d["confidence_note"] == "regex-only match"
        assert d["language"] == "javascript"

    def test_from_dict_restores_new_fields(self):
        data = {
            "marker_id": "PYN-FD-001",
            "issue_type": "test",
            "rule_id": "TestRule",
            "severity": "medium",
            "line": 5,
            "owasp_id": "A05",
            "cvss_score": 5.5,
            "file_path": "/src/test.py",
            "remediated": False,
            "fix_constraints": ["C1", "C2"],
            "do_not": ["D1"],
            "verify": ["V1"],
            "resources": ["R1"],
            "impact": "Attacker can read all data",
            "confidence_note": "heuristic pattern match",
            "language": "python",
        }
        marker = AgentMarker.from_dict(data)
        assert marker.owasp_id == "A05"
        assert marker.cvss_score == 5.5
        assert marker.file_path == "/src/test.py"
        assert marker.fix_constraints == ("C1", "C2")
        assert marker.do_not == ("D1",)
        assert marker.verify == ("V1",)
        assert marker.resources == ("R1",)
        assert marker.impact == "Attacker can read all data"
        assert marker.confidence_note == "heuristic pattern match"
        assert marker.language == "python"
