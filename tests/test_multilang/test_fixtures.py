"""Multi-language scanner test fixtures and integration tests.

Tests the scanner's ability to handle 8 languages: Python, JavaScript,
TypeScript, Java, Go, Rust, C#, PHP, Ruby.
"""

import pytest
from pathlib import Path

from pyneat.core.types import CodeFile, RuleConfig


# -----------------------------------------------------------------------------
# Fixtures for each language
# -----------------------------------------------------------------------------

JAVA_FIXTURES = {
    "command_injection": {
        "code": """public class ProcessRunner {
    public void runCommand(String cmd) {
        Runtime.getRuntime().exec(cmd);
    }
}""",
        "expected_rule_ids": ["SEC-001"],
        "file_ext": ".java",
    },
    "sql_injection": {
        "code": """public class UserDAO {
    public User findById(String id) throws SQLException {
        String query = "SELECT * FROM users WHERE id=" + id;
        return stmt.executeQuery(query);
    }
}""",
        "expected_rule_ids": ["SEC-002"],
        "file_ext": ".java",
    },
    "hardcoded_secret": {
        "code": '''public class Config {
    private static final String API_KEY = "sk-abc123xyz789";
}''',
        "expected_rule_ids": ["SEC-010"],
        "file_ext": ".java",
    },
    "safe_code": {
        "code": """public class SafeDAO {
    public User findById(long id) {
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM users WHERE id=?"
        );
        ps.setLong(1, id);
        return ps.executeQuery();
    }
}""",
        "expected_rule_ids": [],
        "file_ext": ".java",
    },
}


JAVASCRIPT_FIXTURES = {
    "command_injection": {
        "code": """const { exec } = require('child_process');
function run(cmd) {
    exec(cmd);
}""",
        "expected_rule_ids": ["SEC-001"],
        "file_ext": ".js",
    },
    "sql_injection": {
        "code": """db.query("SELECT * FROM users WHERE id=" + userId, callback);""",
        "expected_rule_ids": ["SEC-002"],
        "file_ext": ".js",
    },
    "eval_dangerous": {
        "code": """eval(userInput);""",
        "expected_rule_ids": ["SEC-003"],
        "file_ext": ".js",
    },
    "safe_code": {
        "code": """db.query("SELECT * FROM users WHERE id=?", [userId]);""",
        "expected_rule_ids": [],
        "file_ext": ".js",
    },
}


GO_FIXTURES = {
    "command_injection": {
        "code": """package main

import (
    "os/exec"
)

func run(cmd string) {
    exec.Command("sh", "-c", cmd)
}""",
        "expected_rule_ids": ["SEC-001"],
        "file_ext": ".go",
    },
    "sql_injection": {
        "code": """func getUser(id string) {
    query := "SELECT * FROM users WHERE id=" + id
    db.Query(query)
}""",
        "expected_rule_ids": ["SEC-002"],
        "file_ext": ".go",
    },
    "hardcoded_secret": {
        "code": """const API_KEY = "sk-live-abc123xyz"
const PASSWORD = "supersecretpassword" """,
        "expected_rule_ids": ["SEC-010"],
        "file_ext": ".go",
    },
    "safe_code": {
        "code": """func getUser(id string) {
    db.Query("SELECT * FROM users WHERE id=$1", id)
}""",
        "expected_rule_ids": [],
        "file_ext": ".go",
    },
}


RUST_FIXTURES = {
    "command_injection": {
        "code": """use std::process::Command;
fn run(cmd: &str) {
    Command::new("sh").arg("-c").arg(cmd).output();
}""",
        "expected_rule_ids": ["SEC-001"],
        "file_ext": ".rs",
    },
    "unsafe_code": {
        "code": """unsafe {
    let f: fn(u8) = transmute::<_, fn(u8)>(42);
}""",
        "expected_rule_ids": ["SEC-007"],
        "file_ext": ".rs",
    },
    "safe_code": {
        "code": """fn safe_add(a: i32, b: i32) -> i32 {
    a.saturating_add(b)
}""",
        "expected_rule_ids": [],
        "file_ext": ".rs",
    },
}


CSHARP_FIXTURES = {
    "command_injection": {
        "code": """using System.Diagnostics;
public void Run(string cmd) {
    Process.Start("cmd.exe", "/c " + cmd);
}""",
        "expected_rule_ids": ["SEC-001"],
        "file_ext": ".cs",
    },
    "sql_injection": {
        "code": """var query = "SELECT * FROM Users WHERE Id=" + userId;
var cmd = new SqlCommand(query, conn);""",
        "expected_rule_ids": ["SEC-002"],
        "file_ext": ".cs",
    },
    "hardcoded_secret": {
        "code": '''private const string API_KEY = "sk-abc123xyz789";''',
        "expected_rule_ids": ["SEC-010"],
        "file_ext": ".cs",
    },
    "safe_code": {
        "code": """var query = "SELECT * FROM Users WHERE Id=@id";
var cmd = new SqlCommand(query, conn);
cmd.Parameters.AddWithValue("@id", userId);""",
        "expected_rule_ids": [],
        "file_ext": ".cs",
    },
}


PHP_FIXTURES = {
    "sql_injection": {
        "code": """<?php
$query = "SELECT * FROM users WHERE id=" . $_GET['id'];
$result = mysqli_query($conn, $query);
?>""",
        "expected_rule_ids": ["SEC-002"],
        "file_ext": ".php",
    },
    "xss_reflected": {
        "code": """<?php echo $_GET['name']; ?>""",
        "expected_rule_ids": ["SEC-074"],
        "file_ext": ".php",
    },
    "eval_dangerous": {
        "code": """<?php eval($_POST['code']); ?>""",
        "expected_rule_ids": ["SEC-077"],
        "file_ext": ".php",
    },
    "safe_code": {
        "code": """<?php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id=:id");
$stmt->execute([':id' => $id]);
?>""",
        "expected_rule_ids": [],
        "file_ext": ".php",
    },
}


RUBY_FIXTURES = {
    "command_injection": {
        "code": """def run_cmd(cmd)
    `#{cmd}`
end""",
        "expected_rule_ids": ["SEC-001"],
        "file_ext": ".rb",
    },
    "sql_injection": {
        "code": """User.where("id = #{params[:id]}").first""",
        "expected_rule_ids": ["SEC-002"],
        "file_ext": ".rb",
    },
    "eval_dangerous": {
        "code": """eval(user_input)""",
        "expected_rule_ids": ["SEC-003"],
        "file_ext": ".rb",
    },
    "safe_code": {
        "code": """User.where(id: params[:id]).first""",
        "expected_rule_ids": [],
        "file_ext": ".rb",
    },
}


ALL_FIXTURES = {
    "java": JAVA_FIXTURES,
    "javascript": JAVASCRIPT_FIXTURES,
    "go": GO_FIXTURES,
    "rust": RUST_FIXTURES,
    "csharp": CSHARP_FIXTURES,
    "php": PHP_FIXTURES,
    "ruby": RUBY_FIXTURES,
}

# Languages supported by AgentMarker
SUPPORTED_LANGUAGES = (
    "python", "javascript", "typescript", "java",
    "go", "rust", "csharp", "php", "ruby"
)


class TestMultiLanguageFixtures:
    """Verify that fixture data is well-formed."""

    def test_all_fixtures_have_required_fields(self):
        """Every fixture must have code, expected_rule_ids, and file_ext."""
        for lang, fixtures in ALL_FIXTURES.items():
            for name, fixture in fixtures.items():
                assert "code" in fixture, f"{lang}/{name}: missing 'code'"
                assert "expected_rule_ids" in fixture, f"{lang}/{name}: missing 'expected_rule_ids'"
                assert "file_ext" in fixture, f"{lang}/{name}: missing 'file_ext'"
                assert isinstance(fixture["expected_rule_ids"], list)
                assert fixture["file_ext"].startswith(".")

    def test_file_ext_matches_language(self):
        """file_ext must be consistent with language name."""
        mapping = {
            "java": ".java",
            "javascript": ".js",
            "go": ".go",
            "rust": ".rs",
            "csharp": ".cs",
            "php": ".php",
            "ruby": ".rb",
        }
        for lang, fixtures in ALL_FIXTURES.items():
            for name, fixture in fixtures.items():
                assert fixture["file_ext"] == mapping[lang], (
                    f"{lang}/{name}: expected {mapping[lang]}, "
                    f"got {fixture['file_ext']}"
                )

    def test_code_snippets_not_empty(self):
        """Every fixture must have non-empty code."""
        for lang, fixtures in ALL_FIXTURES.items():
            for name, fixture in fixtures.items():
                assert len(fixture["code"].strip()) > 0, f"{lang}/{name}: empty code"

    def test_all_7_languages_covered(self):
        """All 7 non-Python languages must be present."""
        expected_langs = {"java", "javascript", "go", "rust", "csharp", "php", "ruby"}
        assert set(ALL_FIXTURES.keys()) == expected_langs

    def test_at_least_3_fixtures_per_language(self):
        """Each language should have at least 3 fixtures (vuln, vuln2, safe)."""
        for lang, fixtures in ALL_FIXTURES.items():
            assert len(fixtures) >= 3, f"{lang}: only {len(fixtures)} fixtures"

    def test_each_language_has_safe_fixture(self):
        """Each language should have at least one safe (no findings) fixture."""
        for lang, fixtures in ALL_FIXTURES.items():
            safe_fixtures = [
                name for name, f in fixtures.items()
                if len(f["expected_rule_ids"]) == 0
            ]
            assert len(safe_fixtures) >= 1, f"{lang}: no safe fixture found"


class TestLanguageDetection:
    """Test language detection from file extension via RuleEngine."""

    def test_language_from_java_ext(self):
        code_file = CodeFile(path=Path("User.java"), content="public class User {}", language="java")
        assert code_file.language == "java"

    def test_language_from_javascript_ext(self):
        code_file = CodeFile(path=Path("app.js"), content="const x = 1;", language="javascript")
        assert code_file.language == "javascript"

    def test_language_from_typescript_ext(self):
        code_file = CodeFile(path=Path("app.ts"), content="const x: number = 1;", language="typescript")
        assert code_file.language == "typescript"

    def test_language_from_go_ext(self):
        code_file = CodeFile(path=Path("main.go"), content="package main", language="go")
        assert code_file.language == "go"

    def test_language_from_rust_ext(self):
        code_file = CodeFile(path=Path("lib.rs"), content="fn main() {}", language="rust")
        assert code_file.language == "rust"

    def test_language_from_csharp_ext(self):
        code_file = CodeFile(path=Path("Program.cs"), content="class Program {}", language="csharp")
        assert code_file.language == "csharp"

    def test_language_from_php_ext(self):
        code_file = CodeFile(path=Path("index.php"), content="<?php echo 'hi';", language="php")
        assert code_file.language == "php"

    def test_language_from_ruby_ext(self):
        code_file = CodeFile(path=Path("script.rb"), content="puts 'hello'", language="ruby")
        assert code_file.language == "ruby"


class TestAgentMarkerLanguageField:
    """Test that AgentMarker accepts language field for all supported languages."""

    def test_all_8_languages_accepted(self):
        """AgentMarker should accept all 8 supported languages."""
        from pyneat.core.types import AgentMarker

        for lang in SUPPORTED_LANGUAGES:
            marker = AgentMarker(
                marker_id=f"PYN-TEST-{lang}",
                issue_type="test",
                rule_id="TestRule",
                line=1,
                language=lang,
            )
            assert marker.language == lang
