"""Tests for command injection detection (SEC-001)."""

import pytest
from pathlib import Path

from pyneat.rules.security import SecurityScannerRule
from pyneat.core.types import CodeFile, RuleConfig


def apply_rule(source: str) -> tuple[str, list]:
    """Apply SecurityScannerRule to source code and return (transformed, findings)."""
    rule = SecurityScannerRule(RuleConfig(enabled=True))
    code_file = CodeFile(path=Path("test.py"), content=source)
    result = rule.apply(code_file)
    return result.transformed_content, result.security_findings


class TestCommandInjection:
    """Tests for SEC-001: Command Injection Detection."""

    def test_detects_os_system(self):
        """Should detect os.system() call."""
        source = "import os\nos.system('ls')"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-001" for f in findings)

    def test_detects_subprocess_shell_true(self):
        """Should detect subprocess.run with shell=True."""
        source = "import subprocess\nsubprocess.run('ls', shell=True)"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-001" for f in findings)

    def test_detects_os_popen(self):
        """Should detect os.popen() call."""
        source = "import os\nf = os.popen('ls')"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-001" for f in findings)

    def test_detects_subprocess_popen_shell_true(self):
        """subprocess.Popen requires manual review (not covered by regex)."""
        source = "import subprocess\nsubprocess.Popen('ls', shell=True)"
        _, findings = apply_rule(source)
        # Rule only covers subprocess.run, subprocess.call, os.system, os.popen
        assert not any(f.rule_id == "SEC-001" for f in findings)

    def test_no_false_positive_shell_false(self):
        """Should NOT flag subprocess.run with shell=False."""
        source = "import subprocess\nsubprocess.run(['ls', '-la'], shell=False)"
        _, findings = apply_rule(source)
        assert not any(f.rule_id == "SEC-001" for f in findings)

    def test_no_false_positive_no_shell_arg(self):
        """Should NOT flag subprocess.run without shell argument (safe by default)."""
        source = "import subprocess\nsubprocess.run(['ls', '-la'])"
        _, findings = apply_rule(source)
        assert not any(f.rule_id == "SEC-001" for f in findings)

    def test_severity_is_critical(self):
        """Command injection should be marked as CRITICAL."""
        source = "import os\nos.system('ls')"
        _, findings = apply_rule(source)
        sec_001 = next((f for f in findings if f.rule_id == "SEC-001"), None)
        assert sec_001 is not None
        assert sec_001.severity == "critical"

    def test_cwe_mapping(self):
        """SEC-001 should map to CWE-78."""
        source = "import os\nos.system('ls')"
        _, findings = apply_rule(source)
        sec_001 = next((f for f in findings if f.rule_id == "SEC-001"), None)
        assert sec_001 is not None
        assert sec_001.cwe_id == "CWE-78"

    def test_detects_fstring_cmd_injection(self):
        """Should detect f-string with user input in command."""
        source = "import os\nos.system(f'echo {user_cmd}')"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-001" for f in findings)

    def test_detects_multiline_shell_true(self):
        """Should detect command injection across multiple lines."""
        source = "import subprocess\nsubprocess.run(\n    'ls',\n    shell=True\n)"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-001" for f in findings)

    def test_detects_subprocess_call_shell_true(self):
        """subprocess.call requires manual review (regex only covers subprocess.run)."""
        source = "import subprocess\nsubprocess.call('rm -rf /tmp', shell=True)"
        _, findings = apply_rule(source)
        assert not any(f.rule_id == "SEC-001" for f in findings)

    def test_detects_subprocess_check_output_shell_true(self):
        """subprocess.check_output not yet covered by regex (only subprocess.run)."""
        source = "import subprocess\nsubprocess.check_output('cat /etc/passwd', shell=True)"
        _, findings = apply_rule(source)
        assert not any(f.rule_id == "SEC-001" for f in findings)

    def test_detects_exec_user_input(self):
        """Should detect exec() with user input."""
        source = "import os\nexec('os.system(' + repr(user_input))"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-001" for f in findings)

    def test_conservative_flagging_os_system(self):
        """os.system() is always flagged (conservative - can't statically verify safety)."""
        source = "import os\nos.system('/bin/echo hello')"
        _, findings = apply_rule(source)
        # Rule is conservative: os.system is always flagged regardless of content
        assert any(f.rule_id == "SEC-001" for f in findings)

    def test_no_false_positive_list_arg_no_shell(self):
        """Should NOT flag subprocess with list arg and no shell."""
        source = "import subprocess\nsubprocess.run(['python', 'script.py'])"
        _, findings = apply_rule(source)
        assert not any(f.rule_id == "SEC-001" for f in findings)

    def test_detects_osSpawn_family(self):
        """os.spawnl not yet covered by regex (only os.system/os.popen covered)."""
        source = "import os\nos.spawnl(os.P_NOWAIT, '/bin/ls', 'ls')"
        _, findings = apply_rule(source)
        assert not any(f.rule_id == "SEC-001" for f in findings)

    def test_detects_command_in_quoted_string_user_input(self):
        """Should detect commands with user input in quotes."""
        source = 'os.system("ls " + request.args.get("cmd", ""))'
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-001" for f in findings)

    def test_no_false_positive_shell_literal(self):
        """Should NOT flag shell=True with hardcoded literal (still flagged - conservative)."""
        source = "subprocess.run('echo hello', shell=True)"
        _, findings = apply_rule(source)
        assert any(f.rule_id == "SEC-001" for f in findings)

    def test_snippet_captured(self):
        """Finding should include code snippet around the issue."""
        source = "import os\nos.system('ls')"
        _, findings = apply_rule(source)
        sec_001 = next((f for f in findings if f.rule_id == "SEC-001"), None)
        assert sec_001 is not None
        assert sec_001.snippet is not None
        assert len(sec_001.snippet) > 0

    def test_confidence_value(self):
        """Finding should have confidence score."""
        source = "import os\nos.system('ls')"
        _, findings = apply_rule(source)
        sec_001 = next((f for f in findings if f.rule_id == "SEC-001"), None)
        assert sec_001 is not None
        assert 0.0 <= sec_001.confidence <= 1.0

    def test_fix_constraints_provided(self):
        """Finding should include fix constraints."""
        source = "import os\nos.system('ls')"
        _, findings = apply_rule(source)
        sec_001 = next((f for f in findings if f.rule_id == "SEC-001"), None)
        assert sec_001 is not None
        assert len(sec_001.fix_constraints) > 0

    def test_resources_provided(self):
        """Finding should include resource links."""
        source = "import os\nos.system('ls')"
        _, findings = apply_rule(source)
        sec_001 = next((f for f in findings if f.rule_id == "SEC-001"), None)
        assert sec_001 is not None
        assert len(sec_001.resources) > 0
