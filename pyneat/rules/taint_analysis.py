"""Taint analysis for tracking data flow from sources to sinks.

This module provides lightweight taint tracking to identify potential security
vulnerabilities where untrusted input flows into dangerous operations.

Copyright (c) 2026 PyNEAT Authors
License: AGPL-3.0
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Set, Dict, List, Optional, Tuple
import ast


class TaintLevel(Enum):
    """Level of taint in a variable or expression."""
    CLEAN = "clean"
    POTENTIAL = "potential"  # May be tainted, needs verification
    TAINTED = "tainted"     # Definitely tainted


class TaintSource(Enum):
    """Types of taint sources (where untrusted data comes from)."""
    USER_INPUT = "user_input"           # input(), sys.stdin
    ENV_VAR = "env_var"               # os.environ, os.getenv
    FILE_READ = "file_read"           # open(), read()
    NETWORK = "network"               # requests, urllib, socket
    DATABASE = "database"              # query results
    CGI = "cgi"                       # CGI parameters
    COMMAND_LINE = "command_line"     # sys.argv
    TEST_DATA = "test_data"           # Test fixtures
    WEB_INPUT = "web_input"           # Flask/Django/FastAPI request
    UNKNOWN = "unknown"


class DangerousSink(Enum):
    """Types of dangerous sinks (operations that can be exploited)."""
    EVAL = "eval"                    # eval(), exec()
    COMMAND = "command"              # os.system, subprocess
    SQL = "sql"                      # cursor.execute with string
    FILE_OP = "file_operation"       # open() for write
    CODE_GEN = "code_generation"     # compile(), __import__
    DESERIALIZE = "deserialization"  # pickle.loads, yaml.load
    HTML = "html"                    # markupsafe, innerHTML
    REDIRECT = "redirect"            # urllib redirect


@dataclass
class VariableTaint:
    """Taint information for a variable."""
    name: str
    source: TaintSource
    level: TaintLevel
    line: int
    propagation_chain: List[str] = field(default_factory=list)

    def __repr__(self):
        return f"VariableTaint({self.name}, {self.source.value}, {self.level.value})"


@dataclass
class Finding:
    """A taint analysis finding."""
    source_variable: str
    sink: DangerousSink
    source_type: TaintSource
    path: List[str]  # Variables in the propagation chain
    line: int
    severity: str
    description: str
    suggestion: str


class TaintTracker:
    """Tracks taint propagation through variable assignments.

    This is a simplified taint analysis that tracks:
    1. Where tainted data enters (sources)
    2. How it propagates through variables
    3. Where it reaches dangerous operations (sinks)
    """

    def __init__(self):
        self.sources: Dict[str, VariableTaint] = {}
        self.tainted_vars: Set[str] = set()
        self.assignments: Dict[str, str] = {}  # var -> expression/source
        self._in_test_file = False

    def mark_tainted(
        self,
        var_name: str,
        source: TaintSource,
        level: TaintLevel = TaintLevel.TAINTED,
        line: int = 0,
    ):
        """Mark a variable as tainted from a source."""
        self.tainted_vars.add(var_name)
        self.sources[var_name] = VariableTaint(
            name=var_name,
            source=source,
            level=level,
            line=line,
        )
        self.assignments[var_name] = source.value

    def propagate(self, from_var: str, to_var: str):
        """Propagate taint from one variable to another."""
        if from_var in self.tainted_vars:
            self.tainted_vars.add(to_var)
            self.assignments[to_var] = self.assignments.get(from_var, TaintSource.UNKNOWN.value)
            if from_var in self.sources:
                self.sources[to_var] = VariableTaint(
                    name=to_var,
                    source=self.sources[from_var].source,
                    level=self.sources[from_var].level,
                    line=self.sources[from_var].line,
                    propagation_chain=self.sources[from_var].propagation_chain + [from_var],
                )

    def get_taint_level(self, var_name: str) -> TaintLevel:
        """Get the taint level of a variable."""
        if var_name not in self.tainted_vars:
            return TaintLevel.CLEAN
        if var_name in self.sources:
            return self.sources[var_name].level
        return TaintLevel.POTENTIAL

    def is_tainted(self, var_name: str) -> bool:
        """Check if a variable is tainted."""
        return var_name in self.tainted_vars

    def set_test_file(self, is_test: bool):
        """Mark whether we're analyzing a test file."""
        self._in_test_file = is_test


# Source detection patterns
USER_INPUT_PATTERNS = {
    "input(": TaintSource.USER_INPUT,
    "sys.stdin": TaintSource.USER_INPUT,
    "sys.argv": TaintSource.COMMAND_LINE,
    "os.environ": TaintSource.ENV_VAR,
    "os.getenv": TaintSource.ENV_VAR,
    "os.environ.get": TaintSource.ENV_VAR,
    "request.args": TaintSource.WEB_INPUT,
    "request.form": TaintSource.WEB_INPUT,
    "request.json": TaintSource.WEB_INPUT,
    "request.values": TaintSource.WEB_INPUT,
    "request.GET": TaintSource.WEB_INPUT,
    "request.POST": TaintSource.WEB_INPUT,
    "flask.request": TaintSource.WEB_INPUT,
    "django.request": TaintSource.WEB_INPUT,
    "fastapi.Request": TaintSource.WEB_INPUT,
}

SINK_PATTERNS = {
    DangerousSink.EVAL: {"eval(", "exec("},
    DangerousSink.COMMAND: {"os.system", "os.popen", "subprocess.run", "subprocess.Popen"},
    DangerousSink.SQL: {"cursor.execute", "db.execute", "connection.execute"},
    DangerousSink.FILE_OP: {"open(", "Path.write", "Path.touch"},
    DangerousSink.CODE_GEN: {"compile(", "__import__", "importlib.import_module"},
    DangerousSink.DESERIALIZE: {"pickle.loads", "yaml.load", "marshal.loads", "eval("},
    DangerousSink.HTML: {"markupsafe.Markup", ".html(", "innerHTML", ".append("},
    DangerousSink.REDIRECT: {"redirect(", "Response.redirect"},
}


def analyze_taint(code: str, file_path: str = "") -> List[Finding]:
    """Analyze code for taint flow vulnerabilities.

    Args:
        code: Python source code to analyze
        file_path: Path to the source file (for context)

    Returns:
        List of findings where tainted data reaches dangerous sinks
    """
    findings = []
    tracker = TaintTracker()
    tracker.set_test_file("test" in file_path.lower())

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings

    # Pass 1: Identify taint sources
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    if isinstance(node.value, ast.Call):
                        call_str = ast.unparse(node.value)
                        for pattern, source in USER_INPUT_PATTERNS.items():
                            if pattern in call_str:
                                level = TaintLevel.TAINTED
                                if source == TaintSource.TEST_DATA or tracker._in_test_file:
                                    level = TaintLevel.POTENTIAL
                                tracker.mark_tainted(var_name, source, level, node.lineno or 0)
                                break

        # Track direct assignments from tainted variables
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    if isinstance(node.value, ast.Name):
                        tracker.propagate(node.value.id, var_name)
                    elif isinstance(node.value, ast.Attribute):
                        if isinstance(node.value.value, ast.Name):
                            tracker.propagate(node.value.value.id, var_name)

    # Pass 2: Find dangerous sink usages
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_str = ast.unparse(node.value) if isinstance(node.value, ast.Attribute) else ""

            for sink_type, patterns in SINK_PATTERNS.items():
                for pattern in patterns:
                    if pattern in call_str:
                        # Check if any argument is tainted
                        for arg in node.args:
                            tainted_vars = _find_tainted_vars(arg, tracker)
                            if tainted_vars:
                                for var in tainted_vars:
                                    source_info = tracker.sources.get(var)
                                    findings.append(Finding(
                                        source_variable=var,
                                        sink=sink_type,
                                        source_type=source_info.source if source_info else TaintSource.UNKNOWN,
                                        path=[var],
                                        line=node.lineno or 0,
                                        severity="high",
                                        description=f"Tainted data from {source_info.source.value if source_info else 'unknown'} flows to {sink_type.value}",
                                        suggestion=f"Validate/sanitize {var} before using in {sink_type.value}",
                                    ))

    return findings


def _find_tainted_vars(node: ast.AST, tracker: TaintTracker) -> List[str]:
    """Find all tainted variables in an AST node."""
    tainted = []

    if isinstance(node, ast.Name):
        if tracker.is_tainted(node.id):
            tainted.append(node.id)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        # Concatenation - both sides might be tainted
        tainted.extend(_find_tainted_vars(node.left, tracker))
        tainted.extend(_find_tainted_vars(node.right, tracker))
    elif isinstance(node, ast.JoinedStr):
        # f-string - all values might be tainted
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                tainted.extend(_find_tainted_vars(value.value, tracker))

    return tainted


def get_taint_report(findings: List[Finding]) -> str:
    """Generate a human-readable taint analysis report.

    Args:
        findings: List of taint analysis findings

    Returns:
        Formatted report string
    """
    if not findings:
        return "No taint flow vulnerabilities detected."

    lines = ["Taint Analysis Report", "=" * 40]

    for i, f in enumerate(findings, 1):
        lines.append(f"\n{i}. Line {f.line}: {f.description}")
        lines.append(f"   Source: {f.source_variable} ({f.source_type.value})")
        lines.append(f"   Sink: {f.sink.value}")
        lines.append(f"   Suggestion: {f.suggestion}")

    return "\n".join(lines)


# Example usage
if __name__ == "__main__":
    test_code = '''
import os
import sys

# Taint source: user input
user_input = input("Enter name: ")

# Taint propagation
name = user_input

# Dangerous sink: SQL injection
cursor.execute("SELECT * FROM users WHERE name=" + name)

# Another dangerous sink: command injection
os.system("echo " + user_input)
'''

    findings = analyze_taint(test_code, "/app/user_input.py")
    print(get_taint_report(findings))
