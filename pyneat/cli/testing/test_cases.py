"""Test case definitions for CLI testing per language.

Each language has test cases for the `clean` and `check` commands.
Add new test cases here — the test runner picks them up automatically.

Copyright (c) 2026 PyNEAT Authors
"""

from dataclasses import dataclass, field
from typing import Optional

from pyneat.cli.testing.cli_tester import TestCase


# --------------------------------------------------------------------------
# Python test cases
# --------------------------------------------------------------------------

PYTHON_CLEAN_CASES: list[TestCase] = [
    TestCase(
        name="is_not_none: fix != None",
        input_code='x = (y != None)\n',
        expected_contains="is not None",
        expected_return=0,
    ),
    TestCase(
        name="is_not_none: == None not changed",
        input_code='if x == None:\n    pass\n',
        expected_contains="No changes needed",
        expected_return=0,
    ),
    TestCase(
        name="clean empty file",
        input_code='# Just a comment\n',
        expected_contains="No changes needed",
        expected_return=0,
    ),
    TestCase(
        name="clean with already-clean code",
        input_code='def greet(name: str) -> str:\n    return f"Hello, {name}"\n',
        expected_contains="No changes needed",
        expected_return=0,
    ),
    TestCase(
        name="clean function with unused import",
        input_code='import os\ndef foo():\n    pass\n',
        flags=["--enable-unused"],
        expected_contains="import",
        expected_return=0,
    ),
]

PYTHON_CHECK_CASES: list[TestCase] = [
    TestCase(
        name="detect pickle.loads (CRITICAL)",
        input_code='import pickle\ndata = pickle.loads(user_input)\n',
        expected_severity="CRITICAL",
        command="check",
    ),
    TestCase(
        name="detect hardcoded secret (HIGH or CRITICAL)",
        input_code='API_KEY = "sk-abcdef1234567890"\n',
        expected_severity=None,
        command="check",
    ),
    TestCase(
        name="clean code returns no critical issues",
        input_code='def add(a: int, b: int) -> int:\n    return a + b\n',
        expected_severity=None,
        command="check",
        expected_return=0,
    ),
]

PYTHON_CASES = {
    "clean": PYTHON_CLEAN_CASES,
    "check": PYTHON_CHECK_CASES,
}


# --------------------------------------------------------------------------
# JavaScript test cases
# --------------------------------------------------------------------------

JS_CHECK_CASES: list[TestCase] = [
    TestCase(
        name="detect eval usage (CRITICAL)",
        input_code='eval(userInput);\n',
        lang="javascript",
        expected_severity="CRITICAL",
        command="check",
        flags=["--lang", "javascript"],
    ),
    TestCase(
        name="detect innerHTML injection (CRITICAL)",
        input_code='element.innerHTML = userData;\n',
        lang="javascript",
        expected_severity="CRITICAL",
        command="check",
        flags=["--lang", "javascript"],
    ),
    TestCase(
        name="detect console.log (info/low)",
        input_code='console.log("debug info");\nconst x = 1;\n',
        lang="javascript",
        expected_severity=None,
        command="check",
        flags=["--lang", "javascript"],
    ),
    TestCase(
        name="detect hardcoded API key",
        input_code='const API_KEY = "sk-live-abcdef123456";\n',
        lang="javascript",
        command="check",
        flags=["--lang", "javascript"],
    ),
    TestCase(
        name="clean JS file with no critical issues",
        input_code='const sum = (a, b) => a + b;\nexport { sum };\n',
        lang="javascript",
        command="check",
        flags=["--lang", "javascript"],
        expected_return=0,
    ),
]

JS_CASES: dict[str, list[TestCase]] = {
    "check": JS_CHECK_CASES,
}


# --------------------------------------------------------------------------
# TypeScript test cases
# --------------------------------------------------------------------------

TS_CHECK_CASES: list[TestCase] = [
    TestCase(
        name="detect eval in TS",
        input_code='eval(userInput);\n',
        lang="typescript",
        command="check",
        flags=["--lang", "typescript"],
    ),
    TestCase(
        name="clean TS with proper types",
        input_code='function greet(name: string): string {\n    return `Hello, ${name}`;\n}\n',
        lang="typescript",
        command="check",
        flags=["--lang", "typescript"],
        expected_return=0,
    ),
]

TS_CASES: dict[str, list[TestCase]] = {
    "check": TS_CHECK_CASES,
}


# --------------------------------------------------------------------------
# Go test cases
# --------------------------------------------------------------------------

GO_CHECK_CASES: list[TestCase] = [
    TestCase(
        name="detect error swallowing in Go",
        input_code='func main() {\n    _ = os.Open("file.txt")\n}\n',
        lang="go",
        command="check",
        flags=["--lang", "go"],
    ),
    TestCase(
        name="detect hardcoded secret in Go",
        input_code='apiKey := "sk-live-abcdef123456"\n',
        lang="go",
        expected_severity=None,
        command="check",
        flags=["--lang", "go"],
    ),
    TestCase(
        name="clean Go code",
        input_code='package main\n\nimport "fmt"\n\nfunc main() {\n    fmt.Println("Hello")\n}\n',
        lang="go",
        command="check",
        flags=["--lang", "go"],
        expected_return=0,
    ),
]

GO_CASES: dict[str, list[TestCase]] = {
    "check": GO_CHECK_CASES,
}


# --------------------------------------------------------------------------
# Java test cases
# --------------------------------------------------------------------------

JAVA_CHECK_CASES: list[TestCase] = [
    TestCase(
        name="detect SQL injection in Java",
        input_code='String query = "SELECT * FROM users WHERE id=" + userId;\n',
        lang="java",
        command="check",
        flags=["--lang", "java"],
    ),
    TestCase(
        name="detect hardcoded password in Java",
        input_code='String password = "admin123";\n',
        lang="java",
        command="check",
        flags=["--lang", "java"],
    ),
    TestCase(
        name="clean Java code",
        input_code='public class Hello {\n    public static void main(String[] args) {\n        System.out.println("Hello");\n    }\n}\n',
        lang="java",
        command="check",
        flags=["--lang", "java"],
        expected_return=0,
    ),
]

JAVA_CASES: dict[str, list[TestCase]] = {
    "check": JAVA_CHECK_CASES,
}


# --------------------------------------------------------------------------
# Rust test cases
# --------------------------------------------------------------------------

RUST_CHECK_CASES: list[TestCase] = [
    TestCase(
        name="detect expect() on Result",
        input_code='fn main() {\n    let _ = std::fs::read_to_string("file.txt").expect("Failed");\n}\n',
        lang="rust",
        command="check",
        flags=["--lang", "rust"],
    ),
    TestCase(
        name="detect unwrap() usage",
        input_code='fn main() {\n    let val = Some(42).unwrap();\n}\n',
        lang="rust",
        command="check",
        flags=["--lang", "rust"],
    ),
    TestCase(
        name="clean Rust code",
        input_code='fn main() {\n    println!("Hello, world!");\n}\n',
        lang="rust",
        command="check",
        flags=["--lang", "rust"],
        expected_return=0,
    ),
]

RUST_CASES: dict[str, list[TestCase]] = {
    "check": RUST_CHECK_CASES,
}


# --------------------------------------------------------------------------
# C# test cases
# --------------------------------------------------------------------------

CSHARP_CHECK_CASES: list[TestCase] = [
    TestCase(
        name="detect SQL injection in C#",
        input_code='var query = "SELECT * FROM Users WHERE Id=" + userId;\n',
        lang="csharp",
        command="check",
        flags=["--lang", "csharp"],
    ),
    TestCase(
        name="detect hardcoded connection string in C#",
        input_code='string connStr = "Server=localhost;Database=test";\n',
        lang="csharp",
        command="check",
        flags=["--lang", "csharp"],
    ),
    TestCase(
        name="clean C# code",
        input_code='using System;\nclass Program {\n    static void Main() {\n        Console.WriteLine("Hello");\n    }\n}\n',
        lang="csharp",
        command="check",
        flags=["--lang", "csharp"],
        expected_return=0,
    ),
]

CSHARP_CASES: dict[str, list[TestCase]] = {
    "check": CSHARP_CHECK_CASES,
}


# --------------------------------------------------------------------------
# PHP test cases
# --------------------------------------------------------------------------

PHP_CHECK_CASES: list[TestCase] = [
    TestCase(
        name="detect eval in PHP",
        input_code='<?php\neval($userCode);\n',
        lang="php",
        command="check",
        flags=["--lang", "php"],
    ),
    TestCase(
        name="clean PHP code",
        input_code='<?php\nfunction greet($name) {\n    return "Hello, $name";\n}\n',
        lang="php",
        command="check",
        flags=["--lang", "php"],
        expected_return=0,
    ),
]

PHP_CASES: dict[str, list[TestCase]] = {
    "check": PHP_CHECK_CASES,
}


# --------------------------------------------------------------------------
# Ruby test cases
# --------------------------------------------------------------------------

RUBY_CHECK_CASES: list[TestCase] = [
    TestCase(
        name="detect eval in Ruby",
        input_code='eval(user_input)\n',
        lang="ruby",
        command="check",
        flags=["--lang", "ruby"],
    ),
    TestCase(
        name="clean Ruby code",
        input_code='def greet(name)\n  puts "Hello, #{name}"\nend\n',
        lang="ruby",
        command="check",
        flags=["--lang", "ruby"],
        expected_return=0,
    ),
]

RUBY_CASES: dict[str, list[TestCase]] = {
    "check": RUBY_CHECK_CASES,
}


# --------------------------------------------------------------------------
# All languages combined
# --------------------------------------------------------------------------

ALL_LANG_CASES: dict[str, dict[str, list[TestCase]]] = {
    "python": PYTHON_CASES,
    "javascript": JS_CASES,
    "typescript": TS_CASES,
    "go": GO_CASES,
    "java": JAVA_CASES,
    "rust": RUST_CASES,
    "csharp": CSHARP_CASES,
    "php": PHP_CASES,
    "ruby": RUBY_CASES,
}

ALL_LANGUAGES: list[str] = list(ALL_LANG_CASES.keys())


def get_test_cases(lang: str) -> dict[str, list[TestCase]]:
    """Get all test cases for a language."""
    return ALL_LANG_CASES.get(lang.lower(), {})


def get_test_cases_for_command(lang: str, command: str) -> list[TestCase]:
    """Get test cases for a specific language and command."""
    lang_cases = get_test_cases(lang)
    return lang_cases.get(command, [])


def get_all_test_cases() -> list[tuple[str, str, TestCase]]:
    """Get all test cases as (lang, command, case) tuples."""
    result: list[tuple[str, str, TestCase]] = []
    for lang, commands in ALL_LANG_CASES.items():
        for cmd, cases in commands.items():
            for case in cases:
                result.append((lang, cmd, case))
    return result
