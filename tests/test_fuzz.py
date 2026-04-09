"""Edge-case inputs: must not crash; output parses when success."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from pyneat.cli import _build_engine
from pyneat.core.types import CodeFile

_NO_BOOLS = (
    False, False, False, False,  # security, quality, performance, unused
    False, False, False, False,  # redundant, is_not_none, magic_numbers, dead_code
    False, False, False, False,  # fstring, range_len, typing, match_case
    False,                      # dataclass
    False, False, False, False,  # import_cleaning, naming, refactoring, comment_clean
    False,
)


@pytest.fixture
def engine():
    return _build_engine({}, *_NO_BOOLS, debug_clean_mode="off")


@pytest.fixture
def debug_engine():
    """Engine with debug rules enabled for DebugCleaner fuzz tests."""
    return _build_engine({}, *_NO_BOOLS, debug_clean_mode="safe")


# ----------------------------------------------------------------------
# Basic round-trip: valid Python should parse after transformation
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "src",
    [
        "pass\n",
        "def f():\n    pass\n",
        "class C:\n    x = 1\n",
        "import os\nimport sys\n",
        "async def a():\n    await x\n",
        "match 1:\n    case _:\n        pass\n",
    ],
)
def test_snippet_roundtrip_parse(engine, src):
    r = engine.process_code_file(CodeFile(path=Path("snippet.py"), content=src))
    assert r.success, r.error
    ast.parse(r.transformed_content)


# ----------------------------------------------------------------------
# Malformed / invalid Python: must handle gracefully without crashing
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "src",
    [
        "def f(\n",                    # unclosed paren
        "class C:\n    x = 1\n",      # class without colon
        "if True\n",                  # missing colon
        "def f():\n    return\n" * 100,  # deeply nested return
        "x = 1",                       # no trailing newline
        "# only a comment\n",           # comment only
        "\n\n\n",                     # whitespace only
        "",                            # empty file
        "    leading whitespace\n",   # indented line outside function
    ],
)
def test_malformed_python_no_crash(engine, src):
    """Malformed Python should not crash the engine."""
    r = engine.process_code_file(CodeFile(path=Path("malformed.py"), content=src))
    # Should either succeed (with unchanged content) or gracefully fail
    assert r.success or r.error is not None
    # No crash means the error is captured
    assert isinstance(r.error, str) or r.transformed_content is not None


# ----------------------------------------------------------------------
# Unicode: identifiers, comments, strings
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "src",
    [
        "# comment with unicode: caf\u00e9\nx = 1\n",
        "name = '\u2764'  # heart emoji\n",
        "\u00e9 = 1  # valid Unicode name\n",
        # Unicode in strings only (identifiers excluded to avoid Python 3.14 ast edge cases)
        "name = '\u2764'  # heart emoji\n",
        "# comment with caf\u00e9\nx = 1\n",
    ],
)
def test_unicode_handling(engine, src):
    """Unicode identifiers and strings should not crash."""
    r = engine.process_code_file(CodeFile(path=Path("unicode.py"), content=src))
    assert r.success
    assert r.transformed_content is not None


# ----------------------------------------------------------------------
# Very long lines (>10K chars): must not crash or timeout
# ----------------------------------------------------------------------

def test_very_long_line(engine):
    """Very long lines should be handled without crashing."""
    long_line = "x = " + '"' + "a" * 20_000 + '"\n'
    r = engine.process_code_file(CodeFile(path=Path("long.py"), content=long_line))
    assert r.success
    assert len(r.transformed_content) > 0


def test_many_small_lines(engine):
    """Many small lines should be handled."""
    lines = "\n".join(f"x{i} = {i}" for i in range(10_000)) + "\n"
    r = engine.process_code_file(CodeFile(path=Path("many.py"), content=lines))
    assert r.success


# ----------------------------------------------------------------------
# Whitespace-only and comment-only files
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "src",
    [
        "",
        "   \n   \n   \n",
        "# just a comment\n",
        "# multiple\n# comments\n",
        "    # indented comment\n",
    ],
)
def test_whitespace_comment_only(engine, src):
    """Whitespace-only and comment-only files should not crash."""
    r = engine.process_code_file(CodeFile(path=Path("ws.py"), content=src))
    assert r.success
    assert r.transformed_content is not None


# ----------------------------------------------------------------------
# DebugCleaner fuzz: various debug print patterns
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "src,expect_removed",
    [
        ("print('debug')\n", True),
        ("print('[INFO] starting')\n", True),
        ("print('xwyn')\n", True),
        ("print('Processing complete')\n", False),   # meaningful message
        ("print('Hello, World!')\n", False),           # user message
        ("print()\n", True),                            # empty print
        ("print('[DEBUG] value:', x)\n", True),
        ("print('[ERROR] failed')\n", True),
        ("print('test result:', result)\n", True),
    ],
)
def test_debug_cleaner_patterns(debug_engine, src, expect_removed):
    """DebugCleaner correctly identifies and removes debug prints."""
    r = debug_engine.process_code_file(CodeFile(path=Path("debug.py"), content=src))
    assert r.success
    if expect_removed:
        assert 'print' not in r.transformed_content, f"Expected 'print' to be removed from: {src!r}"
    else:
        assert 'print' in r.transformed_content, f"Expected 'print' to remain in: {src!r}"


# ----------------------------------------------------------------------
# Concatenated strings with keywords
# ----------------------------------------------------------------------

def test_concatenated_debug_string(debug_engine):
    """Concatenated strings containing debug keywords should be removed."""
    src = "print('debug' + ': ' + 'message')\n"
    r = debug_engine.process_code_file(CodeFile(path=Path("debug.py"), content=src))
    assert r.success
    assert 'print' not in r.transformed_content
