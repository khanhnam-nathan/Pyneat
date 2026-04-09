"""Smoke tests: engine runs and output stays valid Python."""

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
    False,                      # package placeholder
)


@pytest.fixture
def default_engine():
    return _build_engine({}, *_NO_BOOLS, debug_clean_mode="off")


def test_build_engine_has_rules(default_engine):
    stats = default_engine.get_rule_stats()
    assert stats["total_rules"] >= 1
    assert stats["enabled_rules"] >= 1


def test_process_minimal_module(default_engine):
    src = "x = 1\n"
    r = default_engine.process_code_file(CodeFile(path=Path("t.py"), content=src))
    assert r.success, r.error
    ast.parse(r.transformed_content)


def test_process_with_print_debug_mode_off(default_engine):
    src = "def f():\n    print('hi')\n"
    r = default_engine.process_code_file(CodeFile(path=Path("t.py"), content=src))
    assert r.success, r.error
    ast.parse(r.transformed_content)
