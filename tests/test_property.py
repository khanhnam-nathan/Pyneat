"""Parameterized checks (lightweight stand-in for heavy property-based deps)."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from pyneat.cli import _build_engine
from pyneat.core.types import CodeFile


@pytest.fixture
def redundant_engine():
    return _build_engine(
        {},
        False,
        False,
        False,
        False,
        True,
        False,
        False,
        debug_clean_mode="off",
    )


@pytest.mark.parametrize(
    "src,forbidden",
    [
        ("def f(x):\n    if x == True:\n        return 1\n", "== True"),
        ("def f():\n    return str(str(1))\n", "str(str("),
    ],
)
def test_redundant_rule_simplifies(redundant_engine, src, forbidden):
    r = redundant_engine.process_code_file(CodeFile(path=Path("p.py"), content=src))
    assert r.success, r.error
    ast.parse(r.transformed_content)
    assert forbidden not in r.transformed_content
