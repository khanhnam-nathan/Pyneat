"""Edge-case inputs: must not crash; output parses when success."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from pyneat.cli import _build_engine
from pyneat.core.types import CodeFile


@pytest.fixture
def engine():
    return _build_engine(
        {},
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        debug_clean_mode="off",
    )


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
