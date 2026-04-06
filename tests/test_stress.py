"""Larger inputs and directory processing."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from pyneat.cli import _build_engine


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


def test_many_duplicate_imports(engine):
    lines = ["import os\n"] * 200 + ["x = 1\n"]
    src = "".join(lines)
    from pyneat.core.types import CodeFile

    r = engine.process_code_file(CodeFile(path=Path("big.py"), content=src))
    assert r.success, r.error
    ast.parse(r.transformed_content)


def test_process_test_samples_github_new(engine):
    root = Path(__file__).resolve().parent.parent / "test_samples" / "github_new"
    if not root.is_dir():
        pytest.skip("test_samples/github_new not present")
    summary = engine.process_directory(root, pattern="*.py", recursive=False)
    assert summary["failed"] == 0, summary["results"]
