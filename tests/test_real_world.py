"""Integration-style checks against bundled sample files."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from pyneat.cli import _build_engine
from pyneat.core.types import CodeFile


SAMPLES = Path(__file__).resolve().parent.parent / "test_samples"


@pytest.mark.parametrize(
    "rel",
    [
        "github_new/redundant_exprs.py",
        "github_new/complex_imports.py",
    ],
)
def test_sample_file_processes(rel):
    path = SAMPLES / rel
    if not path.is_file():
        pytest.skip(f"missing {rel}")
    engine = _build_engine(
        {},
        False,
        False,
        False,
        True,
        True,
        False,
        False,
        debug_clean_mode="safe",
    )
    r = engine.process_file(path)
    assert r.success, r.error
    ast.parse(r.transformed_content)
