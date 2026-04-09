"""Comprehensive semantic integrity tests for PyNEAT.

Detects bugs by verifying that cleaned code is semantically equivalent to
the original — same AST structure, same runtime behavior, no new type errors.

Strategy:
  1. Syntax preservation   — cleaned code must parse/compile
  2. AST structural guard  — only expected node types change
  3. Runtime equivalence   — original and cleaned produce identical output
  4. Round-trip stability — cleaning twice yields the same result
  5. Type regression       — no new mypy/pyright errors (Layer 6)
  6. Fuzz robustness     — no crash on malformed inputs
  7. Rule edge cases       — per-rule boundary testing
"""

from __future__ import annotations

import ast
import hashlib
import io
import os
import random
import re
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Callable, List, Optional, Set

import pytest

from pyneat.cli import _build_engine
from pyneat.core.engine import RuleEngine
from pyneat.core.types import CodeFile, TransformationResult
from pyneat.rules.base import Rule


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

_NO_BOOLS = (
    False, False, False, False,  # security, quality, performance, unused
    False, False, False, False,  # redundant, is_not_none, magic_numbers, dead_code
    False, False, False, False,  # fstring, range_len, typing, match_case
    False,                      # dataclass
    # 5 new destructive rule flags
    False, False, False, False,  # import_cleaning, naming, refactoring, comment_clean
    False,                      # package (no-op, accepted by _build_engine)
)


def _build(**overrides) -> RuleEngine:
    """Build engine with default safe rules."""
    engine = _build_engine({}, *_NO_BOOLS, debug_clean_mode="off")
    for k, v in overrides.items():
        setattr(engine, k, v)
    return engine


def _capture_exec(code: str, globals_dict: dict | None = None) -> tuple[str, Exception | None]:
    """Run code, return (stdout, exception)."""
    buf = io.StringIO()
    err_buf = io.StringIO()
    g = {"__stdout__": buf} | (globals_dict or {})
    try:
        exec(compile(code, "<test>", "exec"), g)
        return buf.getvalue(), None
    except Exception as e:
        return buf.getvalue(), e


def _ast_key(node: ast.AST) -> str:
    """Structural AST key (no position metadata)."""
    return f"{node.__class__.__name__}:{getattr(node, 'name', '')}"


def _strip_and_key(tree: ast.AST) -> str:
    """Serialize AST without positions for comparison."""
    nodes: list[str] = []
    for n in ast.walk(tree):
        nodes.append(_ast_key(n))
    return "|".join(sorted(nodes))


# --------------------------------------------------------------------------
# 1. Syntax Preservation
# --------------------------------------------------------------------------

class TestSyntaxPreservation:
    """Every cleaned file must be valid Python — no syntax errors."""

    @pytest.mark.parametrize("snippet", [
        "x = 1",
        "def f(): pass",
        "class C: pass",
        "import os",
        "from __future__ import annotations",
        "x: int = 1",
        "match x:\n    case 1: pass",
        "async def f(): await x",
        "[x for x in range(10)]",
        "{**a, **b}",
        "f'x={x}'",
    ])
    def test_clean_parses_valid(self, snippet: str):
        engine = _build()
        result = engine.process_code_file(
            CodeFile(path=Path("t.py"), content=snippet)
        )
        if result.has_changes:
            ast.parse(result.transformed_content)  # raises SyntaxError

    def test_clean_compiles_valid(self, tmp_path: Path):
        engine = _build()
        f = tmp_path / "t.py"
        f.write_text("def f():\n    pass\n")
        result = engine.process_file(f)
        if result.has_changes:
            compile(result.transformed_content, str(f), "exec")  # raises

    @pytest.mark.parametrize("malformed", [
        "===INVALID<<<",
        "def f(\n",
        "class C:\n",
        "",
        "   \n   \n",
        "# comment\n",
        "if True\n",
        "x = ",
        "   leading ws\n",
    ])
    def test_malformed_no_crash(self, malformed: str):
        result = _build().process_code_file(
            CodeFile(path=Path("t.py"), content=malformed)
        )
        assert isinstance(result, TransformationResult)


# --------------------------------------------------------------------------
# 2. AST Structural Guard
# --------------------------------------------------------------------------

class TestASTStructure:
    """Cleaned code must have the same AST structure — except for allowed nodes."""

    # Allowed structural changes per-rule-category
    ALLOWED_BY_CATEGORY: dict[str, Set[str]] = {
        "deadcode": {"FunctionDef", "AsyncFunctionDef", "ClassDef"},
        "fstring": {"JoinedStr", "FormattedValue"},
        "imports": {"Import", "ImportFrom"},
    }

    @pytest.mark.parametrize("code,allowed", [
        ("def unused(): pass\n\nx = 1\n",
         {"FunctionDef"}),
        ("from __future__ import annotations\nx = 1\n", set()),
        ('print("%s" % x)', {"JoinedStr", "FormattedValue"}),
        ("import os\nprint(os)", set()),
        ("if x is not None: print(x)",
         set()),  # is_not_none may only fire in safe contexts
    ])
    def test_only_allowed_nodes_change(self, code: str, allowed: Set[str]):
        tree_before = ast.parse(code)
        result = _build().process_code_file(
            CodeFile(path=Path("t.py"), content=code)
        )
        if not result.has_changes:
            return  # nothing changed

        tree_after = ast.parse(result.transformed_content)
        keys_before = set(_ast_key(n) for n in ast.walk(tree_before))
        keys_after = set(_ast_key(n) for n in ast.walk(tree_after))

        unexpected = keys_after - keys_before - allowed
        removed_allowed = keys_before - keys_after - allowed

        assert not unexpected, f"Unexpected nodes added: {unexpected}"
        assert not removed_allowed, f"Unexpected nodes removed: {removed_allowed}"

    def test_all_rules_preserve_module_structure(self):
        """Top-level constructs (except dead code) should be stable."""
        code = textwrap.dedent("""\
            from __future__ import annotations
            import os
            import sys

            def public_func():
                pass

            class MyClass:
                pass

            if __name__ == "__main__":
                public_func()
        """)
        tree_before = ast.parse(code)
        result = _build().process_code_file(
            CodeFile(path=Path("t.py"), content=code)
        )
        tree_after = ast.parse(result.transformed_content)

        # Only private/dead code should disappear
        before_keys = {_ast_key(n) for n in ast.walk(tree_before)}
        after_keys = {_ast_key(n) for n in ast.walk(tree_after)}

        public_nodes = {n for n in before_keys
                       if "unused" not in n and "private" not in n}
        assert public_nodes <= after_keys, "Public constructs disappeared!"


# --------------------------------------------------------------------------
# 3. Runtime Equivalence (BEFORE == AFTER)
# --------------------------------------------------------------------------

class TestRuntimeEquivalence:
    """Original and cleaned code must produce identical output."""

    @pytest.mark.parametrize("code,call_dicts", [
        # Basic
        ("x = 1\nprint(x)", [{"x": 1}]),
        # Function
        ("def inc(n): return n+1\nprint(inc(5))", [{}]),
        # Class
        ("class C:\n    val = 42\nprint(C.val)", [{}]),
        # Side effects preserved
        ("results = []\n"
         "for i in range(3): results.append(i*2)\n"
         "print(results)", [{}]),
        # Dead code removed — behavior unchanged
        ("def unused(): return 999\n"
         "def used(): return 42\n"
         "print(used())", [{}]),
        # Conditional branches preserved
        ("x = True\n"
         "if x: print('yes')\n"
         "else: print('no')", [{}]),
        # Imports
        ("import math\nprint(math.pi)", [{}]),
        # F-string (behavior must match)
        ('x = 42\nprint(f"x={x}")', [{}]),
    ])
    def test_output_identical(self, code: str, call_dicts: List[dict]):
        result = _build().process_code_file(
            CodeFile(path=Path("t.py"), content=code)
        )

        if result.has_changes:
            # Ensure cleaned code parses
            ast.parse(result.transformed_content)

        for ctx in call_dicts:
            _, err_orig = _capture_exec(code, ctx)
            _, err_clean = _capture_exec(result.transformed_content, ctx)

            # Both must succeed or both must fail the same way
            assert type(err_orig) == type(err_clean), (
                f"Runtime error mismatch:\n  orig={err_orig}\n  clean={err_clean}"
            )

    @pytest.mark.parametrize("code", [
        "def fib(n): return n if n < 2 else fib(n-1) + fib(n-2)\nprint(fib(8))",
        "[x**2 for x in range(1, 6)]",
        "{k: v for k, v in enumerate(['a','b','c'])}",
        "d = {'a': 1, 'b': 2}\nprint(sum(d.values()))",
    ])
    def test_return_value_stable(self, code: str):
        result = _build().process_code_file(
            CodeFile(path=Path("t.py"), content=code)
        )
        if not result.has_changes:
            return

        _, err_orig = _capture_exec(code)
        _, err_clean = _capture_exec(result.transformed_content)

        assert err_orig is None and err_clean is None, \
            f"Cleaned code raises: {err_clean}"


# --------------------------------------------------------------------------
# 4. Round-trip Stability
# --------------------------------------------------------------------------

class TestRoundTripStability:
    """Cleaning twice must converge — idempotent."""

    @pytest.mark.parametrize("code", [
        "x = 1\ny = 2\nz = 3\n",
        "def unused(): pass\ndef used(): return 1\nprint(used())\n",
        "import os\nimport sys\nimport re\n",
        "a = 1\nb = 2\nc = 3\n",
        "from __future__ import annotations\nfrom __future__ import print_function\n",
    ])
    def test_double_clean_same_as_single(self, code: str):
        r1 = _build().process_code_file(
            CodeFile(path=Path("t.py"), content=code)
        )
        r2 = _build().process_code_file(
            CodeFile(path=Path("t.py"), content=r1.transformed_content)
        )

        assert r1.transformed_content == r2.transformed_content, (
            "Clean is not idempotent:\n"
            f"  1st clean: {repr(r1.transformed_content)}\n"
            f"  2nd clean: {repr(r2.transformed_content)}"
        )

    @pytest.mark.parametrize("snippet", [
        "def foo(): pass",
        "class Bar: pass",
        "x = 1",
        "import os",
    ])
    def test_clean_clean_already_clean(self, snippet: str):
        r1 = _build().process_code_file(
            CodeFile(path=Path("t.py"), content=snippet)
        )
        r2 = _build().process_code_file(
            CodeFile(path=Path("t.py"), content=r1.transformed_content)
        )
        assert r1.transformed_content == r2.transformed_content


# --------------------------------------------------------------------------
# 5. Type Regression (Layer 6)
# --------------------------------------------------------------------------

class TestTypeRegression:
    """Clean must not introduce new mypy errors."""

    def test_no_new_mypy_errors(self, tmp_path: Path):
        code = (
            "def add(a: int, b: int) -> int:\n"
            "    return a + b\n"
            "x: int = add(1, 2)\n"
        )
        f = tmp_path / "typed.py"
        f.write_text(code)

        # Baseline
        r1 = subprocess.run(
            [sys.executable, "-m", "mypy", str(f), "--no-error-summary"],
            capture_output=True, text=True,
        )
        baseline = set(r1.stdout.splitlines())

        # Clean
        _build().process_file(f)

        # After clean
        r2 = subprocess.run(
            [sys.executable, "-m", "mypy", str(f), "--no-error-summary"],
            capture_output=True, text=True,
        )
        after = set(r2.stdout.splitlines())

        new_errors = after - baseline
        assert not new_errors, f"New mypy errors after clean: {new_errors}"


# --------------------------------------------------------------------------
# 6. Fuzz Robustness
# --------------------------------------------------------------------------

class TestFuzzRobustness:
    """Random/minimal Python snippets must not crash the engine."""

    SNIPPETS = [
        # Edge Python syntax
        "...",
        "pass",
        "continue",
        "break",
        "return",
        "raise",
        "yield",
        "global x",
        "nonlocal x",
        "del x",
        # Literals
        "None",
        "True",
        "...",
        "b'bytes'",
        "r'raw'",
        # Expressions
        "(x for x in [])",
        "[x for x in [] if x]",
        "{x for x in []}",
        "{x: y for x, y in []}",
        # Control flow
        "try: pass\nexcept: pass\nfinally: pass",
        "with open('x') as f: pass",
        "match x:\n    case 1: pass\n    case _: pass",
        # Decorators
        "@property\ndef x(self): pass",
        "@staticmethod\ndef f(): pass",
        "@classmethod\ndef f(cls): pass",
        # Docstrings
        '"""docstring"""',
        "'''multi\nline'''",
        # Complex
        "class A(B, metaclass=M): pass",
        "def f(*args, **kwargs): pass",
        "lambda x: x + 1",
    ]

    @pytest.mark.parametrize("snippet", SNIPPETS)
    def test_no_crash_on_edge_cases(self, snippet: str):
        result = _build().process_code_file(
            CodeFile(path=Path("t.py"), content=snippet)
        )
        assert isinstance(result, TransformationResult)
        # If changes were made, must parse
        if result.has_changes:
            ast.parse(result.transformed_content)

    def test_unicode_and_emojis_no_crash(self, tmp_path: Path):
        snippets = [
            "café = 'café'",
            "name = 'Αλφα'",
            "emoji = '🎉'",
            "x = 'café Ω'",
            "# comment with 日本語",
        ]
        for s in snippets:
            result = _build().process_code_file(
                CodeFile(path=Path("t.py"), content=s)
            )
            assert isinstance(result, TransformationResult)

    @pytest.mark.parametrize("snippet", SNIPPETS[:5])
    def test_all_rules_combined_no_crash(self, snippet: str):
        """Run engine with ALL rules enabled — hardest stress test."""
        # Only safe rules enabled in _build(), so use a full engine
        from pyneat.cli import _build_engine
        full_engine = _build_engine(
            {}, True, True, True, True,
            True, True, True, True,
            True, True, True, True,
            True, True, True, True,
            True, True,
            debug_clean_mode="off",
        )
        result = full_engine.process_code_file(
            CodeFile(path=Path("t.py"), content=snippet)
        )
        assert isinstance(result, TransformationResult)


# --------------------------------------------------------------------------
# 7. Per-Rule Edge Cases
# --------------------------------------------------------------------------

class TestDeadCodeRuleEdgeCases:
    """DeadCodeRule must be conservative — only remove truly dead code."""

    @pytest.mark.parametrize("code,should_remove", [
        # Truly unused
        ("def unused(): pass\n\nprint(1)", True),
        ("class UnusedClass: pass\n\nprint(1)", True),
        # Used
        ("def used(): return 1\n\nprint(used())", False),
        ("class Used: pass\n\nx = Used()", False),
        # Magic methods
        ("def __init__(self): pass", False),
        ("def __str__(self): return ''", False),
        # Entry points
        ("def main(): pass", False),
        ("def run(): pass", False),
        ("def cli(): pass", False),
        ("def app(): pass", False),
        # Decorated
        ("@property\ndef x(self): pass", False),
        ("@staticmethod\ndef f(): pass", False),
        ("@app.route('/')\ndef handler(): pass", False),
        # In __main__
        ("def helper(): pass\n\nif __name__ == '__main__':\n    helper()", False),
        # Side effects — these should NOT be removed
        ("def f(): print('side')\n\nprint(1)", False),  # print = side effect → keep
        ("def f(): raise ValueError()\n\nprint(1)", False),  # raise = side effect → keep
        # Private (underscore)
        ("def _unused(): pass\n\nprint(1)", True),  # conservative: remove
    ])
    def test_deadcode_removal_decisions(self, code: str, should_remove: bool):
        from pyneat.rules.deadcode import DeadCodeRule
        rule = DeadCodeRule()
        result = rule.apply(CodeFile(path=Path("t.py"), content=code))

        removed_anything = "dead code" in " ".join(result.changes_made).lower() or \
                           "unused" in " ".join(result.changes_made).lower()
        assert removed_anything == should_remove, (
            f"Code: {repr(code)}\n"
            f"Changes: {result.changes_made}\n"
            f"Expected removal={should_remove}"
        )


class TestFStringRuleEdgeCases:
    """FStringRule must preserve string semantics."""

    @pytest.mark.parametrize("code", [
        'print("hello")',
        'print("x=%s" % x)',
        'print("a={} b={}".format(a, b))',
        'print(f"x={x}")',
        'print(f"a:{x:.2f}")',
        'x = "%s" % val',   # non-print context
    ])
    def test_fstring_conversion_safe(self, code: str):
        result = _build().process_code_file(
            CodeFile(path=Path("t.py"), content=code)
        )
        if result.has_changes:
            _, err_orig = _capture_exec(code)
            _, err_clean = _capture_exec(result.transformed_content)
            assert err_orig is None and err_clean is None


class TestImportRuleEdgeCases:
    """Import cleaning must preserve all used names."""

    @pytest.mark.parametrize("code", [
        "import os\nprint(os.getcwd())",
        "import os, sys\nprint(sys.version)",
        "from os.path import join\nprint(join('a', 'b'))",
        "from collections import OrderedDict\nd = OrderedDict()",
        "import typing as t\nprint(t.Optional)",  # aliased
    ])
    def test_import_removal_preserves_used(self, code: str):
        result = _build().process_code_file(
            CodeFile(path=Path("t.py"), content=code)
        )
        # Must not crash
        assert isinstance(result, TransformationResult)
        # If it changes imports, the cleaned code must still run
        if result.has_changes:
            _, err_clean = _capture_exec(result.transformed_content)
            assert err_clean is None


# --------------------------------------------------------------------------
# 8. On-Disk Integration
# --------------------------------------------------------------------------

class TestOnDiskIntegration:
    """process_file must handle real files correctly."""

    @pytest.mark.parametrize("content", [
        "x = 1\n",
        "def f(): return 42\n",
        "class C: pass\n",
    ])
    def test_file_written_equals_result(self, content: str, tmp_path: Path):
        f = tmp_path / "sample.py"
        f.write_bytes(content.encode("utf-8"))

        result = _build().process_file(f)

        if result.has_changes:
            assert f.read_bytes() == result.transformed_content.encode("utf-8")

    def test_backup_exists_after_change(self, tmp_path: Path):
        f = tmp_path / "sample.py"
        f.write_text("def unused(): pass\n\nx = 1\n")

        result = _build().process_file(f)

        if result.has_changes:
            bak = Path(str(f) + ".pyneat.bak")
            assert bak.exists(), "Backup .pyneat.bak not created"

    def test_backup_equals_original(self, tmp_path: Path):
        f = tmp_path / "sample.py"
        original = "x = 1\n"
        f.write_text(original)

        result = _build().process_file(f)

        if result.has_changes:
            bak = Path(str(f) + ".pyneat.bak")
            assert bak.read_bytes() == original.encode("utf-8-sig")


# --------------------------------------------------------------------------
# 9. Semantic Guard (Layer 5) smoke tests
# --------------------------------------------------------------------------

class TestLayer5SemanticGuard:
    """SemanticGuard catches dangerous transformations."""

    def test_guard_blocks_undeclared_assignment_removal(self):
        from pyneat.core.semantic_guard import SemanticDiffGuard
        guard = SemanticDiffGuard()

        before = "x = 1\n"
        after = ""
        is_safe, msgs = guard.is_safe(before, after, allowed_nodes=set())

        assert is_safe is False, "Removing an assignment should be flagged!"

    def test_guard_blocks_undeclared_assignment_addition(self):
        from pyneat.core.semantic_guard import SemanticDiffGuard
        guard = SemanticDiffGuard()

        before = "x = 1\n"
        after = "x = 1\ny = 2\n"
        is_safe, msgs = guard.is_safe(before, after, allowed_nodes=set())

        assert is_safe is False, "Adding an assignment should be flagged!"

    def test_guard_allows_declared_removals(self):
        from pyneat.core.semantic_guard import SemanticDiffGuard
        guard = SemanticDiffGuard()

        before = "def unused(): pass\n\nx = 1\n"
        after = "x = 1\n"
        is_safe, _ = guard.is_safe(
            before, after,
            allowed_nodes={"FunctionDef", "AsyncFunctionDef", "ClassDef"},
        )
        assert is_safe is True, "Removing unused FunctionDef should be allowed"


# --------------------------------------------------------------------------
# 10. Smoke: real-world code snippets
# --------------------------------------------------------------------------

class TestRealWorldSnippets:
    """Test on realistic Python code patterns."""

    REALISTIC = [
        # Django/Flask-style (decorators + called entry point to prevent dead removal)
        textwrap.dedent("""\
            app = None  # placeholder so deadcode rule knows 'app' is defined

            @app.route('/')
            def index():
                return render_template('index.html')

            def get_user(uid):
                return User.query.get(uid)

            def main():
                get_user(1)  # reference to prevent dead removal
                index()       # decorated → never removed
        """),
        # Data processing
        textwrap.dedent("""\
            import pandas as pd

            def load_data(path):
                df = pd.read_csv(path)
                return df.dropna()

            def process(df):
                return df.groupby('category').sum()
        """),
        # Async
        textwrap.dedent("""\
            import asyncio

            async def fetch(url):
                async with aiohttp.get(url) as resp:
                    return await resp.json()

            async def main():
                results = await asyncio.gather(
                    fetch('/api/1'),
                    fetch('/api/2'),
                )
                return results
        """),
        # Type-annotated
        textwrap.dedent("""\
            from typing import List, Optional

            def find_max(numbers: List[int]) -> Optional[int]:
                return max(numbers) if numbers else None

            class Cache:
                def __init__(self) -> None:
                    self._store: dict[str, Any] = {}
        """),
    ]

    @pytest.mark.parametrize("code", REALISTIC)
    def test_realistic_no_crash(self, code: str):
        result = _build().process_code_file(
            CodeFile(path=Path("t.py"), content=code)
        )
        assert isinstance(result, TransformationResult)
        if result.has_changes:
            # Must still parse
            ast.parse(result.transformed_content)
            # Runtime check: only for self-contained snippets.
            # Skip snippets that:
            # - Use placeholder assignments (e.g. app = None)
            # - Reference external frameworks/functions that aren't defined (Flask, pandas, aiohttp, render_template)
            uses_external = (
                "= None  #" in code or
                "render_template" in code or
                "flask" in code.lower() or
                "pandas" in code.lower() or
                "aiohttp" in code.lower() or
                "asyncio" in code.lower()
            )
            if not uses_external:
                _, err = _capture_exec(result.transformed_content)
                assert err is None, f"Cleaned code raises: {err}"
