"""Rule for detecting performance issues using AST analysis.

Copyright (c) 2026 PyNEAT Authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, contact: license@pyneat.dev
"""

import ast
from typing import List
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class PerformanceRule(Rule):
    """Detects performance anti-patterns using AST analysis.

    Detects:
    - List concatenation in loops -> use list comprehension
    - Nested loops iterating over the same collection
    - Repeated computation of expensive expressions in loops
    - while True without break
    """

    KNOWN_SAFE_METHODS: frozenset = frozenset({
        # Collection mutating methods
        'append', 'extend', 'add', 'update', 'pop', 'popitem',
        'clear', 'remove', 'discard', 'insert', 'reverse', 'sort',
        # Dict/view methods
        'get', 'setdefault', 'copy', 'keys', 'values', 'items',
        # String methods
        'lower', 'upper', 'strip', 'lstrip', 'rstrip', 'split',
        'rsplit', 'splitlines', 'join', 'replace', 'find', 'rfind',
        'startswith', 'endswith', 'encode', 'decode', 'format',
        'zfill', 'center', 'ljust', 'rjust', 'capitalize', 'swapcase',
        'title', 'casefold', 'expandtabs', 'partition', 'rpartition',
        # File/IO methods
        'read', 'readline', 'readlines', 'write', 'flush', 'seek',
        'tell', 'truncate', 'fileno', 'isatty',
        # Collection methods
        'copy', 'deepcopy', 'count', 'index',
        'difference', 'intersection', 'union', 'issubset', 'issuperset',
        'symmetric_difference',
        # Safe type conversion
        'str', 'int', 'float', 'bool', 'list', 'dict', 'set', 'tuple',
        'bytes', 'ascii', 'repr', 'hash', 'abs', 'round', 'min', 'max',
        'sum', 'all', 'any', 'sorted', 'reversed', 'enumerate', 'filter', 'map',
        # Other safe
        'isalpha', 'isdigit', 'isalnum', 'isspace', 'isupper', 'islower',
        # Path methods that are cheap (property-like, no I/O)
        'name', 'stem', 'suffix', 'parent', 'parts', 'anchor',
        'drive', 'root', 'parents',
    })

    # Methods that may involve I/O or computation but are commonly used
    # on loop variables and are not performance issues when each item
    # is processed independently. These are excluded to avoid false
    # positives.
    KNOWN_CONTEXT_SAFE_METHODS: frozenset = frozenset({
        # Path methods (I/O bound per-item; each call processes one item)
        'relative_to', 'resolve', 'absolute', 'realpath', 'normpath',
        'exists', 'is_file', 'is_dir', 'is_symlink', 'is_absolute',
        'stat', 'lstat',
        'open', 'read_bytes', 'read_text', 'write_bytes', 'write_text',
        'mkdir', 'makedirs', 'touch', 'unlink', 'remove', 'rmdir',
        'rename', 'replace', 'copy2', 'copy', 'link',
        'samefile', 'sameopenfile',
        # Path utilities — cheap string manipulation, not I/O
        'join', 'basename', 'dirname', 'split', 'splitext',
        'abspath', 'exists',
        # glob returns a new iterator each call — per-item processing
        'glob', 'rglob', 'iglob', 'iterdir',
    })

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)

    @property
    def description(self) -> str:
        return "Detects performance issues and inefficient code"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes)

            try:
                # Use cached AST if available (RuleEngine pre-parses)
                if hasattr(code_file, 'ast_tree') and code_file.ast_tree is not None:
                    tree = code_file.ast_tree
                else:
                    tree = ast.parse(content)
            except SyntaxError:
                return self._create_result(code_file, content, changes)

            # Set parent pointers so _get_loop_invariant_names can walk the tree
            for node in ast.walk(tree):
                for child in ast.iter_child_nodes(node):
                    child.parent = node  # type: ignore[attr-defined]

            if self._has_list_concat_in_loop(tree):
                changes.append("INEFFICIENT LOOP: Use list comprehension or extend()")

            nested = self._find_nested_same_iterable(tree)
            for item in nested:
                changes.append(f"INEFFICIENT: Nested loops over same iterable in {item}")

            if self._has_while_true_without_break(tree):
                changes.append("POTENTIAL INFINITE LOOP: Missing break condition")

            repeated = self._find_repeated_method_calls(tree)
            for item in repeated:
                # item is already "base.method" like "x.relative_to"
                method_part = item.split(".", 1)[-1]
                changes.append(
                    f"PERFORMANCE: Repeated {item}() call in loop - call once and reuse"
                )

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"Performance check failed: {str(e)}")

    def _has_list_concat_in_loop(self, tree: ast.AST) -> bool:
        """Detect patterns like `mylist = mylist + [x]` or `mylist += [x]` inside loops."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                for child in ast.walk(node):
                    if isinstance(child, ast.AugAssign):
                        if isinstance(child.op, ast.Add):
                            return True
                    if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Add):
                        if isinstance(child.left, ast.Name):
                            return True
        return False

    def _find_nested_same_iterable(self, tree: ast.AST) -> List[str]:
        """Find nested for loops that iterate over the same collection."""
        results: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.AsyncFor)):
                self._check_nested_same(node, results)
        return results

    def _check_nested_same(self, outer_node: ast.For, results: List[str], depth: int = 0) -> None:
        """Recursively check for nested loops over the same iterable."""
        outer_source = self._get_iter_source(outer_node.iter)
        if outer_source is None:
            return

        for child in ast.walk(outer_node):
            if child is outer_node:
                continue
            if isinstance(child, (ast.For, ast.AsyncFor)):
                inner_source = self._get_iter_source(child.iter)
                if inner_source == outer_source and isinstance(inner_source, ast.Name):
                    results.append(f"{inner_source.id}")

    def _get_iter_source(self, node: ast.AST) -> ast.AST | None:
        """Get the source of a for loop iterator."""
        if isinstance(node, ast.Name):
            return node
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ('range', 'enumerate', 'zip'):
                return node
        return None

    def _has_while_true_without_break(self, tree: ast.AST) -> bool:
        """Check for `while True:` or `while 1:` without any break statement."""
        for node in ast.walk(tree):
            if isinstance(node, ast.While):
                test = node.test
                is_forever = (
                    isinstance(test, ast.Constant) and test.value in (True, 1)
                )
                if is_forever:
                    has_break = any(
                        isinstance(n, ast.Break)
                        for n in ast.walk(node)
                    )
                    if not has_break:
                        return True
        return False

    def _find_repeated_method_calls(self, tree: ast.AST) -> List[str]:
        """Find methods called repeatedly inside loops that are NOT in safe list.

        Key fix: tracks (base_object, method_name) pairs instead of just method names.
        Also skips:
        - Methods on loop iteration variables (expected per-item access)
        - Methods on objects assigned once before the loop (loop-invariant)
        - Methods in the KNOWN_SAFE_METHODS and KNOWN_CONTEXT_SAFE_METHODS lists
        """
        results: List[str] = []
        seen_in_loop: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                loop_methods: set[str] = set()
                # Identify the loop variable(s) so we can skip calls on them
                loop_vars = self._get_loop_variables(node)
                # Identify loop-invariant assignments: Name nodes assigned before
                # the loop body that are still in scope
                loop_invariants = self._get_loop_invariant_names(node)

                for child in self._walk_no_nested(node, set()):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                        name = child.func.attr
                        if name in self.KNOWN_SAFE_METHODS:
                            continue
                        if name in self.KNOWN_CONTEXT_SAFE_METHODS:
                            continue

                        base = child.func.value
                        base_desc = self._describe_base(base)
                        pair_key = f"{base_desc}.{name}"

                        # Skip if base is a loop iteration variable
                        if isinstance(base, ast.Name) and base.id in loop_vars:
                            continue
                        # Skip if base is a loop-invariant name (assigned before loop)
                        if isinstance(base, ast.Name) and base.id in loop_invariants:
                            continue

                        loop_methods.add(pair_key)

                if loop_methods:
                    for pair in sorted(loop_methods):
                        if pair not in seen_in_loop:
                            seen_in_loop.add(pair)

        if len(seen_in_loop) <= 5:
            results.extend(sorted(seen_in_loop))
        return results

    def _get_loop_variables(self, loop_node: ast.AST) -> set:
        """Extract variable names from a for-loop target."""
        vars = set()
        if isinstance(loop_node, ast.For):
            target = loop_node.target
            if isinstance(target, ast.Name):
                vars.add(target.id)
            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        vars.add(elt.id)
        return vars

    def _get_loop_invariant_names(self, loop_node: ast.AST) -> set:
        """Get names assigned once *before* the loop body starts.

        An assignment is loop-invariant if it appears as a direct child
        statement of the loop node's parent, *before* the loop itself,
        and the name is a simple `Name` node (not attribute/index access).
        """
        parent = getattr(loop_node, 'parent', None)
        if parent is None:
            return set()

        invariants: set = set()
        if isinstance(parent, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = parent.body
        elif isinstance(parent, (ast.For, ast.While)):
            # Check the else-branch of the loop — assignments there are also
            # before the loop body runs
            body = parent.body
        else:
            return set()

        # Linear scan through parent body until we hit the loop itself
        for stmt in body:
            if stmt is loop_node:
                break
            # Simple name assignments: `x = ...`
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        invariants.add(target.id)
            # Named expression (walrus): `x := ...`
            elif isinstance(stmt, ast.NamedExpr):
                if isinstance(stmt.target, ast.Name):
                    invariants.add(stmt.target.id)
            # Augmented assignment: `x += ...`
            elif isinstance(stmt, ast.AugAssign):
                if isinstance(stmt.target, ast.Name):
                    invariants.add(stmt.target.id)
            # AnnAssign: `x: T = ...`
            elif isinstance(stmt, ast.AnnAssign):
                if isinstance(stmt.target, ast.Name):
                    invariants.add(stmt.target.id)

        return invariants

    def _describe_base(self, node: ast.AST) -> str:
        """Return a human-readable string describing the base of a method call.

        Examples:
            ast.Name(id='x')          -> "x"
            ast.Attribute(value=..., attr='data') -> "xxx.data"
            ast.Subscript(...)        -> "[...]"
            ast.Call(...)             -> "(...)"
            _                         -> "?"
        """
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._describe_base(node.value)}.{node.attr}"
        elif isinstance(node, ast.Subscript):
            return "[...]"
        elif isinstance(node, ast.Call):
            return "(call)"
        else:
            return "?"

    def _walk_no_nested(self, node: ast.AST, visited: set) -> list:
        """Walk AST but stop descent into nested functions/lambdas.

        Uses visited set to prevent infinite recursion. Returns flat list of nodes.
        """
        result = []
        for child in ast.iter_child_nodes(node):
            node_id = id(child)
            if node_id in visited:
                continue
            visited.add(node_id)

            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            # Skip loop-control parts that are not the body:
            # - target: the loop variable (`f` in `for f in ...`)
            # - iter:   the iterable expression (`base.rglob("*")` in `for f in base.rglob("*")`)
            # Only walk the body, else clause, and type comment.
            if isinstance(node, ast.For) and child is node.target:
                continue
            if isinstance(node, (ast.For, ast.AsyncFor)) and child is node.iter:
                continue
            result.append(child)
            result.extend(self._walk_no_nested(child, visited))
        return result