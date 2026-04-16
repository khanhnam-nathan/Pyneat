"""Semantic diffing guard — detects unintended semantic changes in code transformations.

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

For commercial licensing, contact: khanhnam.copywriting@gmail.com

Compares AST structure (ignoring position metadata) before and after a rule runs.
If the executable semantics drift in ways the rule didn't explicitly declare as
"allowed", the transformation is flagged and the engine can revert it.
"""

from __future__ import annotations

import ast
import logging
from typing import Optional, Set, List, Tuple

logger = logging.getLogger(__name__)


# Nodes whose presence changes the runtime semantics — removing them is dangerous
_CRITICAL_NODE_TYPES: Set[str] = {
    "Assign",           # variable assignment
    "AnnAssign",        # annotated assignment
    "AugAssign",        # += -= etc.
    "NamedExpr",        # walrus operator := (Python 3.8+)
    "FunctionDef",      # function definition
    "AsyncFunctionDef", # async function
    "ClassDef",         # class definition
    "Return",           # return statement (can break caller logic)
    "Yield",            # yield (generator)
    "YieldFrom",        # yield from
    "Raise",            # raise (control flow)
    "Assert",           # assertion (can change behavior when -O)
    "Import",           # import statement
    "ImportFrom",       # from ... import
    "Global",           # global declaration
    "Nonlocal",         # nonlocal declaration
    "Try",              # try/except
    "With",             # with statement
    "AsyncWith",        # async with
    "Delete",           # del statement
    "If",               # if/elif/else (structural)
    "For",              # for loop
    "AsyncFor",         # async for
    "While",            # while loop
    "Match",            # match/case (Python 3.10+)
    "Break",            # break
    "Continue",         # continue
}


class SemanticDiffGuard:
    """Compares two AST trees to detect unintended semantic changes.

    The guard strips position metadata (lineno, col_offset, end_lineno,
    end_col_offset) before comparison so that minor formatting changes
    do not trigger false positives.

    Rules can declare which node types they are *allowed* to change via
    ``allowed_semantic_nodes`` in their config. For example, a dead-code
    removal rule that is allowed to delete functions would set
    ``allowed_semantic_nodes = {"FunctionDef", "AsyncFunctionDef"}``.
    """

    def __init__(self):
        self._last_diff: Optional[dict] = None

    def is_safe(
        self,
        before: str,
        after: str,
        allowed_nodes: Optional[Set[str]] = None,
    ) -> Tuple[bool, List[str]]:
        """Determine whether ``after`` is semantically equivalent to ``before``.

        Args:
            before: Original source code.
            after: Transformed source code.
            allowed_nodes: Set of AST node type names that the rule is
                explicitly allowed to change.

        Returns:
            A 2-tuple of (is_safe: bool, diff_messages: List[str]).
            ``diff_messages`` is empty when ``is_safe`` is True.
        """
        if before == after:
            return True, []

        try:
            tree_before = ast.parse(before)
            tree_after = ast.parse(after)
        except SyntaxError as e:
            logger.warning("SemanticDiffGuard: could not parse code: %s", e)
            return False, [f"Parse error: {e}"]

        self._strip_metadata(tree_before)
        self._strip_metadata(tree_after)

        diff = self._compute_diff(tree_before, tree_after)
        allowed = allowed_nodes or set()

        # Filter out allowed node changes
        real_diff = [d for d in diff if d["node_type"] not in allowed]

        if not real_diff:
            return True, []

        messages = [
            f"{d['action']} {d['node_type']} (line {d.get('lineno', '?')}): {d.get('name', '')}"
            for d in real_diff
        ]

        self._last_diff = {
            "before": before,
            "after": after,
            "diffs": real_diff,
        }

        logger.debug(
            "SemanticDiffGuard: detected %d unsafe changes: %s",
            len(real_diff),
            messages,
        )

        return False, messages

    def _compute_diff(
        self,
        tree_before: ast.AST,
        tree_after: ast.AST,
    ) -> List[dict]:
        """Recursively compute structural differences between two AST trees."""
        diffs: List[dict] = []

        # Build node inventories by type and name
        nodes_before = self._inventory(tree_before)
        nodes_after = self._inventory(tree_after)

        for node_type, name_map in nodes_before.items():
            if node_type not in nodes_after:
                for name, lineno in name_map.items():
                    diffs.append({
                        "action": "removed",
                        "node_type": node_type,
                        "name": name,
                        "lineno": lineno,
                    })
            else:
                for name, lineno in name_map.items():
                    if name not in nodes_after[node_type]:
                        diffs.append({
                            "action": "removed",
                            "node_type": node_type,
                            "name": name,
                            "lineno": lineno,
                        })

        for node_type, name_map in nodes_after.items():
            if node_type not in nodes_before:
                for name, lineno in name_map.items():
                    diffs.append({
                        "action": "added",
                        "node_type": node_type,
                        "name": name,
                        "lineno": lineno,
                    })
            else:
                for name, lineno in name_map.items():
                    if name not in nodes_before[node_type]:
                        diffs.append({
                            "action": "added",
                            "node_type": node_type,
                            "name": name,
                            "lineno": lineno,
                        })

        # Track structural changes (top-level statement count)
        count_before = sum(len(m) for m in nodes_before.values())
        count_after = sum(len(m) for m in nodes_after.values())
        if count_after > count_before:
            diffs.append({
                "action": "added",
                "node_type": "Statement",
                "name": f"+{count_after - count_before} statement(s)",
                "lineno": 0,
            })

        return diffs

    def _inventory(self, tree: ast.AST) -> dict[str, dict[str, int]]:
        """Build a hierarchical inventory of named nodes by type."""
        inventory: dict[str, dict[str, int]] = {}

        for node in ast.walk(tree):
            node_type = type(node).__name__

            if node_type in _CRITICAL_NODE_TYPES:
                # Extract name if the node has one
                name: Optional[str] = None
                lineno: int = getattr(node, "lineno", 0) or 0

                if node_type in ("FunctionDef", "AsyncFunctionDef", "ClassDef"):
                    name = getattr(node, "name", None) or ""
                elif node_type == "Assign":
                    # Try to get the target name(s)
                    for target in getattr(node, "targets", []):
                        if isinstance(target, ast.Name):
                            name = getattr(target, "id", None) or ""
                            break
                elif node_type == "AnnAssign":
                    target = getattr(node, "target", None)
                    if isinstance(target, ast.Name):
                        name = getattr(target, "id", None) or ""

                key = name or f"<anon:{node_type}>"
                inventory.setdefault(node_type, {})[key] = lineno

        return inventory

    @staticmethod
    def _strip_metadata(tree: ast.AST) -> None:
        """Remove position metadata from all nodes in the tree."""
        for node in ast.walk(tree):
            for attr in ("lineno", "col_offset", "end_lineno", "end_col_offset", "ctx"):
                if hasattr(node, attr):
                    try:
                        object.__setattr__(node, attr, None)
                    except (AttributeError, TypeError):
                        pass

    @property
    def last_diff(self) -> Optional[dict]:
        """The last diff result, for debugging."""
        return self._last_diff
