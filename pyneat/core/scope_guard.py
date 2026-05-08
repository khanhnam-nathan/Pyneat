"""Scope guard — tracks variable/function lifecycle using LibCST ScopeProvider.

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

Prevents dead-code removal rules from deleting items that are still referenced
later in the file (e.g. a variable used after its apparent "definition" point
due to being assigned inside a conditional).
"""

from __future__ import annotations

import logging
from typing import Dict, List, Set, Optional, Tuple

logger = logging.getLogger(__name__)


try:
    import libcst as cst
    from libcst.metadata import MetadataWrapper, ScopeProvider
    _LIBCST_AVAILABLE = True
except ImportError:
    _LIBCST_AVAILABLE = False
    MetadataWrapper = None  # type: ignore[assignment, misc]
    ScopeProvider = None   # type: ignore[assignment, misc]


class ScopeGuard:
    """Checks whether a code item (function/class/variable) is safe to remove.

    Uses LibCST's ``ScopeProvider`` to resolve which names are read/written
    within each scope. An item is considered "in use" if any later line
    reads its name.
    """

    def __init__(self):
        self._wrapper_cache: Dict[str, MetadataWrapper] = {}

    def check_dead_code_safe(
        self,
        code_content: str,
        dead_items: List[dict],
    ) -> Tuple[List[dict], List[str]]:
        """Filter dead_items to keep only those that are truly dead.

        Args:
            code_content: Full source code of the file.
            dead_items: List of dicts with keys ``name``, ``start``, ``end``
                (1-indexed line numbers) representing items considered dead.

        Returns:
            A 2-tuple of (safe_items, warnings).
            ``safe_items`` are items confirmed dead (no reads after definition).
            ``warnings`` describe why an item was kept.
        """
        if not dead_items or not _LIBCST_AVAILABLE:
            return list(dead_items), []

        warnings: List[str] = []
        safe_items: List[dict] = []

        try:
            wrapper = self._get_wrapper(code_content)
            scope_map = wrapper.resolve(ScopeProvider)
        except Exception as e:
            logger.warning("ScopeGuard: could not resolve scopes: %s", e)
            return list(dead_items), []

        # Collect all accessed (read) names in all scopes
        all_reads: Set[str] = set()
        for node, scope in scope_map.items():
            for access in scope.accesses:
                # access.node is a CST Name node; get its .value
                name_node = getattr(access, "node", None)
                if name_node is not None:
                    name_val = getattr(name_node, "value", None)
                    if isinstance(name_val, str) and name_val:
                        all_reads.add(name_val)

        for item in dead_items:
            name = item.get("name", "")
            # Keep if the name is read anywhere (function called, variable used)
            if name in all_reads:
                warnings.append(
                    f"Keeping '{name}': referenced in scope (detected by ScopeGuard)"
                )
            else:
                safe_items.append(item)

        return safe_items, warnings

    def check_variable_safe(
        self,
        code_content: str,
        var_name: str,
        definition_line: int,
    ) -> Tuple[bool, str]:
        """Check if a variable at ``definition_line`` is read anywhere after it.

        Args:
            code_content: Full source code.
            var_name: Name of the variable.
            definition_line: 1-indexed line where the variable is defined.

        Returns:
            A 2-tuple of (is_safe, reason).
        """
        if not _LIBCST_AVAILABLE:
            return True, "libcst not available — skipping scope check"

        try:
            wrapper = self._get_wrapper(code_content)
            scope_map = wrapper.resolve(ScopeProvider)
        except Exception as e:
            return True, f"scope resolution failed: {e}"

        for node, scope in scope_map.items():
            for access in scope.accesses:
                name_node = getattr(access, "node", None)
                if name_node is not None:
                    name_val = getattr(name_node, "value", None)
                    if isinstance(name_val, str) and name_val == var_name:
                        return False, f"'{var_name}' is read in scope {type(scope).__name__}"

        return True, f"'{var_name}' is not read after line {definition_line}"

    def _get_wrapper(self, code_content: str) -> MetadataWrapper:
        """Get or create a cached MetadataWrapper for the content."""
        content_hash = str(hash(code_content))
        if content_hash not in self._wrapper_cache:
            cst_tree = cst.parse_module(code_content)
            self._wrapper_cache[content_hash] = MetadataWrapper(cst_tree)
        return self._wrapper_cache[content_hash]

    def clear_cache(self) -> None:
        """Clear the wrapper cache."""
        self._wrapper_cache.clear()
