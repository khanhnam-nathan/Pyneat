"""Rule for removing genuinely unused imports using AST analysis + partial import splitting.

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
import re
from typing import List, Set, Tuple
import libcst as cst

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class UnusedImportRule(Rule):
    """Removes import statements whose names are never used in the code.

    Uses AST to track which names are imported and which are actually
    referenced, removing only imports with no side effects and no usage.

    Also splits multi-name imports when some names are used and some aren't.
    E.g., "import os, sys" where only os is used → converts to "import os".

    Skips imports marked with # pyneat: protected and imports in __all__.
    """

    # Modules commonly used for side-effects — these individual names are protected
    SIDE_EFFECT_MODULES: frozenset = frozenset({
        'os', 'sys', 'builtins', '__future__',
    })

    # Modules commonly re-exported in __init__.py files
    COMMON_REEXPORT_PREFIXES: frozenset = frozenset({
        '.',  # relative imports in __init__.py
    })

    @property
    def description(self) -> str:
        return "Removes unused import statements using AST analysis"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes)

            # Use cached AST if available (RuleEngine pre-parses)
            ast_tree = None
            if hasattr(code_file, 'ast_tree') and code_file.ast_tree is not None:
                ast_tree = code_file.ast_tree

            new_content, removed_names = self._remove_unused_imports(content, ast_tree)
            for name in removed_names:
                changes.append(f"Removed unused import: {name}")

            return self._create_result(code_file, new_content, changes)

        except SyntaxError:
            # File has syntax errors — skip transformation
            return self._create_result(code_file, code_file.content, [])

        except Exception as e:
            return self._create_error_result(
                code_file, f"UnusedImportRule failed: {str(e)}"
            )

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------

    def _remove_unused_imports(self, content: str, ast_tree=None) -> Tuple[str, List[str]]:
        """Return (new_content, removed_import_names)."""
        try:
            tree = ast.parse(content) if ast_tree is None else ast_tree
        except SyntaxError:
            return content, []

        imports_info: List[dict] = []

        all_names: Set[str] = self._extract_all_names(tree)
        protected_lines: Set[int] = self._find_protected_lines(content)

        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names, side_effect, module = self._extract_import_info(node)
                if names:
                    imports_info.append({
                        'names': names,
                        'first_lineno': node.lineno,
                        'last_lineno': node.end_lineno or node.lineno,
                        'side_effect': side_effect,
                        'module': module,
                        'node': node,
                    })

        if not imports_info:
            return content, []

        used_names: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name):
                    used_names.add(node.value.id)
            elif isinstance(node, ast.arg):
                used_names.add(node.arg)

        lines = content.split('\n')
        removed_names: List[str] = []
        removed_import_indices: List[int] = []
        partial_replacements: List[dict] = []

        for imp in imports_info:
            if imp['side_effect']:
                continue

            # __future__ imports must NEVER be removed - they are compiler directives
            if self._is_future_import(imp['node']):
                continue

            imported_names = set(imp['names'])

            is_protected = any(
                ln in protected_lines
                for ln in range(imp['first_lineno'] - 1, imp['last_lineno'])
            )
            if is_protected:
                continue

            protected_by_all = imported_names & all_names
            if all_names and protected_by_all:
                continue

            unused = imported_names - used_names
            used_from_line = imported_names - unused

            if unused == imported_names:
                for ln in range(imp['first_lineno'] - 1, imp['last_lineno']):
                    if 0 <= ln < len(lines):
                        removed_import_indices.append(ln)
                        lines[ln] = ''
                removed_names.append(', '.join(sorted(imp['names'])))
            elif unused and used_from_line:
                lines[imp['first_lineno'] - 1] = self._build_replacement_line(
                    imp['node'], used_from_line
                )
                partial_replacements.append({
                    'line_idx': imp['first_lineno'] - 1,
                    'used_names': used_from_line,
                    'node': imp['node'],
                })

        for pr in partial_replacements:
            lines[pr['line_idx']] = self._build_replacement_line(pr['node'], used_names)

        if not removed_import_indices and not partial_replacements:
            return content, []

        removed_set = set(removed_import_indices)
        cleaned: List[str] = []
        first_non_import_seen = False
        for i, line in enumerate(lines):
            if line == '' and i in removed_set:
                continue

            is_blank = line.strip() == ''
            if is_blank:
                if not first_non_import_seen:
                    if not cleaned or cleaned[-1].strip() != '':
                        cleaned.append(line)
                else:
                    cleaned.append(line)
            else:
                cleaned.append(line)
                stripped = line.strip()
                if stripped and not stripped.startswith('#') and \
                   not stripped.startswith('import ') and not stripped.startswith('from '):
                    first_non_import_seen = True

        new_content = '\n'.join(cleaned).strip('\n') + '\n'

        return new_content, removed_names

    def _build_replacement_line(self, node, used_names: Set[str]) -> str:
        """Build a replacement import line for partially used imports."""
        sorted_names = sorted(used_names, key=lambda n: n.split('.')[0])

        if isinstance(node, ast.Import):
            parts = []
            for alias in node.names:
                name = alias.name
                asname = alias.asname if alias.asname else None
                if name in used_names or (name.split('.')[0] if '.' in name else name) in used_names:
                    if asname:
                        parts.append(f"{name} as {asname}")
                    else:
                        parts.append(name)
            return f"import {', '.join(parts)}"

        elif isinstance(node, ast.ImportFrom):
            # Python 3.14: node.module is a str, not an ast.Name
            module = getattr(node, 'module', '') or ''
            if isinstance(module, str):
                module_str = module
            elif isinstance(module, ast.Name):
                module_str = module.name
            elif isinstance(module, ast.Attribute):
                parts = []
                current = module
                while isinstance(current, ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    parts.append(current.name)
                module_str = '.'.join(reversed(parts))
            else:
                module_str = str(module)

            rel_level = getattr(node, 'level', 0) or 0
            rel_dots = ''.join('.' * rel_level) if rel_level else ''
            parts = []
            for alias in node.names:
                name = alias.name
                asname = alias.asname if alias.asname else None
                if name in used_names:
                    if asname:
                        parts.append(f"{name} as {asname}")
                    else:
                        parts.append(name)
            return f"from {rel_dots}{module_str} import {', '.join(parts)}"

        return ""

    def _extract_all_names(self, tree: ast.AST) -> Set[str]:
        """Extract names from __all__ = (...) or __all__ = [...]."""
        all_names: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == '__all__':
                        val = self._extract_all_value(node.value)
                        all_names.update(val)
                        break
        return all_names

    def _extract_all_value(self, node: ast.AST) -> List[str]:
        """Extract names from __all__ = (...) or __all__ = [...]."""
        if isinstance(node, (ast.List, ast.Tuple)):
            result = []
            for elt in node.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    result.append(elt.value)
                elif isinstance(elt, ast.Str):  # Python 3.7 compat
                    result.append(elt.s)
            return result
        return []

    def _find_protected_lines(self, content: str) -> Set[int]:
        """Find lines with # pyneat: protected markers."""
        protected: Set[int] = set()
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if '# pyneat: protected' in line:
                protected.add(i)
        return protected

    def _extract_import_info(self, node):
        """Extract (names, side_effect, module) from an import node."""
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
            side_effect = self._is_side_effect_module(names)
            return names, side_effect, None
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                return [], False, None
            # Return the alias names (asname if present, else name)
            names = [alias.asname if alias.asname else alias.name for alias in node.names]
            return names, False, node.module
        return [], False, None

    def _is_side_effect_module(self, names: List[str]) -> bool:
        """Return True if all imported names are known side-effect-only imports.

        If any name is a real module that has non-side-effect uses (e.g., os.path,
        json.loads), return False so it can be analyzed properly.
        """
        if not names:
            return False
        return all(name.split('.')[0] in self.SIDE_EFFECT_MODULES for name in names)

    def _is_future_import(self, node) -> bool:
        """Return True if this is a __future__ import, which must never be removed."""
        if isinstance(node, ast.ImportFrom):
            module = getattr(node, 'module', None)
            # In Python 3.14+, module is a string
            if isinstance(module, str) and module == '__future__':
                return True
            # In older Python, module could be None for relative imports
            # and the name would be imported via names list
            if module is None:
                # Check if any imported name starts with __future__ marker
                for alias in getattr(node, 'names', []):
                    name = getattr(alias, 'name', None)
                    if name and name.startswith('_'):
                        # __future__ features are the only underscore-prefixed
                        # imports that are allowed at module level
                        if name in frozenset({
                            'annotations', 'absolute_import', 'division',
                            'print_function', 'unicode_literals', 'generator_stop',
                            'coerce_class', 'generators', 'nested_scopes',
                            'braces', 'with_statement',
                        }):
                            return True
        return False
