"""Rule to prevent removing critical imports from __init__.py files.

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

In Python's import system, an import in __init__.py can be "used" for two reasons:
1. Direct usage in the module code
2. Re-exporting as part of the public API (listed in __all__)

This rule ensures imports that support __all__ re-export are NOT removed,
since removing them would break the public API of the package.

Bug fixed: chatterbot_init.py had `from .chatterbot import ChatBot` removed
because ChatBot wasn't used inside the file - but it WAS needed for
`__all__ = ('ChatBot',)`, making it a public API re-export.
"""
import ast
import re
from typing import List, Set, Tuple

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class InitFileProtectionRule(Rule):
    """Prevents removing critical imports from __init__.py files.

    Detects when a file is an __init__.py and treats imports that
    contribute to __all__ as "used", preventing their removal.

    This runs BEFORE UnusedImportRule and marks protected imports
    by wrapping them in a special comment that UnusedImportRule
    will respect.
    """

    @property
    def description(self) -> str:
        return "Protects __init__.py re-export imports from being removed"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes)

            # Only applies to __init__.py files
            path = str(code_file.path or "")
            is_init = "__init__" in path or self._looks_like_init(content)

            if not is_init:
                return self._create_result(code_file, content, changes)

            # Use cached AST if available (RuleEngine pre-parses)
            ast_tree = None
            if hasattr(code_file, 'ast_tree') and code_file.ast_tree is not None:
                ast_tree = code_file.ast_tree

            # Parse and analyze
            new_content, protected = self._protect_init_imports(content, ast_tree)

            for name in protected:
                changes.append(f"Protected __init__ re-export: {name}")

            if protected:
                changes.append(
                    f"Protected {len(protected)} import(s) critical for public API"
                )

            return self._create_result(code_file, new_content, changes)

        except SyntaxError:
            return self._create_result(code_file, code_file.content, [])
        except Exception as e:
            return self._create_error_result(
                code_file, f"InitFileProtectionRule failed: {str(e)}"
            )

    def _looks_like_init(self, content: str) -> bool:
        """Heuristic: if file is very short and has __all__, likely __init__."""
        lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
        if len(lines) <= 20 and '__all__' in content:
            return True
        return False

    def _protect_init_imports(self, content: str, ast_tree=None) -> Tuple[str, List[str]]:
        """Add protection markers to __all__-related imports."""
        try:
            tree = ast.parse(content) if ast_tree is None else ast_tree
        except SyntaxError:
            return content, []

        # Step 1: Extract __all__ names
        all_names: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == '__all__':
                        val = self._extract_all_value(node.value)
                        all_names.update(val)
                        break

        if not all_names:
            return content, []

        # Step 2: Find imports that provide names in __all__
        protected_imports: List[dict] = []  # {first_line, last_line, names}

        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                info = self._extract_import_info(node)
                if not info:
                    continue

                imported_names = info['names']
                matching = imported_names & all_names
                if matching:
                    protected_imports.append({
                        'first_line': node.lineno,
                        'last_line': node.end_lineno or node.lineno,
                        'names': list(matching),
                    })

        if not protected_imports:
            return content, []

        # Step 3: Add # pyneat: protected comment to these imports
        lines = content.split('\n')
        protected_names: List[str] = []
        protected_indices: Set[int] = set()

        for imp in protected_imports:
            for ln in range(imp['first_line'] - 1, imp['last_line']):
                if 0 <= ln < len(lines):
                    protected_indices.add(ln)

        # Add protection markers (from bottom to top to preserve line numbers)
        for ln in sorted(protected_indices, reverse=True):
            stripped = lines[ln].strip()
            if stripped and not stripped.startswith('# pyneat: protected'):
                lines[ln] = '# pyneat: protected\n' + lines[ln]
                # Also protect the next line if it's a continuation (e.g. backslash)
                if ln + 1 < len(lines):
                    next_stripped = lines[ln + 1].strip()
                    if next_stripped and not next_stripped.startswith('#'):
                        if not (next_stripped.startswith('import ') or
                                next_stripped.startswith('from ') or
                                next_stripped.startswith('#')):
                            lines[ln + 1] = '# pyneat: protected\n' + lines[ln + 1]

        new_content = '\n'.join(lines)
        for imp in protected_imports:
            protected_names.extend(imp['names'])

        return new_content, protected_names

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

    def _extract_import_info(self, node) -> dict:
        """Extract (names, module) from an import node."""
        if isinstance(node, ast.Import):
            names = [alias.asname or alias.name for alias in node.names]
            return {'names': set(names), 'module': None}
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                return None
            names = [alias.asname or alias.name for alias in node.names]
            return {'names': set(names), 'module': node.module}
        return None


class InitFileProtectionRuleV2(Rule):
    """V2: Inline approach - directly skips import removal in __init__.py.

    This version doesn't add markers but instead patches UnusedImportRule
    to check __all__ context directly. This is cleaner but requires
    UnusedImportRule to be modified to call back.

    NOTE: This is kept for reference. V1 (InitFileProtectionRule) is the
    recommended approach as it works without modifying UnusedImportRule.
    """

    @property
    def description(self) -> str:
        return "[V2] Protects __init__.py re-export imports (inline approach)"

    @property
    def name(self) -> str:
        return "init_file_protection_v2"

    # The inline approach: modify UnusedImportRule to call this helper
    # See: UnusedImportRule._is_init_re_export()
    pass
