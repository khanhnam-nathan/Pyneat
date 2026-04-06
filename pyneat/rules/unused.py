"""Rule for removing genuinely unused imports using AST analysis."""

import ast
from typing import List, Set, Tuple

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class UnusedImportRule(Rule):
    """Removes import statements whose names are never used in the code.

    Uses AST to track which names are imported and which are actually
    referenced, removing only imports with no side effects and no usage.

    Skips imports marked with # pyneat: protected (added by InitFileProtectionRule)
    and imports that contribute to __all__ in __init__.py files.
    """

    # Modules commonly used for side-effects — never remove these
    SIDE_EFFECT_MODULES: frozenset = frozenset({
        'os', 'sys', 'builtins', '__future__',
    })

    # Modules commonly re-exported in __init__.py files
    # These are package names where removing the import would break the public API
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

            new_content, removed_names = self._remove_unused_imports(content)
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

    def _remove_unused_imports(self, content: str) -> Tuple[str, List[str]]:
        """Return (new_content, removed_import_names)."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return content, []

        # Collect top-level import statement line ranges
        imports_info: List[dict] = []  # {names, first_lineno, last_lineno, side_effect, is_top}

        # Extract __all__ names (for __init__.py re-export detection)
        all_names: Set[str] = self._extract_all_names(tree)

        # Check which lines have protection markers
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
                    })

        if not imports_info:
            return content, []

        # Collect all names referenced in the code
        used_names: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name):
                    used_names.add(node.value.id)
            elif isinstance(node, ast.arg):
                used_names.add(node.arg)

        # Determine which imports to remove
        lines = content.split('\n')
        removed_names: List[str] = []
        removed_import_indices: List[int] = []  # indices of ORIGINAL lines that had imports

        for imp in imports_info:
            if imp['side_effect']:
                continue

            imported_names = set(imp['names'])

            # SKIP: any line of this import is marked protected
            is_protected = any(
                ln in protected_lines
                for ln in range(imp['first_lineno'] - 1, imp['last_lineno'])
            )
            if is_protected:
                continue

            # SKIP: this is an __init__.py and imports contribute to __all__
            if all_names and imported_names & all_names:
                # This import contributes to __all__ — don't remove
                continue

            unused = imported_names - used_names

            if unused == imported_names:
                for ln in range(imp['first_lineno'] - 1, imp['last_lineno']):
                    if 0 <= ln < len(lines):
                        removed_import_indices.append(ln)
                        lines[ln] = ''  # blank out for later filtering
                removed_names.append(', '.join(imp['names']))

        if not removed_import_indices:
            return content, []

        removed_set = set(removed_import_indices)
        first_removed = min(removed_import_indices)
        last_removed = max(removed_import_indices)

        # Build clean list:
        # - Skip '' (blanked import lines)
        # - Find first non-import/non-blank/non-comment statement in output
        # - Ensure exactly one blank line before it (from the import block boundary)
        # - Keep ALL other blank lines as-is (between functions, etc.)
        cleaned: List[str] = []
        first_non_import_seen = False
        for i, line in enumerate(lines):
            if line == '':
                continue  # skip blanked import lines

            is_blank = line.strip() == ''
            if is_blank:
                # Blank line in the output
                if not first_non_import_seen:
                    # Before first non-import: keep at most 1 (boundary separator)
                    if not cleaned or cleaned[-1].strip() != '':
                        cleaned.append(line)
                else:
                    # After first non-import: keep all blanks (e.g. between functions)
                    cleaned.append(line)
            else:
                cleaned.append(line)
                stripped = line.strip()
                # Check if this is the first non-import, non-blank, non-comment statement
                if stripped and not stripped.startswith('#') and \
                   not stripped.startswith('import ') and not stripped.startswith('from '):
                    first_non_import_seen = True

        new_content = '\n'.join(cleaned).strip('\n') + '\n'

        return new_content, removed_names

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
            names = [alias.asname or alias.name for alias in node.names]
            return names, False, node.module
        return [], False, None

    def _is_side_effect_module(self, names: List[str]) -> bool:
        """Return True if any of these module names are known side-effect imports."""
        for name in names:
            top = name.split('.')[0]
            if top in self.SIDE_EFFECT_MODULES:
                return True
        return False
