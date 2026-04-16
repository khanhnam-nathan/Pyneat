"""Remove unused imports in non-Python languages using LN-AST + regex fallback.

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
"""

import re
from typing import List, Tuple, Optional

from pyneat.rules.multilang.base import MultilangCleanRule
from pyneat.core.types import CodeFile, TransformationResult


# Regex patterns to extract import information from source code.
# Returns (line_no, imported_names, module) tuples.
# Each pattern returns a list of (line_number, imported_names_list, module_or_path).
_IMPORT_PATTERNS = {
    "javascript": re.compile(
        r'^import\s+(?:'
        # import { name } from 'module'
        r'\{([^}]+)\}\s+from\s+[\'"]([^\'"]+)[\'"]'
        r'|'
        # import name from 'module'
        r'([^;\s]+?)\s+from\s+[\'"]([^\'"]+)[\'"]'
        r'|'
        # import 'module' (side-effect)
        r'[\'"]([^\'"]+)[\'"]'
        r')',
        re.MULTILINE,
    ),
    "typescript": re.compile(
        r'^import\s+(?:'
        r'\{([^}]+)\}\s+from\s+[\'"]([^\'"]+)[\'"]'
        r'|'
        r'([^;\s]+?)\s+from\s+[\'"]([^\'"]+)[\'"]'
        r'|'
        r'[\'"]([^\'"]+)[\'"]'
        r')',
        re.MULTILINE,
    ),
    "go": re.compile(
        r'^import\s+(?:'
        # import "module" or import "path/to/module"
        r'(?:(?:\(\s*)?|([^\(\s]+)\s*)"([^"]+)"'
        r')',
        re.MULTILINE,
    ),
    "java": re.compile(
        r'^import\s+(?:'
        # import package.Name;
        r'(?:static\s+)?([\w.]+)(?:\.\*)?\s*;'
        r')',
        re.MULTILINE,
    ),
    "rust": re.compile(
        r'^use\s+'
        r'(?:'
        # use path::to::item;
        r'([\w:]+)'
        r'(?:::\{[^}]+\})?'  # use path::{a, b}
        r'|'
        # use path as alias;
        r'([\w:]+)\s+as\s+\w+'
        r'|'
        # use path::{self, ...}
        r'([\w:]+)::\{'
        r')',
        re.MULTILINE,
    ),
    "csharp": re.compile(
        r'^using\s+'
        r'(?:'
        r'([\w.]+)(?:\.\*)?\s*;'
        r'|'
        r'(static\s+[\w.]+)\s*;'
        r')',
        re.MULTILINE,
    ),
    "php": re.compile(
        r'^use\s+'
        r'(?:'
        r'([\\\w]+)(?:\s+as\s+\w+)?\s*;'
        r')',
        re.MULTILINE,
    ),
    "ruby": re.compile(
        r'^(?:require|require_relative)\s+'
        r'[\'"]([^\'"]+)[\'"]',
        re.MULTILINE,
    ),
}


def _parse_imports_regex(
    content: str, lang: str
) -> List[dict]:
    """Parse imports from source code using regex patterns."""
    if lang not in _IMPORT_PATTERNS:
        return []

    imports = []
    pattern = _IMPORT_PATTERNS[lang]

    for m in pattern.finditer(content):
        line_no = content[:m.group(0).find(m.group(0))].count('\n') + 1
        # Adjust for multiline patterns by finding actual start
        full_match = m.group(0)
        match_start = content.find(full_match)
        line_no = content[:match_start].count('\n') + 1

        if lang in ("javascript", "typescript"):
            # Group 1: { names }, Group 2: module
            # Group 3: name, Group 4: module
            # Group 5: module (side-effect)
            names_str = m.group(1) or m.group(3) or ""
            module = m.group(2) or m.group(4) or m.group(5) or ""
            names = [n.strip() for n in names_str.split(',') if n.strip()]
        elif lang == "go":
            module = m.group(1) or m.group(2) or m.group(3) or ""
            names = []
        elif lang == "java":
            full_name = m.group(1) or m.group(2) or ""
            names = [full_name]
            module = full_name.rsplit('.', 1)[-1] if '.' in full_name else full_name
        elif lang == "rust":
            name = m.group(1) or m.group(2) or m.group(3) or ""
            names = [name.rsplit('::', 1)[-1] if '::' in name else name]
            module = name
        elif lang in ("csharp", "php"):
            name = m.group(1) or m.group(2) or ""
            names = [name.rsplit('.', 1)[-1] if '.' in name else name]
            module = name
        elif lang == "ruby":
            module = m.group(1) or ""
            names = []
        else:
            names = []
            module = ""

        if names or module:
            imports.append({
                "name": names[0] if names else module,
                "names": names,
                "module": module,
                "start_line": line_no,
                "end_line": line_no,
            })

    return imports


class UnusedImportRule(MultilangCleanRule):
    """Remove import statements that are never used in the code.

    Uses LN-AST to find all imports (with regex fallback for edge cases)
    and removes imports whose names are not referenced in calls.

    Preserves:
      - Side-effect imports (import "module" with no specific names)
      - Re-exported imports (relative imports)
      - Imports from __future__ (Python-specific)

    Supported languages: javascript, typescript, go, java, rust,
                         csharp, php, ruby.
    """

    @property
    def description(self) -> str:
        return "Removes unused imports in non-Python languages"

    def apply(self, cf: CodeFile) -> TransformationResult:
        try:
            if cf.ln_ast is None:
                return self._create_result(cf, cf.content, [])

            changes: List[str] = []
            removals: List[Tuple[int, int]] = []

            # Collect all used names from LN-AST calls
            used_names = self._get_all_used_names(cf)

            # Get imports from LN-AST, fall back to regex if empty
            imports = self.get_ln_imports(cf)

            if not imports and cf.language in _IMPORT_PATTERNS:
                imports = _parse_imports_regex(cf.content, cf.language)

            if not imports:
                return self._create_result(cf, cf.content, [])

            for imp in imports:
                names = imp.get("names", [])
                module = imp.get("module", "")
                name = imp.get("name", "")
                alias = imp.get("alias", "")
                start = imp.get("start_line", 1)
                end = imp.get("end_line", start)

                # Skip side-effect imports (no specific names)
                if not names and not name:
                    continue

                # Skip relative imports (re-exports)
                if module.startswith('.'):
                    continue

                # Check each imported name
                unused = False
                for n in (names or [name]):
                    effective = alias if alias else n
                    if effective not in used_names:
                        # Also check qualified calls
                        qualified_used = any(
                            f"{effective}." in u
                            for u in used_names if isinstance(u, str)
                        )
                        if not qualified_used:
                            unused = True
                            break

                if unused:
                    if not any(r[0] <= start <= r[1] for r in removals):
                        removals.append((start, end))
                        changes.append(
                            f"Removed unused import: {name or module}"
                        )

            if not removals:
                return self._create_result(cf, cf.content, [])

            # Apply removals in reverse order
            current = cf.content
            for start, end in sorted(removals, key=lambda x: x[0], reverse=True):
                current = self._remove_lines(current, start, end)

            return self._create_result(cf, current, changes)

        except Exception as e:
            return self._create_error_result(cf, f"UnusedImportRule failed: {e}")
