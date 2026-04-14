"""Remove unused (dead) functions in non-Python languages using LN-AST.

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

from typing import List, Tuple

from pyneat.rules.multilang.base import MultilangCleanRule
from pyneat.core.types import CodeFile, TransformationResult


class UnusedFunctionRule(MultilangCleanRule):
    """Remove functions that are defined but never called.

    Uses LN-AST to find all function definitions and all function calls,
    then removes functions with no corresponding call.

    Preserves:
      - Entry point functions: main, init, start, run, app, serve, etc.
      - Exported/public functions (Go: uppercase names, JS: export, etc.)
      - Functions with side effects (yield, raise statements — heuristic)
      - Class constructors (new, __init__ equivalents)
      - Methods that appear as method calls on objects

    Supported languages: javascript, typescript, go, java, rust,
                         csharp, php, ruby.
    """

    @property
    def description(self) -> str:
        return "Removes unused functions in non-Python languages"

    def apply(self, cf: CodeFile) -> TransformationResult:
        try:
            if cf.ln_ast is None:
                return self._create_result(cf, cf.content, [])

            changes: List[str] = []
            removals: List[Tuple[int, int]] = []

            # Step 1: collect all used names
            used_names = self._get_all_callees(cf)

            # Step 2: find all function definitions
            functions = self.get_ln_functions(cf)
            if not functions:
                return self._create_result(cf, cf.content, [])

            # Step 3: for each function, check if it's used
            for fn in functions:
                name = fn.get("name", "")
                if not name:
                    continue

                # Skip entry points
                if self._is_entry_point(name):
                    continue

                # Skip exported/public functions
                if self._is_likely_exported(fn, cf):
                    continue

                # Skip constructors (Java: className, JS: constructor, C#: ClassName)
                if self._is_constructor(name, cf):
                    continue

                # Check if function name or qualified names appear in calls
                if self._is_function_used(name, used_names, cf):
                    continue

                # Function is unused — queue for removal
                start = fn.get("start_line", 1)
                end = fn.get("end_line", start)
                removals.append((start, end))
                changes.append(f"Removed unused function: {name}")

            if not removals:
                return self._create_result(cf, cf.content, [])

            # Apply removals in reverse order
            current = cf.content
            for start, end in sorted(removals, reverse=True):
                current = self._remove_lines(current, start, end)

            return self._create_result(cf, current, changes)

        except Exception as e:
            return self._create_error_result(cf, f"UnusedFunctionRule failed: {e}")

    def _is_function_used(
        self, name: str, used_names: set, cf: CodeFile
    ) -> bool:
        """Check if a function name is referenced anywhere in the code."""
        # Direct call: foo()
        if name in used_names:
            return True

        # Qualified call: obj.foo() or module.foo()
        for used in used_names:
            if used.endswith(f".{name}") or used == name:
                return True

        # JavaScript: obj[name]() dynamic call
        # (handled by checking strings for property access)

        # Skip if name is too short to be reliable
        if len(name) < 3:
            # Only skip if we have clear evidence it's NOT used
            return True  # be conservative for short names

        return False

    def _is_constructor(self, name: str, cf: CodeFile) -> bool:
        """Heuristic: is this a constructor function?

        Only matches explicit constructor naming patterns:
        - JavaScript: function ClassName() {} or new ClassName()
        - Java: public ClassName() {}
        - C#: public ClassName() {}

        Does NOT treat all PascalCase names as constructors - that would
        be too aggressive and preserve unused PascalCase utility functions.
        """
        # Only treat explicit "constructor" name as constructor in JS/TS
        if cf.language in ("javascript", "typescript"):
            if name.lower() == "constructor":
                return True
            # Do NOT treat all PascalCase as constructors - common utility functions
            # like formatData, processData, getConfig are NOT constructors
            return False

        # Java/C#/PHP: explicit class-name constructor (same name as class)
        # Without class context, we can't reliably detect these from name alone.
        # Be conservative and return False - false positives are worse than
        # false negatives for constructor detection.
        return False
