"""Base class for multi-language clean rules using LN-AST.

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
from typing import List, Set, Tuple

from pyneat.rules.base import Rule
from pyneat.core.types import CodeFile, TransformationResult


# Entry point function names that should NEVER be removed
ENTRY_POINT_NAMES: Set[str] = {
    'main', 'init', 'start', 'run', 'app', 'serve',
    'cli', 'execute', 'setup', 'configure', 'boot', 'reset',
}


# Exported function name patterns by language.
# A function is "exported" if its name (or declaration) matches these patterns.
EXPORTED_NAME_PATTERNS: List[re.Pattern] = [
    # Go: func Foo(...) (uppercase first letter)
    re.compile(r'^[A-Z][a-zA-Z0-9]*$'),
    # Java/C#/TypeScript: public methods (already handled via decorators or modifiers)
    re.compile(r'^public[A-Z]'),
    # Rust: pub fn (handled via declaration inspection)
    # JavaScript/TypeScript: export function/export const/export class
    # Ruby: def self.method_name
    # PHP: public function, function __construct
]


class MultilangCleanRule(Rule):
    """Base class for multi-language clean rules.

    All rules in the multilang module inherit from this class.
    They use LN-AST (Language-Neutral AST) produced by pyneat-rs
    (tree-sitter based) to analyze and transform code.

    Subclasses only need to implement the ``detect()`` method
    that returns a list of line ranges to remove/replace.
    """

    #: Supported languages for all multilang rules
    SUPPORTED_LANGUAGES: List[str] = [
        "javascript", "typescript", "go", "java",
        "rust", "csharp", "php", "ruby",
    ]

    @property
    def supported_languages(self) -> List[str]:
        return self.SUPPORTED_LANGUAGES

    # -------------------------------------------------------------------------
    # Helper: line manipulation
    # -------------------------------------------------------------------------

    def _remove_lines(self, content: str, start_line: int, end_line: int) -> str:
        """Remove lines from start_line to end_line (1-indexed, inclusive).

        Replaces each line in the range with empty string, preserving newlines
        so line numbers stay stable for other edits.
        """
        lines = content.splitlines(keepends=True)
        # If the last line doesn't end with newline, add it back
        has_trailing_newline = content.endswith('\n')
        for i in range(start_line - 1, min(end_line, len(lines))):
            lines[i] = ''
        result = "".join(lines)
        if has_trailing_newline and not result.endswith('\n'):
            result += '\n'
        return result

    def _replace_lines(
        self,
        content: str,
        start_line: int,
        end_line: int,
        replacement: str,
    ) -> str:
        """Replace lines from start_line to end_line with replacement text.

        Replaces the entire lines with the replacement string.
        """
        lines = content.splitlines(keepends=True)
        # If the last line doesn't end with newline, add it
        has_trailing_newline = content.endswith('\n')
        replacement_lines = (replacement + '\n').splitlines(keepends=True)
        if replacement_lines and not replacement_lines[-1].endswith('\n'):
            replacement_lines[-1] += '\n'
        # Replace from start_line-1 to end_line-1 inclusive
        before = lines[:start_line - 1]
        after = lines[end_line:]
        result = "".join(before + replacement_lines + after)
        if has_trailing_newline and not result.endswith('\n'):
            result += '\n'
        return result

    # -------------------------------------------------------------------------
    # Helper: LN-AST traversal
    # -------------------------------------------------------------------------

    def _get_all_callees(self, cf: CodeFile) -> Set[str]:
        """Collect all possible callee names from ln_ast calls.

        For a call like `fmt.Println(...)`, returns:
        {"fmt", "fmt.Println", "Println"}

        This ensures we don't falsely flag functions as unused when they're
        called with a qualified name.
        """
        calls = self.get_ln_calls(cf)
        callees: Set[str] = set()
        for call in calls:
            callee = call.get("callee", "")
            if not callee:
                continue
            parts = callee.split(".")
            for j in range(len(parts)):
                callees.add(".".join(parts[j:]))
        return callees

    def _get_all_used_names(self, cf: CodeFile) -> Set[str]:
        """Collect all names used anywhere in the code for import matching.

        Returns all identifiers that appear in:
        - function calls
        - variable assignments
        - type annotations
        - etc.
        """
        used: Set[str] = set()

        # From calls
        callees = self._get_all_callees(cf)
        used.update(callees)

        # From assignments
        for asgn in cf.ln_ast.get("assignments", []):
            used.add(asgn.get("name", ""))

        # From function parameters
        for fn in cf.ln_ast.get("functions", []):
            for param in fn.get("params", []):
                used.add(param)

        # From strings (for dynamic uses)
        for s in cf.ln_ast.get("strings", []):
            val = s.get("value", "")
            if len(val) < 64:  # Reasonable identifier length
                used.add(val)

        return used

    def _is_entry_point(self, name: str) -> bool:
        """Check if function name is a known entry point."""
        return name in ENTRY_POINT_NAMES

    def _is_likely_exported(self, fn: dict, cf: CodeFile) -> bool:
        """Heuristic: is this function likely exported (public API)?

        Conservative: returns True only for clear cases of exported functions.
        """
        name = fn.get("name", "")

        # Check source line for export/modifier keywords
        start = fn.get("start_line", 1) - 1
        lines = cf.content.splitlines(keepends=True)
        if start < len(lines):
            line = lines[start]
            source_line = " " + line + " "

            # JS/TS: export function / export const / export default
            if cf.language in ("javascript", "typescript"):
                if 'export' in source_line:
                    return True
                # TypeScript: export async function
                if re.search(r'\bexport\b', line):
                    return True

            # Go exported functions start with uppercase letter
            if cf.language == "go" and name and name[0].isupper():
                return True

            # Rust pub fn
            if cf.language == "rust" and re.search(r'\bpub\s+(?:async\s+)?fn\b', line):
                return True

            # Java/C#: public methods
            if cf.language in ("java", "csharp") and 'public' in line:
                return True

            # Ruby: def self.method or def initialize
            if cf.language == "ruby":
                if name in ("initialize",):
                    return True
                if re.search(r'\bdef\s+self\.', line):
                    return True

            # PHP: all functions are globally accessible
            if cf.language == "php":
                return True

        return False

    def _collect_changes(
        self,
        content: str,
        removals: List[Tuple[int, int]],
        replacements: List[Tuple[int, int, str]],
    ) -> Tuple[str, List[str]]:
        """Apply removals and replacements to content, return (new_content, change_descriptions).

        Removals and replacements are applied in reverse line order to preserve
        line numbers.
        """
        changes: List[str] = []

        # Sort by line number descending to preserve indices
        all_ops: List[Tuple[int, str, Tuple]] = []
        for start, end in removals:
            all_ops.append((start, "remove", (start, end)))
        for start, end, repl in replacements:
            all_ops.append((start, "replace", (start, end, repl)))

        all_ops.sort(key=lambda x: x[0], reverse=True)

        current = content
        for line_num, op_type, params in all_ops:
            if op_type == "remove":
                start, end = params
                current = self._remove_lines(current, start, end)
            else:
                start, end, repl = params
                current = self._replace_lines(current, start, end, repl)

        return current, changes
