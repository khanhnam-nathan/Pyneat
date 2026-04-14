"""Remove debug statements (console.log, fmt.Print, etc.) in non-Python languages.

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

import re
from typing import List, Tuple, Dict

from pyneat.rules.multilang.base import MultilangCleanRule
from pyneat.core.types import CodeFile, TransformationResult, RuleConfig


# Debug function patterns by language.
# Each pattern matches the callee field in LN-AST calls.
_DEBUG_PATTERNS: Dict[str, List[str]] = {
    "javascript": [
        "console.log", "console.debug", "console.warn", "console.error",
        "console.info", "alert", "debugger", "process.stdout.write",
    ],
    "typescript": [
        "console.log", "console.debug", "console.warn", "console.error",
        "console.info", "alert", "debugger",
    ],
    "go": [
        "fmt.Print", "fmt.Println", "fmt.Printf",
        "log.Print", "log.Println", "log.Printf",
        "fmt.Fprint", "fmt.Fprintln",
    ],
    "java": [
        "System.out.print", "System.out.println", "System.out.printf",
        "System.err.print", "System.err.println",
        "logger.debug", "logger.trace", "logger.info",
        "logger.fine", "logger.finer",
    ],
    "rust": [
        "println!", "dbg!", "eprintln!", "print!", "panic!",
        "trace!", "debug!", "info!", "warn!", "error!",
    ],
    "csharp": [
        "Console.Write", "Console.WriteLine",
        "Debug.Write", "Debug.WriteLine",
        "Trace.Write", "Trace.WriteLine",
        "Console.Error.Write",
    ],
    "php": [
        "var_dump", "print_r", "var_export", "debug_zval_dump",
        "error_log", "printf", "vprintf",
    ],
    "ruby": [
        "puts", "p", "pp", "print", "printf",
        "debugger", "warn",
    ],
}


def _is_debug_call(callee: str, patterns: List[str]) -> bool:
    """Check if callee matches any debug pattern."""
    if not callee:
        return False
    # Strip trailing ! for Rust macro matching
    callee_cmp = callee.rstrip('!')
    for p in patterns:
        p_cmp = p.rstrip('!')
        if callee_cmp == p_cmp:
            return True
        if p.endswith('.') and callee.startswith(p.rstrip('!')):
            return True
    return False


def _callee_to_line_range(
    call: dict, content: str
) -> Tuple[int, int]:
    """Convert LN-AST call node to (start_line, end_line) 1-indexed tuple.

    Falls back to line-based offsets if byte offsets are missing/invalid.
    """
    start_b = call.get("start_byte")
    end_b = call.get("end_byte")
    if start_b is not None and end_b is not None and end_b > start_b:
        start_line = content[:start_b].count('\n') + 1
        end_line = content[:end_b].count('\n') + 1
        return (start_line, end_line)

    # Fallback: use line numbers from ln_ast
    return (call.get("start_line", 1), call.get("end_line", 1))


class DebugStatementRule(MultilangCleanRule):
    """Remove debug statements from code.

    Uses LN-AST's `calls` field to identify debug function calls
    and removes the lines containing them.

    Modes:
      - safe: only removes debug-like statements (console.log, fmt.Print, etc.)
      - aggressive: removes all print/console statements

    Supported languages: javascript, typescript, go, java, rust,
                         csharp, php, ruby.
    """

    def __init__(self, config: RuleConfig = None, mode: str = "safe"):
        super().__init__(config)
        self.mode = mode

    @property
    def description(self) -> str:
        return f"Removes debug statements (mode={self.mode})"

    def apply(self, cf: CodeFile) -> TransformationResult:
        try:
            if cf.ln_ast is None:
                return self._create_result(cf, cf.content, [])

            patterns = _DEBUG_PATTERNS.get(cf.language, [])

            if not patterns and self.mode != "aggressive":
                return self._create_result(cf, cf.content, [])

            # In aggressive mode, use prefix-based matching
            if self.mode == "aggressive":
                aggressive_prefixes: Dict[str, List[str]] = {
                    "javascript": ["console.", "alert"],
                    "typescript": ["console.", "alert"],
                    "go": ["fmt.", "log."],
                    "java": ["System.", "logger."],
                    "rust": ["println!", "print!", "dbg!", "eprintln!", "panic!"],
                    "csharp": ["Console.", "Debug.", "Trace."],
                    "php": ["var_dump", "print_r", "echo", "printf"],
                    "ruby": ["puts", "p", "pp", "print", "printf"],
                }
                patterns = aggressive_prefixes.get(cf.language, [])

            changes: List[str] = []
            removals: List[Tuple[int, int]] = []

            calls = self.get_ln_calls(cf)

            for call in calls:
                callee = call.get("callee", "")
                if not callee:
                    continue

                if self.mode == "aggressive":
                    # Strip ! for macro names
                    callee_cmp = callee.rstrip('!')
                    is_debug = any(
                        callee_cmp.startswith(p.rstrip('!')) for p in patterns
                    )
                else:
                    is_debug = _is_debug_call(callee, patterns)

                if is_debug:
                    start_line, end_line = _callee_to_line_range(call, cf.content)
                    if not any(r[0] <= start_line <= r[1] for r in removals):
                        removals.append((start_line, end_line))
                        changes.append(f"Removed debug call: {callee}")

            # Handle debugger keyword (not a call expression, regex fallback)
            if cf.language in ("javascript", "typescript"):
                for m in re.finditer(r'^\s*debugger\s*;?\s*$', cf.content, re.MULTILINE):
                    line_no = cf.content[:m.start()].count('\n') + 1
                    if not any(r[0] <= line_no <= r[1] for r in removals):
                        removals.append((line_no, line_no))
                        changes.append("Removed debugger statement")

            if not removals:
                return self._create_result(cf, cf.content, [])

            # Apply in reverse line order
            current = cf.content
            for start, end in sorted(removals, key=lambda x: x[0], reverse=True):
                current = self._remove_lines(current, start, end)

            return self._create_result(cf, current, changes)

        except Exception as e:
            return self._create_error_result(cf, f"DebugStatementRule failed: {e}")
