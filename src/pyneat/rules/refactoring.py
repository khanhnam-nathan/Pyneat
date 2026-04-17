"""Rule for refactoring complex code structures.

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
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule

class RefactoringRule(Rule):
    """Refactors complex code structures like arrow anti-pattern."""
    
    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self.nested_if_pattern = re.compile(r'if.*:\s*\n(\s+)if.*:\s*\n(\s+)if.*:\s*\n(\s+)if', re.MULTILINE)
    
    @property
    def description(self) -> str:
        return "Refactors complex nested if-else statements"
    
    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes = []
            content = code_file.content
            
            # Detect arrow anti-pattern (nested if-else)
            if self._has_arrow_anti_pattern(content):
                content = self._refactor_arrow_pattern(content)
                changes.append("Refactored arrow anti-pattern (nested if-else)")
            
            # Detect empty except blocks
            content, except_changes = self._fix_empty_except(content)
            changes.extend(except_changes)
            
            # Detect dangerous eval usage
            content, eval_changes = self._fix_eval_usage(content)
            changes.extend(eval_changes)
            
            return self._create_result(code_file, content, changes)
            
        except Exception as e:
            return self._create_error_result(code_file, f"Refactoring failed: {str(e)}")
    
    def _has_arrow_anti_pattern(self, content: str) -> bool:
        """Check if code has arrow anti-pattern (deeply nested if-else) at module level."""
        lines = content.split('\n')
        max_nesting = 0
        current_nesting = 0

        for line in lines:
            stripped = line.strip()
            if stripped.startswith('if ') or stripped.startswith('elif '):
                # Only count module-level conditionals (zero indentation)
                indent = len(line) - len(line.lstrip())
                if indent == 0:
                    current_nesting += 1
                    max_nesting = max(max_nesting, current_nesting)
            elif stripped.startswith('else:'):
                indent = len(line) - len(line.lstrip())
                if indent == 0:
                    current_nesting += 1
                    max_nesting = max(max_nesting, current_nesting)
            elif stripped and not stripped.startswith('#'):
                if not line.startswith('    ') and not line.startswith('\t'):
                    current_nesting = 0

        return max_nesting >= 4
    
    def _refactor_arrow_pattern(self, content: str) -> str:
        """Refactor arrow anti-pattern to early returns (module-level only)."""
        lines = content.split('\n')
        new_lines = []
        i = 0

        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())

            # Only match module-level if statements (zero indentation)
            if (
                stripped.startswith('if ')
                and indent == 0
                and i + 10 < len(lines)
                and self._count_nesting(lines[i:i + 10], min_indent=0) >= 3
            ):

                # Extract condition
                condition = stripped[3:].rstrip(':')

                # Add early return for negative case
                new_lines.append(f"if not ({condition}):")
                new_lines.append("    return None  # type: ignore")
                new_lines.append("")
                new_lines.append(line)  # Keep original if

                # Skip the indented block
                i += 1
                while i < len(lines) and (lines[i].startswith('    ') or lines[i].startswith('\t')):
                    new_lines.append(lines[i])
                    i += 1
            else:
                new_lines.append(line)
                i += 1

        return '\n'.join(new_lines)
    
    def _count_nesting(self, lines: list, min_indent: int = 0) -> int:
        """Count nesting level in a block of lines."""
        max_nesting = 0
        current_nesting = 0

        for line in lines:
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            if indent < min_indent:
                break
            if stripped.startswith('if ') or stripped.startswith('elif '):
                current_nesting += 1
                max_nesting = max(max_nesting, current_nesting)
            elif stripped.startswith('else:'):
                current_nesting += 1
                max_nesting = max(max_nesting, current_nesting)
            elif stripped and not line.startswith('    ') and not line.startswith('\t'):
                break

        return max_nesting
    
    def _fix_empty_except(self, content: str) -> tuple:
        """Fix empty except blocks by adding a raise instead of silently swallowing errors.

        SKIPS: except blocks inside __getattr__, __getitem__, __setitem__,
        __delitem__, on_invalid, and other special methods where silent-fail
        is the intended behavior (e.g., Jinja2 Undefined objects).
        """
        changes = []
        lines = content.split('\n')
        new_lines = []
        i = 0

        while i < len(lines):
            line = lines[i]
            # Only match BARE except: blocks (not except Exception:, except AttributeError:, etc.)
            # Bare except is almost always wrong; typed except should be handled case-by-case
            if line.strip() == 'except:' and i + 1 < len(lines) and lines[i + 1].strip() == 'pass':
                # Detect if we're inside a special method where silent-fail is intentional
                if self._is_special_method_context(lines, i):
                    new_lines.append(line)
                    new_lines.append(lines[i + 1])
                    i += 2
                    continue

                # Calculate the base indentation of the except line
                base_indent = len(line) - len(line.lstrip())
                body_indent = ' ' * (base_indent + 4)  # Body is one level deeper

                new_lines.append(line.replace('except:', 'except Exception as e:'))
                new_lines.append(f"{body_indent}raise RuntimeError('Unhandled exception') from e")
                changes.append("Fixed empty except block")
                i += 2  # Skip the pass line
            else:
                new_lines.append(line)
                i += 1

        return '\n'.join(new_lines), changes

    def _is_special_method_context(self, lines: list, except_line_idx: int) -> bool:
        """Detect if an except block is inside a special method where silent-fail is intentional.

        Examples: __getattr__, __getitem__, __setitem__, on_invalid, etc.
        In these methods, `except: pass` is a common pattern for graceful degradation.

        Also detects the Jinja2 pattern: `except: pass` followed by `raise` on the next line,
        which is an intentional "try one thing, fall through if it fails" pattern.
        """
        SPECIAL_METHODS = frozenset({
            '__getattr__', '__getitem__', '__setitem__', '__delitem__',
            '__getattribute__', '__setattr__', '__delattr__',
            '__init__', '__call__',
            'on_invalid', 'fail', '_fail', 'fail_silently',
            '_getattr', '_getitem', '_missing',
            'getattr', 'getitem', 'resolve',
            'Undefined', 'undefined',
        })

        # Scan backwards through class bodies and function bodies to find
        # the containing method/function. Keep going until we hit module-level
        # code (indent=0, not a comment, and not a function/class definition).
        for j in range(except_line_idx - 1, -1, -1):
            stripped = lines[j].strip()
            if not stripped:
                continue

            # Check if it's a function definition FIRST (before indent check).
            # Class methods have indent=0 at their def line, so we must
            # handle this before the module-level break.
            if stripped.startswith('def ') or stripped.startswith('async def '):
                match = re.search(r'def\s+(?:async\s+)?(\w+)\s*\(', stripped)
                if match and match.group(1) in SPECIAL_METHODS:
                    return True
                # Non-special function — stop searching.
                break

            current_indent = len(lines[j]) - len(lines[j].lstrip())

            # Module-level code (0 indent, not a comment, not a function/class) — stop.
            if current_indent == 0 and not stripped.startswith('#') and \
               not stripped.startswith('class '):
                break

        # Check 2: Jinja2 pattern — `except: pass` immediately followed by `raise`.
        # Pattern: the except block body is only `pass`, and the next non-blank line
        # after it is a `raise` statement. This means the except is a "suppressor"
        # that lets execution fall through to raise a more informative error.
        # We should NOT touch this pattern.
        pass_line_idx = except_line_idx + 1
        if pass_line_idx < len(lines) and lines[pass_line_idx].strip() == 'pass':
            # Look at the next non-blank line after `pass`
            next_idx = pass_line_idx + 1
            while next_idx < len(lines) and not lines[next_idx].strip():
                next_idx += 1
            if next_idx < len(lines):
                next_stripped = lines[next_idx].strip()
                if next_stripped.startswith('raise '):
                    # This is the Jinja2 "suppressor" pattern — skip it
                    return True

        return False
    
    def _fix_eval_usage(self, content: str) -> tuple:
        """Replace dangerous eval() with safer alternatives."""
        changes = []
        eval_pattern = r"eval\(['\"]([^'\"]*?)['\"]\)"

        def replacer(match):
            eval_content = match.group(1)
            if '*' in eval_content or '+' in eval_content or '-' in eval_content:
                changes.append(f"Replaced dangerous eval: {eval_content}")
                return f"# Replaced eval: {eval_content}"
            return match.group(0)

        new_content = re.sub(eval_pattern, replacer, content)
        return new_content, changes
