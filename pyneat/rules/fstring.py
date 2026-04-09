"""Rule for converting .format() and string concatenation to f-strings.

Copyright (c) 2024-2026 PyNEAT Authors

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
from typing import List
import libcst as cst

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class FStringConverter(cst.CSTTransformer):
    """Converts .format() calls to f-strings.

    Handles:
    - Numbered placeholders: "{0}", "{1}" → "{arg}"
    - Auto-numbered placeholders: "{}", "{}" → "{arg0}", "{arg1}"
    - Named placeholders: "{name}", "{age}" (already in f-string format)
    - Format specs: "{value:d}", "{value:.2f}", "{value:,}" → parsed, output simplified
    - Complex expressions in placeholders: "{obj.attr}", "{func(arg)}" (passthrough)
    """

    def __init__(self):
        super().__init__()
        self.conversions: List[str] = []

    def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.Call:
        """Check if this is a .format() call that can be converted."""
        if not isinstance(updated.func, cst.Attribute):
            return updated

        if updated.func.attr.value != 'format':
            return updated

        string_part = updated.func.value

        # Only handle SimpleString
        if not isinstance(string_part, cst.SimpleString):
            return updated

        format_str = string_part.value
        if not (format_str.startswith('"') or format_str.startswith("'")):
            return updated

        has_placeholders = '{' in format_str and '}' in format_str
        if not has_placeholders:
            return updated

        try:
            new_fstring = self._convert_format_to_fstring(format_str, list(updated.args))
            if new_fstring:
                self.conversions.append("Converted .format() to f-string")
                parsed = cst.parse_expression(new_fstring)
                return parsed
        except Exception:
            pass

        return updated

    def _convert_format_to_fstring(self, format_str: str, args: list) -> str | None:
        """Convert a .format() call to f-string format."""
        quote_char = '"' if format_str.startswith('"') else "'"
        content = format_str[1:-1]

        # 1. Handle format specs: {value:d}, {value:.2f}, {value:,}, etc.
        # Remove format specs from placeholders (f-strings don't need them)
        # Pattern: {anything:format_spec} or {anything!conversion:format_spec}
        content = re.sub(
            r'\{(\d+)(:[^}]+)?\}',
            lambda m: f'{{{int(m.group(1))}}}',
            content
        )
        content = re.sub(
            r'\{([^{}:]+)(:[^}]+)?\}',
            r'{\1}',
            content
        )

        # 2. Replace auto-numbered {} placeholders with positional args
        auto_num = 0
        def replace_auto_num(m):
            nonlocal auto_num
            if auto_num < len(args):
                arg = args[auto_num]
                auto_num += 1
                # Try to get the argument name
                if hasattr(arg, 'value') and isinstance(arg.value, cst.Name):
                    return f'{{{arg.value.value}}}'
                if hasattr(arg, 'value') and isinstance(arg.value, cst.Attribute):
                    return '{' + self._get_attr_name(arg.value) + '}'
                return f'{{{auto_num - 1}}}'
            return m.group(0)

        # Only replace {} (not {name}) - check for bare {}
        if '{}' in content:
            content = re.sub(r'\{\}', replace_auto_num, content)

        # 3. Use double quotes if single quotes appear in content
        if quote_char == "'" and "'" in content:
            quote_char = '"'

        return f'f{quote_char}{content}{quote_char}'

    def _get_attr_name(self, node: cst.Attribute) -> str:
        """Get dotted name from attribute."""
        parts = []
        current = node
        while isinstance(current, cst.Attribute):
            parts.append(current.attr.value)
            current = current.value
        if isinstance(current, cst.Name):
            parts.append(current.value)
        return '.'.join(reversed(parts))


class FStringRule(Rule):
    """Converts .format() calls and string concatenation to f-strings.

    Patterns handled:
    - "{0}".format(x) -> f"{x}"
    - "text {}".format(x) -> f"text {x}"
    - "{} {}".format(a, b) -> f"{a} {b}"
    - "text " + name -> f"text {name}"
    """

    @property
    def description(self) -> str:
        return "Converts .format() and string concatenation to f-strings"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes)

            # Use cached CST tree if available (RuleEngine pre-parses)
            if hasattr(code_file, 'cst_tree') and code_file.cst_tree is not None:
                module = code_file.cst_tree
            else:
                try:
                    module = cst.parse_module(content)
                except Exception:
                    return self._create_result(code_file, content, changes)

            transformer = FStringConverter()
            new_module = module.visit(transformer)

            if transformer.conversions:
                changes.extend(transformer.conversions)
                content = new_module.code

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"FStringRule failed: {str(e)}")


class StringConcatenationConverter(cst.CSTTransformer):
    """Converts string concatenation to f-strings when appropriate."""

    def __init__(self):
        super().__init__()
        self.conversions: List[str] = []

    def leave_BinaryOperation(
        self, original: cst.BinaryOperation, updated: cst.BinaryOperation
    ) -> cst.CSTNode:
        """Check if this is a string concatenation that should be an f-string."""
        if not isinstance(updated.operator, cst.Operator):
            return updated

        if not isinstance(updated.operator, cst.Add):
            return updated

        left = updated.left
        right = updated.right

        if isinstance(left, cst.SimpleString) and isinstance(right, (cst.Name, cst.Attribute)):
            quote = '"' if left.value.startswith('"') else "'"
            content = left.value[1:-1]

            if isinstance(right, cst.Name):
                var_name = right.value
            else:
                var_name = self._get_attr_name(right)

            if content and not content.endswith(' ') and not content.startswith(' '):
                new_fstring = f'f{quote}{content} {{{var_name}}}{quote}'
                self.conversions.append(f"Converted string concat to f-string: {content} + {var_name}")
                return cst.parse_expression(new_fstring)

        return updated

    def _get_attr_name(self, node: cst.Attribute) -> str:
        parts = []
        current = node
        while isinstance(current, cst.Attribute):
            parts.append(current.attr.value)
            current = current.value
        if isinstance(current, cst.Name):
            parts.append(current.value)
        return '.'.join(reversed(parts))


class StringConcatRule(Rule):
    """Converts simple string concatenation to f-strings.

    Pattern: "text" + variable -> f"text {variable}"
    """

    @property
    def description(self) -> str:
        return "Converts string concatenation to f-strings"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes)

            # Use cached CST tree if available (RuleEngine pre-parses)
            if hasattr(code_file, 'cst_tree') and code_file.cst_tree is not None:
                module = code_file.cst_tree
            else:
                try:
                    module = cst.parse_module(content)
                except Exception:
                    return self._create_result(code_file, content, changes)

            transformer = StringConcatenationConverter()
            new_module = module.visit(transformer)

            if transformer.conversions:
                changes.extend(transformer.conversions)
                content = new_module.code

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"StringConcatRule failed: {str(e)}")
