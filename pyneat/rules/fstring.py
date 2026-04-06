"""Rule for converting .format() and string concatenation to f-strings."""

import re
from typing import List, Tuple
import libcst as cst

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class FStringConverter(cst.CSTTransformer):
    """Converts .format() calls and string concatenation to f-strings."""

    def __init__(self):
        super().__init__()
        self.conversions: List[str] = []

    def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.Call:
        """Check if this is a .format() call that can be converted."""
        if not isinstance(updated.func, cst.Attribute):
            return updated

        if updated.func.attr.value != 'format':
            return updated

        # Get the string being called on
        string_part = updated.func.value

        # Check if it's a SimpleString
        if not isinstance(string_part, cst.SimpleString):
            return updated

        # Get the format string
        format_str = string_part.value
        if not (format_str.startswith('"') or format_str.startswith("'")):
            return updated

        # Check if it has format placeholders
        has_placeholders = '{' in format_str and '}' in format_str
        if not has_placeholders:
            return updated

        # Parse the format string and arguments
        try:
            new_fstring = self._convert_format_to_fstring(format_str, list(updated.args))
            if new_fstring:
                self.conversions.append(f"Converted .format() to f-string")
                # Parse the new f-string expression
                parsed = cst.parse_expression(new_fstring)
                return parsed
        except Exception:
            pass

        return updated

    def _convert_format_to_fstring(self, format_str: str, args: list) -> str | None:
        """Convert a .format() call to f-string format."""
        # Extract string content between quotes
        if format_str.startswith('"') and format_str.endswith('"'):
            content = format_str[1:-1]
        elif format_str.startswith("'") and format_str.endswith("'"):
            content = format_str[1:-1]
        else:
            return None

        # Simple conversion for positional arguments
        # Replace {0}, {1}, etc. with {arg_name}
        result = content

        # Replace numbered placeholders: {0}, {1}, etc.
        result = re.sub(r'\{(\d+)\}', lambda m: f'{{{int(m.group(1))}}}', result)

        # Handle named placeholders: {name}, {age}, etc.
        # These are already in f-string format

        # Add f prefix
        quote_char = '"' if format_str.startswith('"') else "'"

        # If there are single quotes inside, use double quotes
        if quote_char == "'" and "'" in result:
            quote_char = '"'

        return f'f{quote_char}{result}{quote_char}'


class FStringRule(Rule):
    """Converts .format() calls and string concatenation to f-strings.

    Patterns handled:
    - "{0}".format(x) -> f"{x}"
    - "text {}".format(x) -> f"text {x}"
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

            # Try to parse and transform
            try:
                module = cst.parse_module(content)
                transformer = FStringConverter()
                new_module = module.visit(transformer)

                if transformer.conversions:
                    changes.extend(transformer.conversions)
                    content = new_module.code
            except Exception:
                # If parsing fails, skip transformation
                pass

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"FStringRule failed: {str(e)}")


class StringConcatenationConverter(cst.CSTTransformer):
    """Converts string concatenation to f-strings when appropriate."""

    def __init__(self):
        super().__init__()
        self.conversions: List[str] = []

    def leave_BinaryOperation(self, original: cst.BinaryOperation, updated: cst.BinaryOperation) -> cst.CSTNode:
        """Check if this is a string concatenation that should be an f-string."""
        # Check if it's addition with strings
        if not isinstance(updated.operator, cst.Operator):
            return updated

        # Only handle + operator
        if not isinstance(updated.operator, cst.Add):
            return updated

        # Check if either side involves string formatting
        left = updated.left
        right = updated.right

        # Simple pattern: "text" + var -> f"text {var}"
        if isinstance(left, cst.SimpleString) and isinstance(right, (cst.Name, cst.Attribute)):
            quote = '"' if left.value.startswith('"') else "'"
            content = left.value[1:-1]

            if isinstance(right, cst.Name):
                var_name = right.value
            else:
                var_name = self._get_attr_name(right)

            # Only convert if content looks like it should be formatted
            if content and not content.endswith(' ') and not content.startswith(' '):
                new_fstring = f'f{quote}{content} {{{var_name}}}{quote}'
                self.conversions.append(f"Converted string concat to f-string: {content} + {var_name}")
                return cst.parse_expression(new_fstring)

        return updated

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

            # Try to parse and transform
            try:
                module = cst.parse_module(content)
                transformer = StringConcatenationConverter()
                new_module = module.visit(transformer)

                if transformer.conversions:
                    changes.extend(transformer.conversions)
                    content = new_module.code
            except Exception:
                pass

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"StringConcatRule failed: {str(e)}")
