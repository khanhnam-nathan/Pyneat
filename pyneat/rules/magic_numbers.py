"""Rule for detecting and flagging magic numbers in code."""

import re
from typing import List, Tuple

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class MagicNumberRule(Rule):
    """Detects magic numbers (numbers > 100) that should be named constants.

    This rule:
      - Detects integer literals with 3+ digits (> 100)
      - Skips common patterns like port numbers, IP parts, etc.
      - Adds a comment flagging the magic number
    """

    @property
    def description(self) -> str:
        return "Detects magic numbers (> 100) and suggests constants"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            # Remove magic numbers with flags
            new_content, count = self._flag_magic_numbers(content)
            if count:
                changes.append(f"Flagged {count} magic number(s)")
            content = new_content

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(
                code_file, f"MagicNumberRule failed: {str(e)}"
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _flag_magic_numbers(self, content: str) -> Tuple[str, int]:
        """Find magic numbers and add comment flags."""
        # Pattern for magic numbers: integers with 3+ digits (>= 100)
        # Excludes: numbers in strings, comments, variable names
        MAGIC_NUM_RE = re.compile(
            r'\b([1-9]\d{2,})\b(?!\s*=)',  # 100 or more, but not in assignment like CONST = 100
        )

        matches = list(MAGIC_NUM_RE.finditer(content))
        if not matches:
            return content, 0

        # Filter out common false positives
        filtered_matches = []
        for m in matches:
            # Get the surrounding context
            start = max(0, m.start() - 20)
            end = min(len(content), m.end() + 20)
            context = content[start:end]

            # Skip if inside a string or comment
            if self._is_in_string_or_comment(content, m.start()):
                continue

            # Skip common patterns like port numbers in URLs, hex colors
            if self._is_common_pattern(context, m.group(1)):
                continue

            filtered_matches.append(m)

        if not filtered_matches:
            return content, 0

        # Add comments to flagged lines
        result_lines = content.split('\n')
        flagged_lines = set()

        for m in filtered_matches:
            # Find which line this match is on
            line_num = content[:m.start()].count('\n')
            if line_num not in flagged_lines:
                flagged_lines.add(line_num)
                line = result_lines[line_num]
                # Add comment at end of line
                result_lines[line_num] = f"{line}  # MAGIC: {m.group(1)}"

        return '\n'.join(result_lines), len(flagged_lines)

    def _is_in_string_or_comment(self, content: str, pos: int) -> bool:
        """Check if position is inside a string or comment."""
        # Simple heuristic: check if there's an odd number of quotes before position
        line_start = content.rfind('\n', 0, pos) + 1
        line_prefix = content[line_start:pos]

        # Count single and double quotes
        single_quotes = line_prefix.count("'")
        double_quotes = line_prefix.count('"')

        # If odd number of quotes, likely inside string
        if single_quotes % 2 == 1 or double_quotes % 2 == 1:
            return True

        # If line starts with #, it's a comment
        if line_prefix.strip().startswith('#'):
            return True

        return False

    def _is_common_pattern(self, context: str, number: str) -> bool:
        """Check if this is a common pattern like port, IP, version."""
        # Common patterns that have legitimate multi-digit numbers
        patterns = [
            r'port[:\s]*' + number,
            r'localhost[:\s]*' + number,
            r'version[:\s]*' + number,
            r'v' + number,
            r'http[s]?://',
            r'\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP-like patterns
            r'0x[0-9a-fA-F]',  # Hex numbers
            r'#\w{6}',  # Color codes
        ]

        for pattern in patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True

        return False
