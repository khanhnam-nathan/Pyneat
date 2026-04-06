"""Rule for refactoring complex code structures."""

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
                new_lines.append("    return 'Default_Value'  # TODO: Replace with actual default")
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
        """Fix empty except blocks by adding a raise instead of silently swallowing errors."""
        changes = []
        lines = content.split('\n')
        new_lines = []
        i = 0

        while i < len(lines):
            line = lines[i]
            if 'except:' in line and i + 1 < len(lines) and lines[i + 1].strip() == 'pass':
                # Calculate the base indentation of the except line
                base_indent = len(line) - len(line.lstrip())
                body_indent = ' ' * (base_indent + 4)  # Body is one level deeper

                new_lines.append(line.replace('except:', 'except Exception as e:'))
                new_lines.append(f"{body_indent}# TODO: Add proper error handling")
                new_lines.append(f"{body_indent}raise RuntimeError('Unhandled exception') from e")
                changes.append("Fixed empty except block")
                i += 2  # Skip the pass line
            else:
                new_lines.append(line)
                i += 1

        return '\n'.join(new_lines), changes
    
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
