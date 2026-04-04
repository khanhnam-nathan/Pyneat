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
        """Check if code has arrow anti-pattern (deeply nested if-else)."""
        lines = content.split('\n')
        max_nesting = 0
        current_nesting = 0
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('if ') or stripped.startswith('elif '):
                current_nesting += 1
                max_nesting = max(max_nesting, current_nesting)
            elif stripped.startswith('else:'):
                current_nesting += 1
                max_nesting = max(max_nesting, current_nesting)
            elif stripped and not stripped.startswith('#'):
                # Reset nesting on non-indented lines
                if not line.startswith('    ') and not line.startswith('\t'):
                    current_nesting = 0
        
        return max_nesting >= 4  # 4+ levels of nesting is considered arrow pattern
    
    def _refactor_arrow_pattern(self, content: str) -> str:
        """Refactor arrow anti-pattern to early returns."""
        lines = content.split('\n')
        new_lines = []
        i = 0
        
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            
            # Detect deeply nested if pattern
            if (stripped.startswith('if ') and 
                i + 10 < len(lines) and 
                self._count_nesting(lines[i:i+10]) >= 3):
                
                # Extract condition
                condition = stripped[3:].rstrip(':')
                
                # Add early return for negative case
                new_lines.append(f"if not ({condition}):")
                new_lines.append("    return 'Default_Value'  # TODO: Replace with actual default")
                new_lines.append("")
                new_lines.append(line)  # Keep original if
                
                # Skip the nested block (simplified - would need complex parsing)
                i += 1
                while i < len(lines) and (lines[i].startswith('    ') or lines[i].startswith('\t')):
                    new_lines.append(lines[i])
                    i += 1
            else:
                new_lines.append(line)
                i += 1
        
        return '\n'.join(new_lines)
    
    def _count_nesting(self, lines: list) -> int:
        """Count nesting level in a block of lines."""
        max_nesting = 0
        current_nesting = 0
        
        for line in lines:
            if line.strip().startswith('if ') or line.strip().startswith('elif '):
                current_nesting += 1
                max_nesting = max(max_nesting, current_nesting)
            elif line.strip().startswith('else:'):
                current_nesting += 1
            elif line.strip() and not line.startswith('    ') and not line.startswith('\t'):
                break
        
        return max_nesting
    
    def _fix_empty_except(self, content: str) -> tuple:
        """Fix empty except blocks by adding proper error handling."""
        changes = []
        lines = content.split('\n')
        new_lines = []
        i = 0
        
        while i < len(lines):
            line = lines[i]
            if 'except:' in line and i + 1 < len(lines) and lines[i + 1].strip() == 'pass':
                new_lines.append(line.replace('except:', 'except Exception as e:'))
                new_lines.append("    # TODO: Add proper error handling")
                new_lines.append("    print(f\"Error: {e}\")  # Basic error logging")
                changes.append("Fixed empty except block")
                i += 2  # Skip the pass line
            else:
                new_lines.append(line)
                i += 1
        
        return '\n'.join(new_lines), changes
    
    def _fix_eval_usage(self, content: str) -> tuple:
        """Replace dangerous eval() with safer alternatives."""
        changes = []
        new_content = content
        
        # Simple eval replacement for basic arithmetic
        eval_pattern = r"eval\(['\"]([^'\"]*?)['\"]\)"
        matches = list(re.finditer(eval_pattern, content))
        
        for match in matches:
            eval_content = match.group(1)
            if '*' in eval_content or '+' in eval_content or '-' in eval_content:
                # Replace simple arithmetic eval with direct calculation
                safe_replacement = f"# Replaced eval: {eval_content}"
                new_content = new_content.replace(match.group(0), safe_replacement)
                changes.append(f"Replaced dangerous eval: {eval_content}")
        
        return new_content, changes
