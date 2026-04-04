"""Rule for improving code quality."""

import re
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule

class CodeQualityRule(Rule):
    """Improves code quality by detecting anti-patterns."""
    
    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self.magic_number_pattern = re.compile(r'\b\d{2,}\b')
        self.empty_except_pattern = re.compile(r'except:\s*pass')
        self.unused_import_pattern = re.compile(r'import\s+(\w+)(?![^\n]*\b\1\b)')
    
    @property
    def description(self) -> str:
        return "Detects and suggests fixes for code quality issues"
    
    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes = []
            content = code_file.content
            
            # Detect magic numbers
            magic_numbers = set(self.magic_number_pattern.findall(content))
            suspicious_numbers = [n for n in magic_numbers if len(n) >= 3 and not n.startswith('0')]
            if suspicious_numbers:
                changes.append(f"🔢 MAGIC NUMBERS DETECTED: {suspicious_numbers}")
            
            # Detect empty except blocks
            if self.empty_except_pattern.search(content):
                changes.append("🔄 EMPTY EXCEPT BLOCKS: Add proper error handling")
            
            # Detect potentially unused imports (basic check)
            imports = re.findall(r'import\s+(\w+)', content)
            for imp in imports:
                if content.count(imp) == 1:  # Only found in import statement
                    changes.append(f"🗑️ POTENTIALLY UNUSED IMPORT: {imp}")
            
            return self._create_result(code_file, content, changes)
            
        except Exception as e:
            return self._create_error_result(code_file, f"Quality check failed: {str(e)}")
