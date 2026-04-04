"""Rule for detecting performance issues."""

import re
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule

class PerformanceRule(Rule):
    """Detects performance anti-patterns."""
    
    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self.inefficient_loop_pattern = re.compile(r'for\s+\w+\s+in\s+range\(\d+\):\s*\n\s*\w+\.append\(\w+\)')
        self.unnecessary_computation_pattern = re.compile(r'(\w+)\s*=\s*\1\s*[+\-*/]')
    
    @property
    def description(self) -> str:
        return "Detects performance issues and inefficient code"
    
    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes = []
            content = code_file.content
            
            # Detect inefficient loops
            if self.inefficient_loop_pattern.search(content):
                changes.append("🐌 INEFFICIENT LOOP: Use list comprehension instead")
            
            # Detect unnecessary computations
            unnecessary = self.unnecessary_computation_pattern.findall(content)
            if unnecessary:
                changes.append(f"⚡ UNNECESSARY COMPUTATION: {unnecessary}")
            
            # Detect potential infinite loops
            if 'while True:' in content and 'break' not in content:
                changes.append("🔄 POTENTIAL INFINITE LOOP: Missing break condition")
            
            return self._create_result(code_file, content, changes)
            
        except Exception as e:
            return self._create_error_result(code_file, f"Performance check failed: {str(e)}")
