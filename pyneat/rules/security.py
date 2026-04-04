"""Rule for detecting security vulnerabilities."""

import re
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule

class SecurityScannerRule(Rule):
    """Detects security vulnerabilities in AI-generated code."""
    
    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self.sql_injection_pattern = re.compile(r'cursor\.execute\s*\(\s*["\'][^"\']*\+[^"\']*["\']')
        self.hardcoded_secrets_pattern = re.compile(r'(api_key|password|secret|token)\s*=\s*["\'][^"\']{10,}["\']')
        self.eval_pattern = re.compile(r'eval\s*\(')
    
    @property
    def description(self) -> str:
        return "Detects security vulnerabilities and hardcoded secrets"
    
    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes = []
            content = code_file.content
            
            # Check for SQL injection vulnerabilities
            if self.sql_injection_pattern.search(content):
                changes.append("⚠️ POTENTIAL SQL INJECTION: String concatenation in SQL queries")
            
            # Check for hardcoded secrets
            secrets = self.hardcoded_secrets_pattern.findall(content)
            if secrets:
                changes.append(f"🔐 HARDCODED SECRETS DETECTED: {secrets}")
            
            # Check for dangerous eval usage
            if self.eval_pattern.search(content):
                changes.append("🚨 DANGEROUS eval() USAGE DETECTED")
            
            return self._create_result(code_file, content, changes)
            
        except Exception as e:
            return self._create_error_result(code_file, f"Security scan failed: {str(e)}")
