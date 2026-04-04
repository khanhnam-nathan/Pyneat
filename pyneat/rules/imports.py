"""Rule for cleaning and standardizing imports."""

import re
from typing import List
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule

class ImportCleaningRule(Rule):
    """Cleans and standardizes Python imports."""
    
    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self.import_pattern = re.compile(r'^import\s+.*|^from\s+.*', re.MULTILINE)
    
    @property
    def description(self) -> str:
        return "Standardizes import statements and removes duplicates"
    
    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes = []
            content = code_file.content
            
            lines = content.split('\n')
            new_lines = []
            
            for line in lines:
                stripped = line.strip()
                
                if stripped.startswith('import ') and ',' in stripped:
                    imports_part = stripped[7:]
                    imports = [imp.strip() for imp in imports_part.split(',')]
                    
                    for imp in imports:
                        if imp:
                            new_lines.append(f'import {imp}')
                    
                    if len(imports) > 1:
                        changes.append(f'Split multi-import: {stripped}')
                else:
                    new_lines.append(line)
            
            new_content = '\n'.join(new_lines)
            lines_after_split = new_content.split('\n')
            
            import_lines = []
            other_lines = []
            
            for line in lines_after_split:
                stripped = line.strip()
                if stripped.startswith('import ') or stripped.startswith('from '):
                    import_lines.append(stripped)
                else:
                    other_lines.append(line)
            
            unique_imports = []
            seen = set()
            for imp in import_lines:
                if imp not in seen:
                    seen.add(imp)
                    unique_imports.append(imp)
            
            if len(import_lines) != len(unique_imports):
                changes.append(f'Removed {len(import_lines) - len(unique_imports)} duplicate imports')
            
            final_content = '\n'.join(unique_imports + [''] + other_lines)
            return self._create_result(code_file, final_content, changes)
            
        except Exception as e:
            return self._create_error_result(code_file, f'Import cleaning failed: {str(e)}')
