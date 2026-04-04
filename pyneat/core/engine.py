"""Orchestrates the application of multiple rules."""

from typing import List, Dict, Any
from pathlib import Path
from pyneat.core.types import CodeFile, TransformationResult, RuleConfig
from pyneat.rules.base import Rule

class RuleEngine:
    """Manages and executes cleaning rules."""
    
    def __init__(self, rules: List[Rule] = None):
        self.rules = rules or []
        self._rule_map = {rule.name: rule for rule in self.rules}
    
    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the engine."""
        self.rules.append(rule)
        self._rule_map[rule.name] = rule
    
    def remove_rule(self, rule_name: str) -> None:
        """Remove a rule by name."""
        self.rules = [r for r in self.rules if r.name != rule_name]
        self._rule_map.pop(rule_name, None)
    
    def process_file(self, file_path: Path) -> TransformationResult:
        """Process a single file with all enabled rules."""
        try:
            # Fix encoding issues including BOM
            encodings = ['utf-8-sig', 'utf-8', 'latin-1', 'cp1252']
            content = None
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                return TransformationResult(
                    original=CodeFile(path=file_path, content=""),
                    transformed_content="",
                    changes_made=[],
                    success=False,
                    error=f"File reading failed: Could not decode with any encoding"
                )
            
            code_file = CodeFile(path=file_path, content=content)
            return self.process_code_file(code_file)
            
        except Exception as e:
            return TransformationResult(
                original=CodeFile(path=file_path, content=""),
                transformed_content="",
                changes_made=[],
                success=False,
                error=f"File reading failed: {str(e)}"
            )
    
    def process_code_file(self, code_file: CodeFile) -> TransformationResult:
        """Process a CodeFile object with all enabled rules."""
        current_content = code_file.content
        all_changes = []
        
        for rule in self.rules:
            if not rule.config.enabled:
                continue
                
            result = rule.apply(CodeFile(
                path=code_file.path,
                content=current_content,
                language=code_file.language
            ))
            
            if result.success:
                current_content = result.transformed_content
                all_changes.extend(result.changes_made)
            else:
                # Stop processing on error if needed
                return result
        
        return TransformationResult(
            original=code_file,
            transformed_content=current_content,
            changes_made=all_changes,
            success=True
        )
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """Get statistics about available rules."""
        return {
            'total_rules': len(self.rules),
            'enabled_rules': len([r for r in self.rules if r.config.enabled]),
            'rules': [{
                'name': rule.name,
                'description': rule.description,
                'enabled': rule.config.enabled
            } for rule in self.rules]
        }
