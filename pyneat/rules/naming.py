"""Rule for standardizing variable and class names."""

import re
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule

class NamingConventionRule(Rule):
    """Enforces consistent naming conventions for classes and functions."""
    
    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self.class_pattern = re.compile(r'class\s+(\w+)')
        self.function_name_pattern = re.compile(r'def\s+(\w+)\s*\(')
    
    @property
    def description(self) -> str:
        return "Enforces PEP8 naming for classes and functions only"
    
    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes = []
            content = code_file.content
            
            # Collect names that need changing
            name_mapping = {}
            
            # 1. Fix class names (PascalCase)
            class_mapping = self._collect_class_names(content)
            name_mapping.update(class_mapping)
            
            # 2. Fix function names (snake_case)
            func_mapping = self._collect_function_names(content)
            name_mapping.update(func_mapping)
            
            # Apply changes
            if name_mapping:
                content = self._apply_all_changes(content, name_mapping)
                for old, new in name_mapping.items():
                    if old != new:
                        changes.append(f"Name '{old}' -> '{new}'")
            
            return self._create_result(code_file, content, changes)
            
        except Exception as e:
            return self._create_error_result(code_file, f"Naming convention failed: {str(e)}")
    
    def _collect_class_names(self, content: str) -> dict:
        """Collect class names that need fixing."""
        mapping = {}
        matches = self.class_pattern.finditer(content)
        
        for match in matches:
            original_name = match.group(1)
            if not self._is_pascal_case(original_name):
                new_name = self._to_pascal_case(original_name)
                if new_name != original_name:
                    mapping[original_name] = new_name
        
        return mapping
    
    def _collect_function_names(self, content: str) -> dict:
        """Collect function names that need fixing."""
        mapping = {}
        matches = self.function_name_pattern.finditer(content)
        
        for match in matches:
            original_name = match.group(1)
            if not self._is_snake_case(original_name) and original_name != original_name.upper():
                new_name = self._to_snake_case(original_name)
                if new_name != original_name:
                    mapping[original_name] = new_name
        
        return mapping
    
    def _apply_all_changes(self, content: str, name_mapping: dict) -> str:
        """Apply all name changes at once with word boundaries."""
        for old_name, new_name in name_mapping.items():
            if old_name != new_name:
                pattern = r'\b' + re.escape(old_name) + r'\b'
                content = re.sub(pattern, new_name, content)
        
        return content
    
    def _is_pascal_case(self, name: str) -> bool:
        if not name:
            return False
        if '_' in name:
            parts = name.split('_')
            return all(part and part[0].isupper() for part in parts if part)
        return name[0].isupper()
    
    def _is_snake_case(self, name: str) -> bool:
        if not name:
            return False
        if name.startswith('_') or name.endswith('_'):
            return True
        if '_' in name:
            parts = name.split('_')
            return all(part.islower() or part.isdigit() for part in parts if part)
        return name.islower()
    
    def _to_pascal_case(self, name: str) -> str:
        if not name:
            return name
        if '_' in name:
            parts = name.split('_')
            return ''.join(part.capitalize() for part in parts if part)
        if name and not name[0].isupper():
            return name[0].upper() + name[1:]
        return name
    
    def _to_snake_case(self, name: str) -> str:
        if not name:
            return name
        
        # If already snake_case, return as is
        if self._is_snake_case(name):
            return name
        
        # Handle uppercase names with underscores
        if name.isupper() or (all(c.isupper() or c == '_' for c in name)):
            clean_name = name.replace('_', '')
            if clean_name:
                result = []
                for i, char in enumerate(clean_name):
                    if char.isupper() and i > 0:
                        result.append('_')
                    result.append(char.lower())
                return ''.join(result)
            return name.lower()
        
        # Convert camelCase/PascalCase to snake_case
        result = []
        for i, char in enumerate(name):
            if char.isupper() and i > 0:
                result.append('_')
            result.append(char.lower())
        
        return ''.join(result)

        
        # Fix common patterns
        fixes = {
            'num_classes': 'num_classes',
            'batch_size': 'batch_size',
            'learning_rate': 'learning_rate',
            'dropout_rate': 'dropout_rate',
            'kernel_size': 'kernel_size',
            'input_dim': 'input_dim',
            'hidden_dim': 'hidden_dim',
            'output_dim': 'output_dim',
            'data_loader': 'data_loader',
            'train_data': 'train_data',
        }
        
        return fixes.get(snake_name, snake_name)
