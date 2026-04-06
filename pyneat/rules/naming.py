"""Rule for standardizing variable and class names."""

import libcst as cst
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class NamingTransformer(cst.CSTTransformer):
    """LibCST transformer that converts snake_case class names to PascalCase."""

    def leave_ClassDef(
        self, original_node: cst.ClassDef, updated_node: cst.ClassDef
    ) -> cst.ClassDef:
        name_node = updated_node.name
        original_name = name_node.value

        if not self._is_pascal_case(original_name) and not self._is_snake_case(original_name):
            new_name = self._to_pascal_case(original_name)
            if new_name != original_name:
                new_name_node = name_node.with_changes(value=new_name)
                return updated_node.with_changes(name=new_name_node)

        return updated_node

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


class NamingConventionRule(Rule):
    """Enforces consistent naming conventions for classes and functions."""

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)

    @property
    def description(self) -> str:
        return "Enforces PEP8 naming for classes and functions only"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            source_tree = cst.parse_module(code_file.content)
            transformer = NamingTransformer()
            modified_tree = source_tree.visit(transformer)
            new_content = modified_tree.code

            changes = []
            original_names = self._collect_class_names(code_file.content)
            for old, new in original_names.items():
                if old != new:
                    changes.append(f"Name '{old}' -> '{new}'")

            return self._create_result(code_file, new_content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"Naming convention failed: {str(e)}")

    def _collect_class_names(self, content: str) -> dict:
        """Collect class names that need fixing."""
        import re

        mapping = {}
        try:
            pattern = re.compile(r'class\s+(\w+)')
            for match in pattern.finditer(content):
                original_name = match.group(1)
                if not self._is_pascal_case(original_name) and not self._is_snake_case(original_name):
                    new_name = self._to_pascal_case(original_name)
                    if new_name != original_name:
                        mapping[original_name] = new_name
        except Exception:
            pass
        return mapping

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
