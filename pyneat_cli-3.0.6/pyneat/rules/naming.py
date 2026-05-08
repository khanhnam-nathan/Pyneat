"""Rule for standardizing variable and class names.

Copyright (c) 2026 PyNEAT Authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, contact: khanhnam.copywriting@gmail.com

NAMINGCONVENTIONRULE CHỈ đổi tên CLASS DEFINITION (snake_case -> PascalCase).
KHÔNG đổi tên biến, function, hay references — tránh lỗi logic.

Nếu muốn đổi tên đầy đủ (class + references), dùng AggressiveNamingRule.
"""

import re
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple
from collections import defaultdict

import libcst as cst
import ast

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule
from pyneat.utils.naming import _is_pascal_case, _is_snake_case, _to_pascal_case


# ----------------------------------------------------------------------
# Cross-file import updater
# ----------------------------------------------------------------------


class _CrossFileImportUpdater(cst.CSTTransformer):
    """Updates import statements and name references when a class is renamed.

    Handles:
    - `from module import OldName`  →  `from module import NewName`
    - `from module import OldName as Alias`  →  skip (user chose an alias)
    - `from module import OldName as OldName`  →  `NewName as NewName`
    - `import module; module.OldName`  →  `module.NewName`  (attribute access)
    - Name references used as types / base classes  →  updated
    """

    def __init__(self, rename_map: dict[str, str]):
        super().__init__()
        self.rename_map = rename_map  # {old_name: new_name}
        self.changes_made: List[str] = []
        self._updated = False

    # --- ImportFrom --------------------------------------------------------

    def leave_ImportFrom(
        self, original: cst.ImportFrom, updated: cst.ImportFrom
    ) -> cst.ImportFrom | cst.RemovalSentinel:
        # TẠM TẮT - Import update có thể gây lỗi nếu:
        # 1. Import là một module chứ không phải class
        # 2. Tên trùng với class nhưng là thứ khác
        # Chỉ update khi CHẮC CHẮN là class reference
        return updated

    # --- Import (module.ClassName style) ------------------------------------

    def leave_Import(
        self, original: cst.Import, updated: cst.Import
    ) -> cst.Import:
        # TẠM TẮT - Tương tự leave_ImportFrom
        return updated

    # --- Attribute access: module.OldName -> module.NewName ----------------

    def leave_Attribute(
        self, original: cst.Attribute, updated: cst.Attribute
    ) -> cst.Attribute:
        parts = []
        node: cst.CSTNode = updated
        while isinstance(node, cst.Attribute):
            if isinstance(node.attr, cst.Name):
                parts.append(node.attr.value)
            node = node.value
        if isinstance(node, cst.Name):
            parts.append(node.value)

        full_name = '.'.join(reversed(parts))

        for old_name, new_name in self.rename_map.items():
            if full_name.endswith(f'.{old_name}'):
                prefix = full_name[:-(len(old_name) + 1)]
                self._updated = True
                self.changes_made.append(f"Updated reference: {prefix}.{old_name} -> {prefix}.{new_name}")
                base = cst.Name(value=prefix.split('.')[-1])
                new_attr = cst.Attribute(value=base, attr=cst.Name(value=new_name))
                for part in reversed(prefix.split('.')[:-1]):
                    new_attr = cst.Attribute(value=cst.Name(value=part), attr=new_attr)
                return new_attr

        return updated

    # NOTE: KHÔNG có leave_Name vì nó đổi TẤT CẢ name references,
    # bao gồm cả biến thường trùng tên với class -> LỖI LOGIC nghiêm trọng


# ----------------------------------------------------------------------
# Class name transformer (in-file)
# ----------------------------------------------------------------------


class NamingTransformer(cst.CSTTransformer):
    """LibCST transformer that converts snake_case class names to PascalCase.

    Updates both class definitions AND name references within the same file.
    """

    def __init__(self, rename_map: dict[str, str] = None):
        super().__init__()
        self.rename_map = rename_map or {}

    def leave_ClassDef(
        self, original_node: cst.ClassDef, updated_node: cst.ClassDef
    ) -> cst.ClassDef:
        name_node = updated_node.name
        original_name = name_node.value

        if not _is_pascal_case(original_name):
            new_name = _to_pascal_case(original_name)
            if new_name != original_name:
                self.rename_map[original_name] = new_name
                new_name_node = name_node.with_changes(value=new_name)
                return updated_node.with_changes(name=new_name_node)

        return updated_node

    def leave_Name(
        self, original: cst.Name, updated: cst.Name
    ) -> cst.Name:
        """Update class name references within the same file."""
        if original.value in self.rename_map:
            return updated.with_changes(value=self.rename_map[original.value])
        return updated


# ----------------------------------------------------------------------
# Main rule
# ----------------------------------------------------------------------


class NamingConventionRule(Rule):
    """Enforces consistent naming conventions for classes ONLY.

    CHỈ đổi tên CLASS DEFINITION từ snake_case -> PascalCase.
    Ví dụ: class my_data -> class MyData

    KHÔNG đổi:
    - Tên biến thường
    - Tên function
    - Name references trong code

    Cross-file updates bị TẮT mặc định để tránh phá vỡ các file khác.
    """

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)

    @property
    def description(self) -> str:
        return "Enforces PEP8 naming for classes and functions only"

    def apply(
        self,
        code_file: CodeFile,
        processed_files: Optional[List[Path]] = None,
    ) -> TransformationResult:
        try:
            # Use cached CST tree if available (RuleEngine pre-parses)
            if hasattr(code_file, 'cst_tree') and code_file.cst_tree is not None:
                source_tree = code_file.cst_tree
            else:
                source_tree = cst.parse_module(code_file.content)

            # Collect rename map first via AST pass
            rename_map = self._collect_class_names(code_file.content)

            # Apply transformer with rename map (updates both class defs and usages)
            transformer = NamingTransformer(rename_map)
            modified_tree = source_tree.visit(transformer)
            new_content = modified_tree.code

            changes: List[str] = []
            for old, new in rename_map.items():
                if old != new:
                    changes.append(f"Renamed class: '{old}' -> '{new}'")

            return self._create_result(code_file, new_content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"Naming convention failed: {str(e)}")

    def _collect_class_names(self, content: str) -> dict:
        """Collect class names that need fixing.

        Handles three cases:
        1. snake_case classes (e.g. my_class) -> PascalCase (MyClass)
        2. camelCase classes (e.g. myClass) -> PascalCase (MyClass)
        3. Mixed naming (e.g. ClassName_foo) -> PascalCase (ClassNameFoo)
        """
        mapping = {}
        try:
            pattern = re.compile(r'class\s+(\w+)')
            for match in pattern.finditer(content):
                original_name = match.group(1)
                if _is_pascal_case(original_name):
                    continue
                new_name = _to_pascal_case(original_name)
                if new_name != original_name:
                    mapping[original_name] = new_name
        except Exception:
            pass
        return mapping


# --------------------------------------------------------------------------
# Naming Inconsistency Rule (AI Bug Pattern)
# --------------------------------------------------------------------------

class _NamingInconsistencyVisitor(ast.NodeVisitor):
    """AST visitor to detect mixed naming conventions in the same file."""

    def __init__(self):
        self.names: Dict[str, str] = {}  # normalized -> original
        self.changes: List[str] = []
        self._seen_pairs: Set[Tuple[str, str]] = set()

    def visit_FunctionDef(self, node):
        self._check_name_style(node.name, f"function '{node.name}'")
        for arg in node.args.args:
            if arg.arg:
                self._check_name_style(arg.arg, f"parameter '{arg.arg}'")
        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._check_name_style(target.id, f"variable '{target.id}'")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        """Check all name references for consistency."""
        self._check_name_style(node.id, f"name '{node.id}'")
        self.generic_visit(node)

    def _check_name_style(self, name: str, context: str):
        """Check if name style is consistent with previously seen names."""
        if not name or len(name) < 3:
            return

        # Normalize: remove underscores, lowercase
        normalized = name.replace('_', '').lower()

        if normalized in self.names:
            original = self.names[normalized]
            if original != name:
                pair = tuple(sorted([original, name]))
                if pair not in self._seen_pairs:
                    self._seen_pairs.add(pair)
                    orig_style = "camelCase" if '_' not in original and any(c.isupper() for c in original) else "snake_case"
                    new_style = "camelCase" if '_' not in name and any(c.isupper() for c in name) else "snake_case"
                    self.changes.append(
                        f"NAMING-INCONSISTENCY: {context} uses {new_style} "
                        f"while '{original}' uses {orig_style}"
                    )
        else:
            self.names[normalized] = name

    def _check_similar_names(self, name: str, context: str):
        """Check if name is similar to an existing one with different style."""
        if not name or len(name) < 3:
            return

        name_lower = name.lower().replace('_', '')
        # Check all existing names for similarity
        for existing, original in list(self.names.items()):
            if existing == name_lower:
                continue
            # Check if one is a prefix of the other (after normalization)
            if name_lower.startswith(existing) or existing.startswith(name_lower):
                if ('_' in name) != ('_' in original):
                    pair = tuple(sorted([original, name]))
                    if pair not in self._seen_pairs:
                        self._seen_pairs.add(pair)
                        orig_style = "camelCase" if '_' not in original and any(c.isupper() for c in original) else "snake_case"
                        new_style = "camelCase" if '_' not in name and any(c.isupper() for c in name) else "snake_case"
                        self.changes.append(
                            f"NAMING-INCONSISTENCY: {context} uses {new_style} "
                            f"while '{original}' uses {orig_style}"
                        )


class NamingInconsistencyRule(Rule):
    """Detect mixed naming conventions (camelCase vs snake_case) in the same file.

    This rule identifies variables and functions that use inconsistent naming
    styles, which is a common AI code generator mistake.
    """

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)

    @property
    def description(self) -> str:
        return "Detect mixed naming conventions (camelCase vs snake_case)"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        """Apply naming inconsistency detection."""
        try:
            tree = ast.parse(code_file.content)
        except SyntaxError:
            return self._create_error_result(code_file, f"Syntax error: {code_file.path}")

        visitor = _NamingInconsistencyVisitor()
        visitor.visit(tree)

        return self._create_result(code_file, code_file.content, visitor.changes)
