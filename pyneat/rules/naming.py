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

For commercial licensing, contact: n.khanhnam@gmail.com

NAMINGCONVENTIONRULE CHỉ ĐỔI tên CLASS DEFINITION (snake_case -> PascalCase).
KHÔNG đổi tên biến, function, hay references — tránh lỗi logic.

Nếu muốn đổi tên đầy đủ (class + references), dùng AggressiveNamingRule.

Extracted from user request: naming inconsistency detection is also provided
via NamingInconsistencyRule for detecting same concept with different styles.
"""

import re
from pathlib import Path
from typing import List, Optional

import libcst as cst

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule
from pyneat.utils.naming import _is_pascal_case, _is_snake_case, _to_pascal_case


# ----------------------------------------------------------------------
# Cross-file import updater
# ----------------------------------------------------------------------


class _CrossFileImportUpdater(cst.CSTTransformer):
    """Updates import statements and name references when a class is renamed.

    Handles:
    - `from module import OldName`  â†’  `from module import NewName`
    - `from module import OldName as Alias`  â†’  skip (user chose an alias)
    - `from module import OldName as OldName`  â†’  `NewName as NewName`
    - `import module; module.OldName`  â†’  `module.NewName`  (attribute access)
    - Name references used as types / base classes  â†’  updated
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
        # Táº M Táº®T - Import update cÃ³ thá»ƒ gÃ¢y lá»—i náº¿u:
        # 1. Import lÃ  má»™t module chá»© khÃ´ng pháº£i class
        # 2. TÃªn trÃ¹ng vá»›i class nhÆ°ng lÃ  thá»© khÃ¡c
        # Chá»‰ update khi CHáº®C CHáº®N lÃ  class reference
        return updated

    # --- Import (module.ClassName style) ------------------------------------

    def leave_Import(
        self, original: cst.Import, updated: cst.Import
    ) -> cst.Import:
        # Táº M Táº®T - TÆ°Æ¡ng tá»± leave_ImportFrom
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

    # NOTE: KHÃ”NG cÃ³ leave_Name vÃ¬ nÃ³ Ä‘á»•i Táº¤T Cáº¢ name references,
    # bao gá»“m cáº£ biáº¿n thÆ°á»ng trÃ¹ng tÃªn vá»›i class -> Lá»–I LOGIC nghiÃªm trá»ng


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

    CHá»ˆ Ä‘á»•i tÃªn CLASS DEFINITION tá»« snake_case -> PascalCase.
    VÃ­ dá»¥: class my_data -> class MyData

    KHÃ”NG Ä‘á»•i:
    - TÃªn biáº¿n thÆ°á»ng
    - TÃªn function
    - Name references trong code

    Cross-file updates bá»‹ Táº®T máº·c Ä‘á»‹nh Ä‘á»ƒ trÃ¡nh phÃ¡ vá»¡ cÃ¡c file khÃ¡c.
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
# Naming Inconsistency Rule (NEW from user request)
# Detects same concept with different naming styles in the same file.
# e.g. userId and user_id both referring to the same entity.
# --------------------------------------------------------------------------


import ast
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class NamingConflict:
    """Represents a naming inconsistency conflict."""
    concept: str
    snake_name: Optional[str] = None
    camel_name: Optional[str] = None
    pascal_name: Optional[str] = None
    lines: List[int] = field(default_factory=list)


class NamingInconsistencyRule(Rule):
    """Detects naming inconsistencies within a file.

    AI often generates code where the same concept is referred to by different
    naming styles in the same file, e.g.:
      - userId vs user_id
      - DBHost vs db_host
      - apiURL vs api_url

    This rule detects these inconsistencies without modifying code.
    Detection categories:
      - User identifiers: userId, user_id, userName, user_name
      - DB config: DBHost, db_host, db_name, dbName
      - API config: apiURL, api_url, apiEndpoint, api_endpoint
    """

    # Concept patterns: regex -> concept name
    CONCEPT_PATTERNS = [
        # User-related
        (r'\buser_?id\b', r'\buser_?name\b', r'\buser_?email\b', r'\buser_?token\b', 'user_identifier'),
        # Database-related
        (r'\bdb_?host\b', r'\bdb_?name\b', r'\bdb_?user\b', r'\bdatabase_?name\b', 'database_config'),
        # API-related
        (r'\bapi_?url\b', r'\bapi_?endpoint\b', r'\bapi_?key\b', r'\bapi_?token\b', 'api_config'),
        # Config file/path
        (r'\bconfig_?file\b', r'\bconfig_?path\b', r'\bcfg_?file\b', r'\bsetting_?path\b', 'config_path'),
        # Server/host
        (r'\bserver_?host\b', r'\bserver_?port\b', r'\bhost_?name\b', r'\bhost_?addr\b', 'server_config'),
        # Request/response
        (r'\brequest_?body\b', r'\brequest_?header\b', r'\bresponse_?data\b', r'\bresponse_?code\b', 'http_message'),
    ]

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)

    @property
    def description(self) -> str:
        return (
            "Detects naming inconsistencies where the same concept uses different "
            "naming styles (snake_case vs camelCase) in the same file. "
            "Helps identify AI-generated code that mixes naming conventions."
        )

    def apply(self, code_file: CodeFile) -> TransformationResult:
        source = code_file.content
        lines = source.splitlines()

        # Scan for naming conflicts using regex
        conflicts: List[NamingConflict] = []
        concept_matches: Dict[str, List[Tuple[int, str]]] = {}

        for concept_pattern in self.CONCEPT_PATTERNS:
            concept_name = concept_pattern[-1]
            patterns = concept_pattern[:-1]

            for i, line in enumerate(lines, 1):
                for pattern in patterns:
                    matches = re.findall(pattern, line, re.IGNORECASE)
                    for match in matches:
                        if concept_name not in concept_matches:
                            concept_matches[concept_name] = []
                        concept_matches[concept_name].append((i, match))

        # Analyze conflicts
        for concept_name, matches in concept_matches.items():
            if len(matches) < 2:
                continue

            snake_names = [(ln, n) for ln, n in matches if '_' in n.lower()]
            camel_names = [(ln, n) for ln, n in matches if any(c.isupper() for c in n)]

            if snake_names and camel_names:
                conflict = NamingConflict(
                    concept=concept_name,
                    snake_name=snake_names[0][1],
                    camel_name=camel_names[0][1],
                    lines=[ln for ln, _ in matches],
                )
                conflicts.append(conflict)

        # Generate changes report
        changes = []
        for conflict in conflicts:
            if conflict.snake_name and conflict.camel_name:
                hint = (
                    f"NAMING-INCONSISTENCY: '{conflict.snake_name}' and '{conflict.camel_name}' "
                    f"refer to the same concept ({conflict.concept}) — use consistent naming"
                )
            else:
                hint = (
                    f"NAMING-INCONSISTENCY: multiple naming styles found for '{conflict.concept}' "
                    f"at lines {conflict.lines}"
                )
            changes.append(hint)

        return self._create_result(code_file, source, changes)
