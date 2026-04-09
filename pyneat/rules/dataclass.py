"""Rule for suggesting @dataclass decorator for simple classes.

Copyright (c) 2024-2026 PyNEAT Authors

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

For commercial licensing, contact: license@pyneat.dev
"""

import ast
import re
from typing import List, Tuple, Optional
import libcst as cst

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class DataclassSuggestionRule(Rule):
    """Suggests @dataclass decorator for simple classes.

    Detects classes that:
    - Have only __init__ method
    - Have mostly data attributes (no complex methods)
    - Could benefit from @dataclass for cleaner code
    """

    @property
    def description(self) -> str:
        return "Suggests @dataclass for simple data classes"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes)

            # Use cached AST if available (RuleEngine pre-parses)
            if hasattr(code_file, 'ast_tree') and code_file.ast_tree is not None:
                tree = code_file.ast_tree
            else:
                try:
                    tree = ast.parse(content)
                except SyntaxError:
                    return self._create_result(code_file, content, changes)

            candidates = self._find_dataclass_candidates(tree, content)

            for class_name, line_no, reason in candidates:
                if reason:
                    changes.append(f"Suggest @dataclass: {class_name} ({reason}) at line {line_no}")
                else:
                    changes.append(f"Suggest @dataclass: {class_name} at line {line_no}")

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"DataclassSuggestion failed: {str(e)}")

    def _find_dataclass_candidates(
        self, tree: ast.AST, content: str
    ) -> List[Tuple[str, int, Optional[str]]]:
        """Find classes that could be dataclasses."""
        candidates = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if node.name.startswith('_'):
                    continue

                if any(self._has_dataclass_or_typed_decorator(d) for d in node.decorator_list):
                    continue

                analysis = self._analyze_class(node)

                if analysis['score'] >= 7:
                    reason = self._get_suggestion_reason(analysis)
                    candidates.append((node.name, node.lineno, reason))

        return candidates

    def _has_dataclass_or_typed_decorator(self, node: ast.AST) -> bool:
        """Check if decorator suggests it's already a dataclass or similar."""
        if isinstance(node, ast.Name):
            return node.id in ('dataclass', 'attrs', 'Attrib', 'pydantic')
        elif isinstance(node, ast.Attribute):
            if node.attr in ('dataclass', 'define', 'model'):
                return True
        elif isinstance(node, ast.Call):
            return self._has_dataclass_or_typed_decorator(node.func)
        return False

    def _analyze_class(self, node: ast.ClassDef) -> dict:
        """Analyze a class to determine if it should be a dataclass."""
        analysis = {
            'attributes': [],
            'methods': [],
            'has_init': False,
            'has_repr': False,
            'has_eq': False,
            'has_str': False,
            'complex_methods': 0,
            'score': 0,
        }

        for item in node.body:
            if isinstance(item, ast.AnnAssign):
                analysis['attributes'].append(item)
                analysis['score'] += 2
            elif isinstance(item, ast.Assign):
                analysis['attributes'].append(item)
                analysis['score'] += 1
            elif isinstance(item, ast.FunctionDef):
                analysis['methods'].append(item)

                if item.name == '__init__':
                    analysis['has_init'] = True
                    if self._is_simple_init(item):
                        analysis['score'] += 3
                elif item.name == '__repr__':
                    analysis['has_repr'] = True
                elif item.name == '__eq__':
                    analysis['has_eq'] = True
                elif item.name == '__str__':
                    analysis['has_str'] = True
                elif item.name.startswith('__') and item.name.endswith('__'):
                    pass
                else:
                    analysis['complex_methods'] += 1
                    analysis['score'] -= 2

        return analysis

    def _is_simple_init(self, node: ast.FunctionDef) -> bool:
        """Check if __init__ is simple (just parameter assignments)."""
        if len(node.args.args) == 0:
            return False

        assign_count = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                assign_count += 1
            elif isinstance(child, ast.Expr) and isinstance(child.value, ast.Call):
                pass

        return assign_count >= len(node.args.args) * 0.5

    def _get_suggestion_reason(self, analysis: dict) -> Optional[str]:
        """Get human-readable reason for suggestion."""
        if analysis['complex_methods'] > 0:
            return "has methods"

        if len(analysis['attributes']) >= 3:
            attr_count = len(analysis['attributes'])
            has_init = "with __init__" if analysis['has_init'] else "no __init__"
            return f"{attr_count} attrs, {has_init}"

        if analysis['has_init'] and len(analysis['attributes']) >= 2:
            return "simple init with attrs"

        return "candidate for dataclass"


# ----------------------------------------------------------------------
# LibCST Transformer
# ----------------------------------------------------------------------


class DataclassAdder(cst.CSTTransformer):
    """LibCST transformer to add @dataclass decorator."""

    def __init__(self, class_names: List[str]):
        super().__init__()
        self.class_names = set(class_names)
        self.conversions: List[str] = []
        self._needs_dataclass_import = False

    def leave_ClassDef(self, original: cst.ClassDef, updated: cst.ClassDef) -> cst.ClassDef:
        """Add @dataclass decorator to target classes."""
        if original.name.value not in self.class_names:
            return updated

        has_dataclass = any(
            self._is_dataclass_decorator(d)
            for d in updated.decorators
        )

        if has_dataclass:
            return updated

        new_decorator = cst.Decorator(
            decorator=cst.Name(value='dataclass')
        )
        new_decorators = [new_decorator] + list(updated.decorators)
        self.conversions.append(f"Added @dataclass to {original.name.value}")
        self._needs_dataclass_import = True

        return updated.with_changes(decorators=new_decorators)

    def _is_dataclass_decorator(self, node: cst.CSTNode) -> bool:
        """Check if decorator is @dataclass or similar."""
        if isinstance(node, cst.Decorator):
            decorator = node.decorator
            if isinstance(decorator, cst.Name):
                return decorator.value == 'dataclass'
            elif isinstance(decorator, cst.Call):
                if isinstance(decorator.func, cst.Name):
                    return decorator.func.value == 'dataclass'
        return False


# ----------------------------------------------------------------------
# DataclassAdderRule — actual conversion
# ----------------------------------------------------------------------


class DataclassAdderRule(Rule):
    """Actually adds @dataclass decorator to appropriate classes.

    Also ensures 'from dataclasses import dataclass' is present when adding
    the decorator to a class that doesn't already import it.
    """

    @property
    def description(self) -> str:
        return "Adds @dataclass decorator to appropriate classes"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes)

            try:
                tree = ast.parse(content)
            except SyntaxError as e:
                return self._create_error_result(code_file, f"Syntax error: {e}")

            candidates = self._find_candidates(tree)
            if not candidates:
                return self._create_result(code_file, content, changes)

            module = cst.parse_module(content)
            transformer = DataclassAdder([name for name, _, _ in candidates])
            new_module = module.visit(transformer)

            if not transformer.conversions:
                return self._create_result(code_file, content, changes)

            content = new_module.code

            if transformer._needs_dataclass_import:
                content = self._ensure_dataclass_import(content)

            changes.extend(transformer.conversions)

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"DataclassAdder failed: {str(e)}")

    def _find_candidates(self, tree: ast.AST) -> List[Tuple[str, int, Optional[str]]]:
        """Find classes that should be dataclasses."""
        rule = DataclassSuggestionRule()
        return rule._find_dataclass_candidates(tree, "")

    def _ensure_dataclass_import(self, content: str) -> str:
        """Add 'from dataclasses import dataclass' if not already present."""
        has_import = bool(
            re.search(r'from\s+dataclasses\s+import\s+.*\bdataclass\b', content) or
            re.search(r'import\s+dataclasses\b', content)
        )
        if has_import:
            return content

        has_from_dataclasses = re.search(r'from\s+dataclasses\s+import', content)
        if has_from_dataclasses:
            return re.sub(
                r'(from\s+dataclasses\s+import\s+)([^\n]+)',
                r'\1dataclass, \2',
                content,
                count=1
            )

        lines = content.splitlines(keepends=True)
        import_line = "from dataclasses import dataclass\n"

        insert_at = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                if stripped.startswith(('"', "'")):
                    continue
                insert_at = i
                break

        lines.insert(insert_at, import_line)
        return ''.join(lines)