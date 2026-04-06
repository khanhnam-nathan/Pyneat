"""Rule for suggesting @dataclass decorator for simple classes."""

import ast
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

            try:
                tree = ast.parse(content)
            except SyntaxError:
                return self._create_result(code_file, content, changes)

            # Find classes that could be dataclasses
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
                # Skip private classes
                if node.name.startswith('_'):
                    continue

                # Skip classes that already have dataclass or other decorators
                if any(self._has_dataclass_or_typed_decorator(d) for d in node.decorator_list):
                    continue

                # Analyze the class
                analysis = self._analyze_class(node)

                if analysis['score'] >= 7:  # Threshold for suggestion
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
                # Type-annotated assignment = attribute
                analysis['attributes'].append(item)
                analysis['score'] += 2
            elif isinstance(item, ast.Assign):
                # Unannotated assignment = possible attribute
                analysis['attributes'].append(item)
                analysis['score'] += 1
            elif isinstance(item, ast.FunctionDef):
                analysis['methods'].append(item)

                if item.name == '__init__':
                    analysis['has_init'] = True
                    # Check if init is simple (just assigns parameters)
                    if self._is_simple_init(item):
                        analysis['score'] += 3
                elif item.name == '__repr__':
                    analysis['has_repr'] = True
                elif item.name == '__eq__':
                    analysis['has_eq'] = True
                elif item.name == '__str__':
                    analysis['has_str'] = True
                elif item.name.startswith('__') and item.name.endswith('__'):
                    pass  # Skip dunder methods
                else:
                    # Non-dunder method suggests it's not a simple data class
                    analysis['complex_methods'] += 1
                    analysis['score'] -= 2

        return analysis

    def _is_simple_init(self, node: ast.FunctionDef) -> bool:
        """Check if __init__ is simple (just parameter assignments)."""
        if len(node.args.args) == 0:
            return False

        # Count assignments in body
        assign_count = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                assign_count += 1
            elif isinstance(child, ast.Expr) and isinstance(child.value, ast.Call):
                # Allow method calls like self._init()
                pass

        # Simple init: number of assigns roughly matches number of args
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


class DataclassAdder(cst.CSTTransformer):
    """LibCST transformer to add @dataclass decorator."""

    def __init__(self, class_names: List[str]):
        super().__init__()
        self.class_names = set(class_names)
        self.conversions: List[str] = []

    def leave_ClassDef(self, original: cst.ClassDef, updated: cst.ClassDef) -> cst.ClassDef:
        """Add @dataclass decorator to target classes."""
        if original.name.value in self.class_names:
            # Check if already has @dataclass
            has_dataclass = any(
                self._is_dataclass_decorator(d)
                for d in updated.decorator_list
            )

            if not has_dataclass:
                # Add @dataclass decorator
                new_decorator = cst.Decorator(
                    decorator=cst.Name(value='dataclass')
                )
                new_decorators = [new_decorator] + list(updated.decorator_list)
                self.conversions.append(f"Added @dataclass to {original.name.value}")

                return updated.with_changes(decorator_list=new_decorators)

        return updated

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


class DataclassAdderRule(Rule):
    """Actually adds @dataclass decorator to appropriate classes."""

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
            except SyntaxError:
                return self._create_result(code_file, content, changes)

            # Find candidates
            candidates = self._find_candidates(tree)
            if not candidates:
                return self._create_result(code_file, content, changes)

            # Apply transformation using LibCST
            try:
                module = cst.parse_module(content)
                transformer = DataclassAdder([name for name, _, _ in candidates])
                new_module = module.visit(transformer)

                if transformer.conversions:
                    changes.extend(transformer.conversions)
                    content = new_module.code
            except Exception:
                pass

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"DataclassAdder failed: {str(e)}")

    def _find_candidates(self, tree: ast.AST) -> List[Tuple[str, int, Optional[str]]]:
        """Find classes that should be dataclasses."""
        rule = DataclassSuggestionRule()
        return rule._find_dataclass_candidates(tree, "")