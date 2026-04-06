"""Rule for fixing 'for i in range(len(items)): item = items[i]' anti-pattern."""

from typing import List, Optional, Tuple

import libcst as cst

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class RangeLenRule(Rule):
    """Fixes range(len()) anti-pattern.

    Converts:
      - for i in range(len(items)): item = items[i]  ->  for item in items:
      - for i in range(len(items)): x = items[i]      ->  for x in items:
      - for i in range(len(items)): print(items[i])    ->  for item in items: print(item)
    """

    @property
    def description(self) -> str:
        return "Fixes range(len()) anti-pattern with direct iteration"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            content = code_file.content

            try:
                tree = cst.parse_module(content)
            except Exception:
                return self._create_result(code_file, content, [])

            transformer = _RangeLenTransformer()
            new_tree = tree.visit(transformer)
            new_content = new_tree.code

            if transformer.changes:
                return self._create_result(code_file, new_content, transformer.changes)
            return self._create_result(code_file, content, [])

        except Exception as e:
            return self._create_error_result(
                code_file, f"RangeLenRule failed: {str(e)}"
            )


# ----------------------------------------------------------------------
# LibCST Transformer
# ----------------------------------------------------------------------


class _RangeLenTransformer(cst.CSTTransformer):
    """Transformer that fixes range(len()) patterns."""

    def __init__(self):
        super().__init__()
        self.changes: List[str] = []

    def leave_For(self, original: cst.For, updated: cst.For) -> cst.BaseStatement:
        """Transform for loops using range(len())."""
        iter_node = updated.iter
        if not isinstance(iter_node, cst.Call):
            return updated

        if not self._is_range_call(iter_node):
            return updated

        args = iter_node.args
        if len(args) != 1:
            return updated

        len_arg = args[0].value
        if not isinstance(len_arg, cst.Call):
            return updated

        if not isinstance(len_arg.func, cst.Name):
            return updated
        if len_arg.func.value != 'len':
            return updated
        if len(len_arg.args) != 1:
            return updated

        iterable_arg = len_arg.args[0].value
        if not isinstance(iterable_arg, cst.Name):
            return updated

        iterable_name = iterable_arg.value
        target = updated.target

        if not isinstance(target, cst.Name):
            return updated

        index_var = target.value

        item_var, subscript_to_remove = self._find_item_assignment(updated.body.body, iterable_name, index_var)

        if item_var is None:
            return updated

        new_target = cst.Name(item_var)
        new_iter = cst.Name(iterable_name)

        new_body = self._remove_subscript_assignment(updated.body, subscript_to_remove)

        replacer = _SubscriptReplacer(iterable_name, index_var, item_var)
        new_body = [stmt.visit(replacer) for stmt in new_body]

        new_for = cst.For(
            target=new_target,
            iter=new_iter,
            body=cst.IndentedBlock(body=new_body),
            orelse=updated.orelse,
        )

        self.changes.append(f"Fixed range(len()) -> for {item_var} in {iterable_name}:")
        return new_for

    def _is_range_call(self, node: cst.Call) -> bool:
        """Check if node is a call to range()."""
        if isinstance(node.func, cst.Name):
            return node.func.value == 'range'
        return False

    def _find_item_assignment(
        self,
        body: List[cst.BaseStatement],
        iterable_name: str,
        index_var: str,
    ) -> Tuple[Optional[str], Optional[int]]:
        """Find pattern: var_name = iterable[index] and return (var_name, line_index)."""
        for idx, stmt in enumerate(body):
            if isinstance(stmt, cst.SimpleStatementLine):
                for expr in stmt.body:
                    if isinstance(expr, cst.Assign) and len(expr.targets) == 1:
                        target = expr.targets[0].target
                        value = expr.value

                        if isinstance(target, cst.Name) and isinstance(value, cst.Subscript):
                            sub_value = value.value
                            if isinstance(sub_value, cst.Name) and sub_value.value == iterable_name:
                                if len(value.slice) == 1:
                                    slice_val = value.slice[0].slice
                                    if isinstance(slice_val, cst.Index):
                                        idx_expr = slice_val.value
                                        if isinstance(idx_expr, cst.Name) and idx_expr.value == index_var:
                                            return (target.value, idx)

        return (None, None)

    def _remove_subscript_assignment(self, body: cst.IndentedBlock, subscript_idx: Optional[int]) -> List[cst.BaseStatement]:
        """Remove the subscript assignment line from body and return a list."""
        if subscript_idx is None:
            return list(body.body)

        new_body = []
        for idx, stmt in enumerate(body.body):
            if idx != subscript_idx:
                new_body.append(stmt)

        return new_body


class _SubscriptReplacer(cst.CSTTransformer):
    """Replace remaining items[i] with item_var in expressions."""

    def __init__(self, iterable_name: str, index_var: str, item_var: str):
        super().__init__()
        self.iterable_name = iterable_name
        self.index_var = index_var
        self.item_var = item_var

    def leave_Subscript(self, original: cst.Subscript, updated: cst.Subscript) -> cst.BaseExpression:
        """Replace items[index] -> item_var."""
        sub_value = updated.value
        if not isinstance(sub_value, cst.Name):
            return updated
        if sub_value.value != self.iterable_name:
            return updated

        if len(updated.slice) != 1:
            return updated
        slice_val = updated.slice[0].slice
        if not isinstance(slice_val, cst.Index):
            return updated
        idx_expr = slice_val.value
        if not isinstance(idx_expr, cst.Name):
            return updated
        if idx_expr.value != self.index_var:
            return updated

        return cst.Name(self.item_var)
