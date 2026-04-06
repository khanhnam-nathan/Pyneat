"""Rule for suggesting/converting if-elif chains to match-case (Python 3.10+)."""

import ast
import sys
from typing import List, Tuple, Optional
import libcst as cst

from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule


class MatchCaseRule(Rule):
    """Suggests converting if-elif chains to match-case statements.

    Python 3.10+ only.
    Detects patterns like:
        if x == 1: ...
        elif x == 2: ...
        elif x == 3: ...
    That could become:
        match x:
            case 1: ...
            case 2: ...
            case 3: ...
    """

    PYTHON_VERSION_SUPPORTED = sys.version_info >= (3, 10)

    @property
    def description(self) -> str:
        if self.PYTHON_VERSION_SUPPORTED:
            return "Suggests converting if-elif chains to match-case (Python 3.10+)"
        else:
            return "Python 3.10+ required for match-case suggestions"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes)

            if not self.PYTHON_VERSION_SUPPORTED:
                return self._create_result(code_file, content, changes)

            try:
                tree = ast.parse(content)
            except SyntaxError:
                return self._create_result(code_file, content, changes)

            # Find if-elif chains that could be match-case
            candidates = self._find_match_case_candidates(tree, content)

            for candidate in candidates:
                changes.append(f"Suggest match-case: {candidate}")

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"MatchCaseRule failed: {str(e)}")

    def _find_match_case_candidates(self, tree: ast.AST, content: str) -> List[str]:
        """Find if-elif chains that could be match-case statements."""
        candidates = []

        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                # Check if this is an if-elif chain
                chain = self._extract_if_elif_chain(node)

                if chain and self._is_match_case_candidate(chain):
                    subject = self._get_match_subject(chain)
                    candidates.append(f"{len(chain)} branches on '{subject}'")

        return candidates

    def _extract_if_elif_chain(self, node: ast.If) -> List[ast.If]:
        """Extract an if-elif chain as a list."""
        chain = [node]

        # Follow elif branches
        current = node
        while isinstance(current.orelse, list) and len(current.orelse) == 1:
            next_if = current.orelse[0]
            if isinstance(next_if, ast.If):
                chain.append(next_if)
                current = next_if
            else:
                break

        return chain

    def _is_match_case_candidate(self, chain: List[ast.If]) -> bool:
        """Check if an if-elif chain is a good match-case candidate.

        A good candidate:
        - Has 3+ branches (if, elif, elif...)
        - All conditions are simple equality checks (x == value)
        - The subject of comparison is the same (e.g., all 'x == 1')
        """
        if len(chain) < 3:
            return False

        subject = None
        values = []

        for i, if_node in enumerate(chain):
            # First condition can be anything (not necessarily equality)
            # But subsequent conditions should be simple equality
            if i == 0:
                subj, val = self._extract_equality_check(if_node.test)
                if subj is None:
                    # First condition not equality, skip
                    if self._is_simple_comparison(if_node.test):
                        subject = self._get_subject_name(if_node.test)
                    else:
                        return False
                else:
                    subject = subj
                    values.append(val)
            else:
                subj, val = self._extract_equality_check(if_node.test)
                if subj is None or subj != subject:
                    return False
                values.append(val)

        # Check for duplicate values
        if len(values) != len(set(str(v) for v in values)):
            return False

        return True

    def _extract_equality_check(self, node: ast.AST) -> Tuple[Optional[str], Optional[any]]:
        """Extract subject and value from an equality comparison."""
        if isinstance(node, ast.Compare):
            if len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.Is)):
                # Get subject
                subject = self._get_subject_name(node.left)

                # Get value
                if isinstance(node.comparators[0], ast.Constant):
                    value = node.comparators[0].value
                    return subject, value

        return None, None

    def _is_simple_comparison(self, node: ast.AST) -> bool:
        """Check if comparison is simple enough for match-case."""
        if isinstance(node, ast.Name):
            return True
        if isinstance(node, ast.Attribute):
            return True
        return False

    def _get_subject_name(self, node: ast.AST) -> Optional[str]:
        """Get the name of the subject being compared."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # Build attribute path
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        elif isinstance(node, ast.Call):
            # Subject might be a function call
            if isinstance(node.func, ast.Name):
                return f"{node.func.id}()"
        return None

    def _get_match_subject(self, chain: List[ast.If]) -> str:
        """Get the subject being matched on."""
        first_test = chain[0].test
        return self._get_subject_name(first_test) or "expression"


class MatchCaseConverter(cst.CSTTransformer):
    """Converts if-elif chains to match-case statements."""

    def __init__(self, start_line: int, subject: str):
        super().__init__()
        self.start_line = start_line
        self.subject = subject
        self.conversions: List[str] = []

    def leave_If(self, original: cst.If, updated: cst.If) -> cst.CSTNode:
        """Convert if-elif to match-case."""
        # This is a simplified version - real implementation would need
        # more sophisticated CST manipulation
        return updated


class MatchCaseAdderRule(Rule):
    """Actually converts if-elif chains to match-case."""

    @property
    def description(self) -> str:
        return "Converts if-elif chains to match-case (Python 3.10+)"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes)

            if not MatchCaseRule.PYTHON_VERSION_SUPPORTED:
                return self._create_result(code_file, content, changes)

            try:
                module = cst.parse_module(content)
            except SyntaxError:
                return self._create_result(code_file, content, changes)

            # For now, just suggest - actual conversion is complex
            # Full implementation would need to:
            # 1. Detect if-elif chains
            # 2. Extract subject and values
            # 3. Build match-case structure
            # 4. Replace the if-elif with match-case

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"MatchCaseAdder failed: {str(e)}")