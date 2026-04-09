"""Rule for suggesting/converting if-elif chains to match-case (Python 3.10+).

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
import sys
import re
from typing import List, Tuple, Optional, Set
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
                # Use cached AST if available (RuleEngine pre-parses)
                if hasattr(code_file, 'ast_tree') and code_file.ast_tree is not None:
                    tree = code_file.ast_tree
                else:
                    tree = ast.parse(content)
            except SyntaxError:
                return self._create_result(code_file, content, changes)

            candidates = self._find_match_case_candidates(tree, content)

            for candidate in candidates:
                changes.append(f"Suggest match-case: {candidate}")

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"MatchCaseRule failed: {str(e)}")

    def _find_match_case_candidates(self, tree: ast.AST, content: str) -> List[str]:
        candidates = []
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                chain = self._extract_if_elif_chain(node)
                if chain and self._is_match_case_candidate(chain):
                    subject = self._get_match_subject(chain)
                    candidates.append(f"{len(chain)} branches on '{subject}'")
        return candidates

    def _extract_if_elif_chain(self, node: ast.If) -> List[ast.If]:
        chain = [node]
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
        if len(chain) < 3:
            return False
        subject = None
        values = []
        for i, if_node in enumerate(chain):
            if i == 0:
                subj, val = self._extract_equality_check(if_node.test)
                if subj is None:
                    if not isinstance(if_node.test, (ast.Name, ast.Attribute)):
                        return False
                    subject = self._get_subject_name(if_node.test)
                else:
                    subject = subj
                    values.append(val)
            else:
                subj, val = self._extract_equality_check(if_node.test)
                if subj is None or subj != subject:
                    return False
                values.append(val)
        if len(values) != len(set(str(v) for v in values)):
            return False
        return True

    def _extract_equality_check(self, node: ast.AST) -> Tuple[Optional[str], Optional[any]]:
        if isinstance(node, ast.Compare):
            if len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.Is)):
                subject = self._get_subject_name(node.left)
                if isinstance(node.comparators[0], ast.Constant):
                    return subject, node.comparators[0].value
        return None, None

    def _get_subject_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return f"{node.func.id}()"
        elif isinstance(node, ast.Compare):
            return self._get_subject_name(node.left)
        return None

    def _get_match_subject(self, chain: List[ast.If]) -> str:
        first_test = chain[0].test
        return self._get_subject_name(first_test) or "expression"


# ----------------------------------------------------------------------
# MatchCaseAdderRule — actual conversion
# ----------------------------------------------------------------------


class MatchCaseAdderRule(Rule):
    """Actually converts if-elif chains to match-case (Python 3.10+)."""

    PYTHON_VERSION_SUPPORTED = sys.version_info >= (3, 10)

    @property
    def description(self) -> str:
        return "Converts if-elif chains to match-case (Python 3.10+)"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes: List[str] = []
            content = code_file.content

            if not content.strip():
                return self._create_result(code_file, content, changes)

            if not self.PYTHON_VERSION_SUPPORTED:
                return self._create_result(code_file, content, changes)

            try:
                # Use cached AST if available (RuleEngine pre-parses)
                if hasattr(code_file, 'ast_tree') and code_file.ast_tree is not None:
                    tree = code_file.ast_tree
                else:
                    tree = ast.parse(content)
            except SyntaxError as e:
                return self._create_error_result(code_file, f"Syntax error: {e}")

            chains = self._find_all_chains(tree)
            if not chains:
                return self._create_result(code_file, content, changes)

            try:
                new_content = self._apply_conversions(content, chains)
                if new_content != content:
                    for chain_data in chains:
                        subject = chain_data['subject']
                        count = len(chain_data['chain'])
                        changes.append(
                            f"Converted if-elif chain to match-case on '{subject}' ({count} branches)"
                        )
                    content = new_content
            except Exception as e:
                return self._create_error_result(
                    code_file, f"MatchCase conversion failed: {e}"
                )

            return self._create_result(code_file, content, changes)

        except Exception as e:
            return self._create_error_result(code_file, f"MatchCaseAdder failed: {str(e)}")

    def _find_all_chains(self, tree: ast.AST) -> List[dict]:
        chains = []
        seen_starts: Set[int] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                if node.lineno in seen_starts:
                    continue
                chain = self._extract_chain(node)
                if chain and len(chain) >= 3 and self._is_good_candidate(chain):
                    seen_starts.add(chain[0].lineno)
                    subject_name = self._get_subject(chain)
                    chains.append({
                        'chain': chain,
                        'subject': subject_name,
                        'start_line': chain[0].lineno,
                        'end_line': chain[-1].end_lineno,
                    })

        chains.sort(key=lambda c: c['start_line'])
        return chains

    def _extract_chain(self, node: ast.If) -> List[ast.If]:
        chain = [node]
        current = node
        while isinstance(current.orelse, list) and len(current.orelse) == 1:
            next_if = current.orelse[0]
            if isinstance(next_if, ast.If):
                chain.append(next_if)
                current = next_if
            else:
                break
        return chain

    def _is_good_candidate(self, chain: List[ast.If]) -> bool:
        if len(chain) < 3:
            return False
        subject = None
        values = []
        for i, if_node in enumerate(chain):
            if i == 0:
                subj, val = self._extract_equality(if_node.test)
                if subj is None:
                    if not isinstance(if_node.test, (ast.Name, ast.Attribute)):
                        return False
                    subject = self._get_subject_name(if_node.test)
                else:
                    subject = subj
                    values.append(val)
            else:
                subj, val = self._extract_equality(if_node.test)
                if subj is None or subj != subject:
                    return False
                values.append(val)
        if len(values) != len(set(str(v) for v in values)):
            return False
        return True

    def _extract_equality(self, node: ast.AST) -> Tuple[Optional[str], Optional[any]]:
        if isinstance(node, ast.Compare):
            if len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.Is)):
                subj = self._get_subject_name(node.left)
                if isinstance(node.comparators[0], ast.Constant):
                    return subj, node.comparators[0].value
        return None, None

    def _get_subject(self, chain: List[ast.If]) -> str:
        return self._get_subject_name(chain[0].test) or "x"

    def _get_subject_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return f"{node.func.id}()"
        elif isinstance(node, ast.Compare):
            return self._get_subject_name(node.left)
        return None

    def _apply_conversions(self, content: str, chains: List[dict]) -> str:
        """Apply all chain-to-match conversions to the source content."""
        lines = content.splitlines(keepends=True)

        offset = 0
        for chain_data in chains:
            start_line = chain_data['start_line'] - 1
            end_line = chain_data['end_line']
            subject = chain_data['subject']
            ast_chain = chain_data['chain']

            block_lines = lines[start_line:end_line]
            if not block_lines:
                continue

            match_code = self._build_match_block(subject, ast_chain, block_lines[0])

            new_lines = lines[:start_line] + [match_code + '\n'] + lines[end_line:]
            lines = new_lines

        return ''.join(lines)

    def _build_match_block(
        self, subject: str, ast_chain: List[ast.If], first_line: str
    ) -> str:
        """Build the match-case block with correct indentation."""
        indent = first_line[:len(first_line) - len(first_line.lstrip())]

        import ast as _ast

        lines = [f"{indent}match {subject}:"]

        for ast_if in ast_chain:
            test = ast_if.test

            if isinstance(test, ast.Compare) and len(test.comparators) == 1:
                comp = test.comparators[0]
                if isinstance(comp, ast.Constant):
                    val = comp.value
                    if val is None:
                        pattern_str = "None"
                    elif val is True:
                        pattern_str = "True"
                    elif val is False:
                        pattern_str = "False"
                    elif isinstance(val, str):
                        pattern_str = repr(val)
                    else:
                        pattern_str = repr(val)
                else:
                    pattern_str = "_"
            else:
                pattern_str = "_"

            lines.append(f"{indent}    case {pattern_str}:")

            body = ast_if.body
            if body:
                for stmt in body:
                    try:
                        src = _ast.unparse(stmt)
                        lines.append(f"{indent}        {src}")
                    except Exception:
                        lines.append(f"{indent}        pass")
            else:
                lines.append(f"{indent}        pass")

        return '\n'.join(lines)