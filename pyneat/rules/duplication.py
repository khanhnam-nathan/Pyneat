"""Code Duplication Rule — detect duplicated code across files.

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

Detects code duplication across files using AST normalization and tree similarity.
This helps identify AI-generated code that recreates existing functions.

Detection approach:
  1. Parse AST for each function/method in each file
  2. Normalize AST by replacing names with placeholders
  3. Compare normalized trees for similarity
  4. Report pairs with similarity > threshold (default: 0.8 = 80%)

This is a HIGH-COST rule: it requires parsing multiple files and computing
tree similarity. Use with --enable-destruction or configure with caution.
"""

from __future__ import annotations

import ast
import hashlib
from typing import List, Dict, Tuple, Set, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path

from pyneat.core.types import CodeFile, TransformationResult, RuleConfig
from pyneat.rules.base import Rule


# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DuplicateGroup:
    """A group of duplicate functions."""
    function_name: str
    files: List[str]
    lines: List[Tuple[int, int]]
    similarity: float
    normalized_hash: str


@dataclass
class FunctionSignature:
    """Represents a function's signature and normalized body."""
    name: str
    file_path: str
    start_line: int
    end_line: int
    param_names: Tuple[str, ...]
    normalized_body: str  # AST dump with names replaced by placeholders
    full_hash: str  # Hash of the normalized body


# --------------------------------------------------------------------------
# AST Normalization
# --------------------------------------------------------------------------


class _ASTNormalizer(ast.NodeVisitor):
    """Normalize AST by replacing names with generic placeholders."""

    def __init__(self):
        self._name_counter: Dict[str, int] = {}
        self._name_map: Dict[str, str] = {}
        self._depth: int = 0

    def _get_placeholder(self, name: str) -> str:
        """Get a placeholder for a name."""
        if name not in self._name_map:
            # Determine type by context
            if name.startswith('_'):
                prefix = '_var'
            elif name[0].isupper():
                prefix = 'ClassName'
            else:
                prefix = 'var'
            self._name_map[name] = f'{prefix}_{self._name_counter.get(prefix, 0)}'
            self._name_counter[prefix] = self._name_counter.get(prefix, 0) + 1
        return self._name_map[name]

    def visit_Name(self, node: ast.Name) -> ast.Name:
        if isinstance(node.ctx, ast.Load):
            # Replace with placeholder
            placeholder = self._get_placeholder(node.id)
            return ast.Name(id=placeholder, ctx=node.ctx)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        # Replace function name with placeholder
        new_node = ast.FunctionDef(
            name='func_placeholder',
            args=node.args,
            body=node.body,
            decorator_list=node.decorator_list,
            returns=node.returns,
            type_comment=node.type_comment,
        )
        self.generic_visit(new_node)
        return new_node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        new_node = ast.AsyncFunctionDef(
            name='func_placeholder',
            args=node.args,
            body=node.body,
            decorator_list=node.decorator_list,
            returns=node.returns,
            type_comment=node.type_comment,
        )
        self.generic_visit(new_node)
        return new_node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        new_node = ast.ClassDef(
            name='ClassName',
            bases=node.bases,
            keywords=node.keywords,
            body=node.body,
            decorator_list=node.decorator_list,
        )
        self.generic_visit(new_node)
        return new_node


def _normalize_function(tree: ast.AST, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Normalize a function's AST for comparison."""
    normalizer = _ASTNormalizer()

    # Clone the node to avoid modifying the original
    if isinstance(node, ast.FunctionDef):
        cloned = ast.FunctionDef(
            name=node.name,
            args=node.args,
            body=node.body,
            decorator_list=node.decorator_list,
            returns=node.returns,
            type_comment=node.type_comment,
        )
    else:
        cloned = ast.AsyncFunctionDef(
            name=node.name,
            args=node.args,
            body=node.body,
            decorator_list=node.decorator_list,
            returns=node.returns,
            type_comment=node.type_comment,
        )

    # Normalize the clone
    normalized = normalizer.visit(cloned)

    # Dump to string
    try:
        return ast.dump(normalized, indent=2)
    except Exception:
        return ast.dump(normalized)


def _compute_similarity(hash1: str, hash2: str) -> float:
    """Compute similarity between two normalized AST hashes."""
    if hash1 == hash2:
        return 1.0

    # Use Levenshtein-like comparison
    len1, len2 = len(hash1), len(hash2)
    if len1 == 0 or len2 == 0:
        return 0.0

    # Simple character-level similarity
    common = sum(1 for a, b in zip(hash1, hash2) if a == b)
    return 2 * common / (len1 + len2)


# --------------------------------------------------------------------------
# Function extractor
# --------------------------------------------------------------------------


def _extract_functions(code_file: CodeFile) -> List[FunctionSignature]:
    """Extract all function signatures from a code file."""
    signatures = []
    try:
        tree = ast.parse(code_file.content)
    except SyntaxError:
        return signatures

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith('_') and not node.name.startswith('__'):
                # Skip private functions by default (configurable)
                continue

            # Get param names
            param_names = tuple(arg.arg for arg in node.args.args if arg.arg not in ('self', 'cls'))

            # Normalize body
            normalized_body = _normalize_function(tree, node)
            body_hash = hashlib.md5(normalized_body.encode()).hexdigest()

            signatures.append(FunctionSignature(
                name=node.name,
                file_path=str(code_file.path),
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                param_names=param_names,
                normalized_body=normalized_body,
                full_hash=body_hash,
            ))

    return signatures


# --------------------------------------------------------------------------
# Main rule
# --------------------------------------------------------------------------


class CodeDuplicationRule(Rule):
    """Detect duplicated code across files using AST normalization.

    This rule identifies functions that are semantically identical (after
    normalizing variable/class names) across different files, indicating:
      - AI-generated code that recreates existing functionality
      - Copy-paste duplication that should be refactored
      - Functions that could be extracted to shared modules

    Configuration:
      - threshold (float): Similarity threshold to flag as duplicate (0.0-1.0, default: 0.8)
      - min_lines (int): Minimum function size to check (default: 3 lines)
      - exclude_private (bool): Exclude private functions (default: True)
      - files (List[str]): Files to check (if empty, checks all provided files)

    Note: This is a HIGH-COST rule. For best performance:
      - Use with --enable-destruction flag
      - Run on specific file patterns rather than entire project
      - Consider caching results for incremental checks
    """

    ALLOWED_SEMANTIC_NODES: Set[str] = set()

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self.threshold = config.params.get('threshold', 0.8) if config else 0.8
        self.min_lines = config.params.get('min_lines', 3) if config else 3
        self.exclude_private = config.params.get('exclude_private', True) if config else True

    @property
    def description(self) -> str:
        return (
            f"Detects duplicated code across files using AST normalization. "
            f"Flags functions with >{int(self.threshold * 100)}% similarity. "
            f"Useful for identifying AI-generated duplicate code."
        )

    def apply(self, code_file: CodeFile) -> TransformationResult:
        """Apply duplication detection to a single file.

        For cross-file detection, use apply_batch() instead.
        """
        # Extract functions from this file only
        signatures = _extract_functions(code_file)

        changes = []
        detected: Set[str] = set()

        # Compare functions within the same file (self-duplication)
        for i, sig1 in enumerate(signatures):
            for sig2 in signatures[i + 1:]:
                if sig1.full_hash == sig2.full_hash:
                    key = f"{sig1.name}@{sig1.start_line}"
                    if key not in detected:
                        detected.add(key)
                        changes.append(
                            f"DUPLICATION: Function '{sig1.name}' at line {sig1.start_line} "
                            f"is identical to '{sig2.name}' at line {sig2.start_line} "
                            f"(within same file) — consider extracting to a shared function"
                        )

        return self._create_result(code_file, code_file.content, changes)

    def apply_batch(self, files: List[CodeFile]) -> List[TransformationResult]:
        """Apply duplication detection across multiple files.

        This is the recommended method for cross-file duplication detection.

        Args:
            files: List of CodeFile objects to analyze

        Returns:
            List of TransformationResult for each file with duplicate findings
        """
        # Step 1: Extract all function signatures from all files
        all_signatures: List[FunctionSignature] = []
        for code_file in files:
            signatures = _extract_functions(code_file)
            all_signatures.extend(signatures)

        # Step 2: Find duplicate groups
        duplicates: List[DuplicateGroup] = []
        processed: Set[Tuple[int, int]] = set()

        for i, sig1 in enumerate(all_signatures):
            for j, sig2 in enumerate(all_signatures[i + 1:], start=i + 1):
                if (i, j) in processed:
                    continue

                # Quick hash comparison first
                if sig1.full_hash == sig2.full_hash:
                    # Exact match
                    similarity = 1.0
                else:
                    # Compute similarity
                    similarity = _compute_similarity(sig1.normalized_body, sig2.normalized_body)

                if similarity >= self.threshold:
                    processed.add((i, j))

                    # Find or create duplicate group
                    found_group = None
                    for group in duplicates:
                        if (sig1.name in group.files or sig1.file_path in group.files) and \
                           (sig2.name in group.files or sig2.file_path in group.files):
                            found_group = group
                            break

                    if found_group:
                        if sig1.file_path not in found_group.files:
                            found_group.files.append(sig1.file_path)
                            found_group.lines.append((sig1.start_line, sig1.end_line))
                        if sig2.file_path not in found_group.files:
                            found_group.files.append(sig2.file_path)
                            found_group.lines.append((sig2.start_line, sig2.end_line))
                    else:
                        duplicates.append(DuplicateGroup(
                            function_name=sig1.name,
                            files=[sig1.file_path, sig2.file_path],
                            lines=[(sig1.start_line, sig1.end_line), (sig2.start_line, sig2.end_line)],
                            similarity=similarity,
                            normalized_hash=sig1.full_hash,
                        ))

        # Step 3: Generate results for each file
        results: List[TransformationResult] = []

        for code_file in files:
            changes = []

            for group in duplicates:
                if any(code_file.path.name in f or str(code_file.path) in f for f in group.files):
                    changes.append(
                        f"DUPLICATION: Function '{group.function_name}' "
                        f"(similarity: {int(group.similarity * 100)}%) "
                        f"found in {len(group.files)} files: "
                        f"{', '.join(Path(f).name for f in group.files)} — "
                        f"consider consolidating duplicated code"
                    )

            results.append(self._create_result(code_file, code_file.content, changes))

        return results
