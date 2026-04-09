"""Orchestrates the application of multiple rules.

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
import hashlib
import logging
import os
import py_compile
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set

import libcst as cst

from pyneat.core.types import (
    CodeFile, TransformationResult, RuleConfig,
    RuleConflict, RuleRange,
)
from pyneat.rules.base import Rule
from pyneat.core.atomic import AtomicWriter
from pyneat.core.semantic_guard import SemanticDiffGuard
from pyneat.core.type_shield import TypeAwareShield

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Module-level cache singleton — persists across RuleEngine instances
# Keyed by (content_hash, file_path) so the same file reused across
# engine instances benefits from the cache
# ----------------------------------------------------------------------

_module_cache: Dict[str, Tuple[ast.AST, cst.Module, float]] = {}
_cache_hits = 0
_cache_misses = 0


def _get_cache_key(content: str, file_path: Path | None) -> str:
    """Build a cache key from content hash and file path."""
    content_hash = hashlib.md5(content.encode()).hexdigest()
    path_part = str(file_path) if file_path else "<string>"
    return f"{content_hash}:{path_part}"


def _get_cached_trees(key: str) -> Optional[Tuple[ast.AST, cst.Module]]:
    global _cache_hits, _cache_misses
    if key in _module_cache:
        _cache_hits += 1
        return _module_cache[key][0], _module_cache[key][1]
    _cache_misses += 1
    return None


def _cache_trees(key: str, ast_tree: ast.AST, cst_tree: cst.Module) -> None:
    global _module_cache
    _module_cache[key] = (ast_tree, cst_tree, os.path.getmtime(__file__))


def clear_module_cache() -> None:
    """Clear the module-level cache and reset hit/miss counters."""
    global _module_cache, _cache_hits, _cache_misses
    _module_cache.clear()
    _cache_hits = 0
    _cache_misses = 0


def get_module_cache_stats() -> Dict[str, Any]:
    """Get module-level cache statistics."""
    total = _cache_hits + _cache_misses
    hit_rate = (_cache_hits / total * 100) if total > 0 else 0.0
    return {
        'cache_entries': len(_module_cache),
        'cache_hits': _cache_hits,
        'cache_misses': _cache_misses,
        'hit_rate_pct': round(hit_rate, 1),
    }


# ----------------------------------------------------------------------
# RuleEngine
# ----------------------------------------------------------------------


class RuleEngine:
    """Manages and executes cleaning rules."""

    def __init__(self, rules: List[Rule] = None):
        self.rules = rules or []
        self._rule_map = {rule.name: rule for rule in self.rules}
        self._tree_cache: Dict[str, Tuple[ast.AST, cst.Module]] = {}
        self._cache_enabled = True
        self._processed_files: set[Path] = set()
        self.atomic_writer = AtomicWriter()
        # Layer 5: Semantic diffing guard
        self.semantic_guard = SemanticDiffGuard()
        # Layer 6: Type-aware shield (disabled by default; enable via config)
        self.type_shield = TypeAwareShield(enabled=False)
        self._type_baseline: Dict[Path, set] = {}

    def _get_content_hash(self, content: str) -> str:
        """Get hash of content for caching."""
        return hashlib.md5(content.encode()).hexdigest()

    def get_cached_trees(self, content: str, file_path: Path | None = None) -> Optional[Tuple[ast.AST, cst.Module]]:
        """Get cached AST and CST trees for content.

        Uses module-level cache for cross-instance sharing,
        plus instance-level cache as fallback.
        """
        if not self._cache_enabled:
            return None
        cache_key = _get_cache_key(content, file_path)
        result = _get_cached_trees(cache_key)
        if result:
            return result
        return self._tree_cache.get(self._get_content_hash(content))

    def cache_trees(self, content: str, ast_tree: ast.AST, cst_tree: cst.Module, file_path: Path | None = None) -> None:
        """Cache AST and CST trees for content."""
        if not self._cache_enabled:
            return
        cache_key = _get_cache_key(content, file_path)
        _cache_trees(cache_key, ast_tree, cst_tree)
        self._tree_cache[self._get_content_hash(content)] = (ast_tree, cst_tree)

    def clear_cache(self) -> None:
        """Clear both instance and module-level caches."""
        self._tree_cache.clear()
        clear_module_cache()

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get combined cache statistics."""
        inst_total = sum(1 for v in self._tree_cache.values())
        mod_stats = get_module_cache_stats()
        return {
            'cache_entries': inst_total + mod_stats['cache_entries'],
            'cache_enabled': self._cache_enabled,
            'cache_hits': mod_stats['cache_hits'],
            'cache_misses': mod_stats['cache_misses'],
            'hit_rate_pct': mod_stats['hit_rate_pct'],
            'module_cache_entries': mod_stats['cache_entries'],
        }

    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the engine."""
        self.rules.append(rule)
        self._rule_map[rule.name] = rule

    def remove_rule(self, rule_name: str) -> None:
        """Remove a rule by name."""
        self.rules = [r for r in self.rules if r.name != rule_name]
        self._rule_map.pop(rule_name, None)
    
    def process_file(self, file_path: Path, check_conflicts: bool = False) -> TransformationResult:
        """Process a single file with all enabled rules."""
        try:
            # Fix encoding issues including BOM
            encodings = ['utf-8-sig', 'utf-8', 'latin-1', 'cp1252']
            content = None

            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        raw = f.read()
                    # Strip BOM — PyNEAT always writes UTF-8 without BOM
                    BOM = "\ufeff"
                    content = raw.lstrip(BOM)
                    break
                except UnicodeDecodeError:
                    continue

            if content is None:
                return TransformationResult(
                    original=CodeFile(path=file_path, content=""),
                    transformed_content="",
                    changes_made=[],
                    success=False,
                    error=f"File reading failed: Could not decode with any encoding"
                )

            # Layer 7: Create backup before any modification
            backup_path = self.atomic_writer.backup(file_path)

            # Layer 6: Capture type baseline before any transformation
            type_baseline: set = set()
            if self.type_shield.enabled:
                type_baseline = self.type_shield.get_baseline(file_path)
                self._type_baseline[file_path] = type_baseline

            code_file = CodeFile(path=file_path, content=content)
            self._processed_files.add(file_path)
            result = self.process_code_file(code_file, check_conflicts=check_conflicts)

            if result.success and result.has_changes and result.transformed_content != content:

                # Layer 6: Check for new type errors after writing
                if self.type_shield.enabled:
                    new_type_errors = self.type_shield.check_new_errors(file_path, type_baseline)
                    if new_type_errors:
                        # Rollback to original content
                        if backup_path:
                            self.atomic_writer.rollback(backup_path, file_path)
                        error_msgs = [f"[type] line {ln}: {msg}" for msg, ln, _ in new_type_errors]
                        logger.warning(
                            "TypeAwareShield: %d new type errors in %s, rolled back: %s",
                            len(new_type_errors), file_path, error_msgs,
                        )
                        return TransformationResult(
                            original=code_file,
                            transformed_content=content,
                            changes_made=result.changes_made + [f"REVERTED: Type errors introduced: {error_msgs}"],
                            success=False,
                            error=f"TypeAwareShield detected {len(new_type_errors)} new type errors, file restored from backup",
                        )

            return result

        except Exception as e:
            return TransformationResult(
                original=CodeFile(path=file_path, content=""),
                transformed_content="",
                changes_made=[],
                success=False,
                error=f"File reading failed: {str(e)}"
            )
    
    def _diff_lines(self, old_content: str, new_content: str) -> List[Tuple[int, int]]:
        """Compute modified line ranges between two contents.

        Returns:
            List of (start_line, end_line) tuples (1-indexed, inclusive).
        """
        old_lines = old_content.splitlines(keepends=True)
        new_lines = new_content.splitlines(keepends=True)
        if old_content == new_content:
            return []

        import difflib
        matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
        ranges: List[Tuple[int, int]] = []
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag in ('replace', 'insert'):
                start = i1 + 1  # 1-indexed
                end = i2 if i2 > i1 else j2
                if end >= start:
                    ranges.append((start, end))
            elif tag == 'delete' and i2 > i1:
                # Deletion: report the original position(s) removed
                start = i1 + 1  # 1-indexed
                end = i2
                if end >= start:
                    ranges.append((start, end))
        return ranges

    def _detect_conflicts(
        self,
        rule_ranges: List[RuleRange],
        original_content: str = "",
    ) -> List[RuleConflict]:
        """Detect overlapping line ranges between rules, with severity.

        Severity is determined by:
        - 'critical': Both rules delete/remove the same function/class definition
        - 'high': Both rules modify the exact same lines (>80% overlap)
        - 'medium': Rules modify overlapping lines (partial overlap)
        - 'low': Rules are close but don't actually overlap (within 1 line)
        """
        conflicts: List[RuleConflict] = []
        seen: set = set()

        # Collect all line ranges per rule
        rule_line_map: Dict[str, List[RuleRange]] = {}
        for r in rule_ranges:
            rule_line_map.setdefault(r.rule_name, []).append(r)

        for i, r_a in enumerate(rule_ranges):
            for r_b in rule_ranges[i + 1:]:
                pair_key = tuple(sorted([r_a.rule_name, r_b.rule_name]))
                if pair_key in seen:
                    continue

                if r_a.overlaps(r_b):
                    seen.add(pair_key)
                    overlap_start = max(r_a.start_line, r_b.start_line)
                    overlap_end = min(r_a.end_line, r_b.end_line)
                    overlap_len = overlap_end - overlap_start + 1

                    range_a_len = r_a.end_line - r_a.start_line + 1
                    range_b_len = r_b.end_line - r_b.start_line + 1
                    min_range_len = min(range_a_len, range_b_len)

                    # Determine severity
                    if overlap_len >= min_range_len * 0.8 and overlap_len >= 3:
                        severity = "high"
                    else:
                        severity = "medium"

                    # Build diff snippet
                    diff_snippet = ""
                    if original_content and overlap_start > 0:
                        lines = original_content.splitlines()
                        snippet_lines = []
                        for ln in range(overlap_start - 1, min(overlap_end, len(lines))):
                            snippet_lines.append(f"  {ln + 1:4d}: {lines[ln]}")
                        if snippet_lines:
                            diff_snippet = "\n".join(snippet_lines)

                    desc = f"CONFLICT: '{r_a.rule_name}' and '{r_b.rule_name}' both modified lines {overlap_start}-{overlap_end}"
                    if diff_snippet:
                        desc += f"\n  Overlapping code:\n{diff_snippet}"

                    conflicts.append(RuleConflict(
                        rule_a=r_a.rule_name,
                        rule_b=r_b.rule_name,
                        line_range=(overlap_start, overlap_end),
                        severity=severity,
                        description=desc,
                    ))

        return conflicts

    def _format_conflicts(self, conflicts: List[RuleConflict]) -> List[str]:
        """Format conflicts into human-readable messages."""
        return [str(c) for c in conflicts]

    def process_code_file(
        self,
        code_file: CodeFile,
        check_conflicts: bool = False,
    ) -> TransformationResult:
        """Process a CodeFile object with all enabled rules.

        Args:
            code_file: The code file to process.
            check_conflicts: If True, detect overlapping modifications between rules.

        Uses the tree cache to avoid re-parsing the same content across
        multiple rules. Each unique content is parsed once (AST + CST).
        """
        # Check cache first — avoid re-parsing if this content was already processed
        cached = self.get_cached_trees(code_file.content)
        if cached:
            cached_ast, cached_cst = cached
            cf = code_file
            object.__setattr__(cf, 'ast_tree', cached_ast)
            object.__setattr__(cf, 'cst_tree', cached_cst)
        else:
            try:
                ast_tree = ast.parse(code_file.content)
                cst_tree = cst.parse_module(code_file.content)
                self.cache_trees(code_file.content, ast_tree, cst_tree)
                cf = code_file
                object.__setattr__(cf, 'ast_tree', ast_tree)
                object.__setattr__(cf, 'cst_tree', cst_tree)
            except SyntaxError:
                cf = code_file

        original_content = cf.content
        current_content = cf.content
        all_changes: List[str] = []
        all_modified_ranges: List[Tuple[int, int]] = []
        rule_ranges: List[RuleRange] = []
        all_security_findings: List = []
        all_dependency_findings: List = []
        all_auto_fix_applied: List[str] = []

        # Sort rules by priority (lower = runs first), then by insertion order
        sorted_rules = sorted(
            self.rules,
            key=lambda r: (r.config.priority, self.rules.index(r))
        )

        for rule in sorted_rules:
            if not rule.config.enabled:
                continue

            before = current_content

            # Create CodeFile for this rule, with cached trees if available
            rule_cf = CodeFile(
                path=cf.path,
                content=current_content,
                language=cf.language,
            )
            # Attach cached trees to avoid re-parsing
            if hasattr(cf, 'ast_tree') and cf.ast_tree is not None:
                object.__setattr__(rule_cf, 'ast_tree', cf.ast_tree)
            if hasattr(cf, 'cst_tree') and cf.cst_tree is not None:
                object.__setattr__(rule_cf, 'cst_tree', cf.cst_tree)

            # Pass processed files to NamingConventionRule for cross-file updates
            if rule.name == 'NamingConventionRule':
                result = rule.apply(rule_cf, processed_files=list(self._processed_files))
            else:
                result = rule.apply(rule_cf)

            if result.success:
                current_content = result.transformed_content

                # Layer 1+: Guard — if a rule produces output that can't be parsed/compiled, revert
                try:
                    # Fast check with ast.parse
                    ast.parse(current_content)
                    # Full bytecode compile check via temporary file
                    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as tmp:
                        tmp.write(current_content)
                        tmp_name = tmp.name
                    try:
                        py_compile.compile(tmp_name, doraise=True)
                    finally:
                        Path(tmp_name).unlink(missing_ok=True)
                except (SyntaxError, py_compile.PyCompileError) as e:
                    # Rule produced invalid output — skip this rule, keep current content
                    err_lineno = getattr(e, "lineno", None)
                    err_msg = str(e.args[0]) if e.args else str(e)
                    logger.warning(
                        "Rule '%s' produced syntax error in %s (line %s): %s. Skipping rule.",
                        rule.name, cf.path, err_lineno if err_lineno is not None else "?", err_msg,
                    )
                    all_changes.append(f"SKIPPED {rule.name}: syntax error (line {getattr(e, 'lineno', '?')})")
                    continue

                # Layer 1+: Guard — don't lose required __future__ imports
                if self._removed_future_imports(before, current_content):
                    logger.warning(
                        "Rule '%s' attempted to remove a __future__ import in %s. Skipping rule.",
                        rule.name, cf.path,
                    )
                    all_changes.append(f"SKIPPED {rule.name}: would remove __future__ import")
                    continue

                # Layer 5: Semantic diffing — detect unintended structural changes
                allowed_nodes = rule.allowed_semantic_nodes
                is_safe, diff_messages = self.semantic_guard.is_safe(
                    before, current_content, allowed_nodes
                )
                if not is_safe:
                    logger.warning(
                        "Rule '%s' produced unsafe semantic changes in %s: %s. Skipping rule.",
                        rule.name, cf.path, diff_messages,
                    )
                    all_changes.append(f"SKIPPED {rule.name}: semantic safety failed — {diff_messages[0]}")
                    current_content = before
                    continue

                all_changes.extend(result.changes_made)
                # Aggregate security findings from SecurityScannerRule and similar
                if hasattr(result, 'security_findings'):
                    all_security_findings.extend(result.security_findings)
                if hasattr(result, 'dependency_findings'):
                    all_dependency_findings.extend(result.dependency_findings)
                if hasattr(result, 'auto_fix_applied'):
                    all_auto_fix_applied.extend(result.auto_fix_applied)

                if check_conflicts and before != current_content:
                    ranges = self._diff_lines(original_content, current_content)
                    all_modified_ranges.extend(ranges)
                    for start, end in ranges:
                        rule_ranges.append(RuleRange(
                            rule_name=rule.name,
                            start_line=start,
                            end_line=end,
                        ))
            else:
                return result

        conflicts: List[RuleConflict] = []
        if check_conflicts and rule_ranges:
            conflicts = self._detect_conflicts(rule_ranges, original_content)
            all_changes.extend(self._format_conflicts(conflicts))

        return TransformationResult(
            original=cf,
            transformed_content=current_content,
            changes_made=all_changes,
            success=True,
            modified_lines=all_modified_ranges if len(all_modified_ranges) > 0 else None,
            security_findings=all_security_findings,
            auto_fix_applied=all_auto_fix_applied,
            dependency_findings=all_dependency_findings,
        )
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """Get statistics about available rules."""
        return {
            'total_rules': len(self.rules),
            'enabled_rules': len([r for r in self.rules if r.config.enabled]),
            'rules': [{
                'name': rule.name,
                'description': rule.description,
                'enabled': rule.config.enabled,
                'priority': rule.config.priority,
            } for rule in self.rules]
        }

    def _removed_future_imports(self, before: str, after: str) -> bool:
        """Check if after removes any __future__ imports that existed in before."""
        import re

        future_import_re = re.compile(
            r'^\s*from\s+__future__\s+import\s+',
            re.MULTILINE,
        )

        before_has_future = bool(future_import_re.search(before))
        after_has_future = bool(future_import_re.search(after))

        return before_has_future and not after_has_future

    def process_directory(
        self,
        dir_path: Path,
        pattern: str = "*.py",
        recursive: bool = True,
        skip: Optional[List[str]] = None,
        max_workers: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Process all matching files in a directory with the rule engine.

        Args:
            dir_path: Path to the directory to process.
            pattern: Glob pattern for files to match (default: "*.py").
            recursive: If True, process subdirectories recursively.
            skip: List of file/directory names to skip (e.g. ["__pycache__", ".venv"]).
            max_workers: Max parallel workers. None=auto (CPU count). 1=sequential.

        Returns:
            Dictionary with summary stats: {total, success, failed, skipped, results}
        """
        skip = skip or ["__pycache__", ".venv", "venv", ".git", "node_modules", ".pytest_cache"]

        if recursive:
            files = list(dir_path.rglob(pattern))
        else:
            files = list(dir_path.glob(pattern))

        # Filter skipped paths immediately
        paths_to_process = [
            fp for fp in sorted(files)
            if not any(skip_name in fp.parts for skip_name in skip)
        ]

        results: List[Dict[str, Any]] = [None] * len(paths_to_process)

        if max_workers == 1 or max_workers == 0:
            # Explicitly sequential
            for i, fp in enumerate(paths_to_process):
                result = self.process_file(fp)
                results[i] = {
                    'file': str(fp.relative_to(dir_path)),
                    'success': result.success,
                    'changes': len(result.changes_made),
                    'error': result.error,
                }
        elif len(paths_to_process) == 0:
            pass  # results stays empty
        else:
            # Parallel execution with ThreadPoolExecutor
            workers = max_workers or os.cpu_count() or 4
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(self.process_file, fp): i
                    for i, fp in enumerate(paths_to_process)
                }
                for future in as_completed(futures):
                    i = futures[future]
                    fp = paths_to_process[i]
                    try:
                        result = future.result()
                    except Exception as e:
                        result = None
                    if result:
                        self._processed_files.add(fp)
                    results[i] = {
                        'file': str(paths_to_process[i].relative_to(dir_path)),
                        'success': result is not None and result.success,
                        'changes': len(result.changes_made) if result else 0,
                        'error': result.error if result else str(e),
                    }

        total = len(results)
        success = sum(1 for r in results if r and r['success'])
        failed = sum(1 for r in results if r and not r['success'])

        return {
            'total': total,
            'success': success,
            'failed': failed,
            'skipped': 0,
            'results': results,
        }
