"""Orchestrates the application of multiple rules."""

import ast
import glob
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import libcst as cst

from pyneat.core.types import CodeFile, TransformationResult, RuleConfig
from pyneat.rules.base import Rule


class RuleEngine:
    """Manages and executes cleaning rules."""

    def __init__(self, rules: List[Rule] = None):
        self.rules = rules or []
        self._rule_map = {rule.name: rule for rule in self.rules}
        self._tree_cache: Dict[str, Tuple[ast.AST, cst.Module]] = {}
        self._cache_enabled = True

    def _get_content_hash(self, content: str) -> str:
        """Get hash of content for caching."""
        return hashlib.md5(content.encode()).hexdigest()

    def get_cached_trees(self, content: str) -> Optional[Tuple[ast.AST, cst.Module]]:
        """Get cached AST and CST trees for content.

        Returns:
            Tuple of (ast_tree, cst_tree) if cached, None otherwise.
        """
        if not self._cache_enabled:
            return None
        content_hash = self._get_content_hash(content)
        return self._tree_cache.get(content_hash)

    def cache_trees(self, content: str, ast_tree: ast.AST, cst_tree: cst.Module) -> None:
        """Cache AST and CST trees for content."""
        if not self._cache_enabled:
            return
        content_hash = self._get_content_hash(content)
        self._tree_cache[content_hash] = (ast_tree, cst_tree)

    def clear_cache(self) -> None:
        """Clear the tree cache."""
        self._tree_cache.clear()

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            'cache_entries': len(self._tree_cache),
            'cache_enabled': self._cache_enabled,
        }

    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the engine."""
        self.rules.append(rule)
        self._rule_map[rule.name] = rule

    def remove_rule(self, rule_name: str) -> None:
        """Remove a rule by name."""
        self.rules = [r for r in self.rules if r.name != rule_name]
        self._rule_map.pop(rule_name, None)
    
    def process_file(self, file_path: Path) -> TransformationResult:
        """Process a single file with all enabled rules."""
        try:
            # Fix encoding issues including BOM
            encodings = ['utf-8-sig', 'utf-8', 'latin-1', 'cp1252']
            content = None
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        content = f.read()
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
            
            code_file = CodeFile(path=file_path, content=content)
            return self.process_code_file(code_file)
            
        except Exception as e:
            return TransformationResult(
                original=CodeFile(path=file_path, content=""),
                transformed_content="",
                changes_made=[],
                success=False,
                error=f"File reading failed: {str(e)}"
            )
    
    def process_code_file(self, code_file: CodeFile) -> TransformationResult:
        """Process a CodeFile object with all enabled rules."""
        current_content = code_file.content
        all_changes = []
        
        for rule in self.rules:
            if not rule.config.enabled:
                continue
                
            result = rule.apply(CodeFile(
                path=code_file.path,
                content=current_content,
                language=code_file.language
            ))
            
            if result.success:
                current_content = result.transformed_content
                all_changes.extend(result.changes_made)
            else:
                # Stop processing on error if needed
                return result
        
        return TransformationResult(
            original=code_file,
            transformed_content=current_content,
            changes_made=all_changes,
            success=True
        )
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """Get statistics about available rules."""
        return {
            'total_rules': len(self.rules),
            'enabled_rules': len([r for r in self.rules if r.config.enabled]),
            'rules': [{
                'name': rule.name,
                'description': rule.description,
                'enabled': rule.config.enabled
            } for rule in self.rules]
        }

    def process_directory(
        self,
        dir_path: Path,
        pattern: str = "*.py",
        recursive: bool = True,
        skip: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Process all matching files in a directory with the rule engine.

        Args:
            dir_path: Path to the directory to process.
            pattern: Glob pattern for files to match (default: "*.py").
            recursive: If True, process subdirectories recursively.
            skip: List of file/directory names to skip (e.g. ["__pycache__", ".venv"]).

        Returns:
            Dictionary with summary stats: {total, success, failed, skipped, results}
        """
        skip = skip or ["__pycache__", ".venv", "venv", ".git", "node_modules", ".pytest_cache"]

        results: List[Dict[str, Any]] = []

        if recursive:
            files = list(dir_path.rglob(pattern))
        else:
            files = list(dir_path.glob(pattern))

        for file_path in sorted(files):
            # Skip unwanted paths
            if any(skip_name in file_path.parts for skip_name in skip):
                continue

            result = self.process_file(file_path)
            results.append({
                'file': str(file_path.relative_to(dir_path)),
                'success': result.success,
                'changes': len(result.changes_made),
                'error': result.error,
            })

        total = len(results)
        success = sum(1 for r in results if r['success'])
        failed = sum(1 for r in results if not r['success'])

        return {
            'total': total,
            'success': success,
            'failed': failed,
            'skipped': 0,
            'results': results,
        }
