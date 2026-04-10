"""Command-line interface for AI Cleaner.

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

import sys
import os
import shutil
import difflib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict
import click
from pathlib import Path
from datetime import datetime

from pyneat.core.engine import RuleEngine, clear_module_cache
from pyneat import __version__
from pyneat.core.types import RuleConfig
from pyneat.rules.imports import ImportCleaningRule
from pyneat.rules.naming import NamingConventionRule
from pyneat.rules.refactoring import RefactoringRule
from pyneat.rules.security import SecurityScannerRule
from pyneat.rules.quality import CodeQualityRule
from pyneat.rules.performance import PerformanceRule
from pyneat.rules.debug import DebugCleaner
from pyneat.rules.comments import CommentCleaner
from pyneat.rules.unused import UnusedImportRule
from pyneat.rules.redundant import RedundantExpressionRule
from pyneat.rules.is_not_none import IsNotNoneRule
from pyneat.rules.magic_numbers import MagicNumberRule
from pyneat.rules.init_protection import InitFileProtectionRule
from pyneat.rules.deadcode import DeadCodeRule
from pyneat.rules.fstring import FStringRule
from pyneat.rules.range_len_pattern import RangeLenRule
from pyneat.rules.typing import TypingRule
from pyneat.rules.match_case import MatchCaseRule
from pyneat.rules.dataclass import DataclassSuggestionRule

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def show_diff(original: str, transformed: str, filename: str) -> str:
    """Generate a unified diff between original and transformed content."""
    if original == transformed:
        return ""
    lines_a = original.splitlines(keepends=True)
    lines_b = transformed.splitlines(keepends=True)
    diff = difflib.unified_diff(
        lines_a, lines_b,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        lineterm=""
    )
    return "".join(diff)


# ----------------------------------------------------------------------
# Config loading
# ----------------------------------------------------------------------


def _load_config(path: Path | None = None) -> dict:
    """Load config from pyproject.toml if it exists."""
    if path is None:
        path = Path.cwd() / "pyproject.toml"

    if not path.exists():
        return {}

    if sys.version_info >= (3, 11):
        import tomllib
        with open(path, "rb") as f:
            data = tomllib.load(f)
        return data.get("tool", {}).get("pyneat", {})
    return {}


# ----------------------------------------------------------------------
# Rule builders
# ----------------------------------------------------------------------


def _build_engine(config: dict,
                  package: str,
                  enable_security: bool, enable_quality: bool,
                  enable_performance: bool, enable_unused: bool,
                  enable_redundant: bool, enable_is_not_none: bool,
                  enable_magic_numbers: bool, enable_dead_code: bool,
                  enable_fstring: bool, enable_range_len: bool,
                  enable_typing: bool, enable_match_case: bool,
                  enable_dataclass: bool,
                  enable_import_cleaning: bool,
                  enable_naming: bool,
                  enable_refactoring: bool,
                  enable_comment_clean: bool,
                  debug_clean_mode: str = 'off') -> RuleEngine:
    """Build a RuleEngine from config dict and CLI flags.

    Args:
        package: Rule package selection
            - 'safe': Default safe rules only (no destructive changes)
            - 'conservative': Safe + opt-in cleanup rules
            - 'destructive': All rules including aggressive refactoring
        debug_clean_mode:
        - 'off': (default) Keeps all print calls (disables DebugCleaner)
        - 'safe': Only removes debug-like prints (keywords, log levels, variable dumps)
        - 'aggressive': Removes ALL print/console.log calls
    """
    rules = []

    # ===================================================================
    # Package: safe (default) — always enabled, won't break code
    # ===================================================================
    rules.extend([
        IsNotNoneRule(RuleConfig(enabled=True)),
        RangeLenRule(RuleConfig(enabled=True)),
        SecurityScannerRule(RuleConfig(enabled=True)),
        TypingRule(RuleConfig(enabled=True)),
        CodeQualityRule(RuleConfig(enabled=True)),
        PerformanceRule(RuleConfig(enabled=True)),
    ])

    # ===================================================================
    # Package: conservative — adds cleanup rules (safe to use)
    # ===================================================================
    if package in ('conservative', 'destructive'):
        if enable_unused or config.get("enable_unused_imports", False):
            rules.append(InitFileProtectionRule(RuleConfig(enabled=True)))
            rules.append(UnusedImportRule(RuleConfig(enabled=True)))
        if enable_fstring or config.get("enable_fstring", False):
            rules.append(FStringRule(RuleConfig(enabled=True)))
        if enable_dataclass or config.get("enable_dataclass", False):
            rules.append(DataclassSuggestionRule(RuleConfig(enabled=True)))
        if enable_magic_numbers or config.get("enable_magic_numbers", False):
            rules.append(MagicNumberRule(RuleConfig(enabled=True)))

    # debug_clean_mode: CLI flag — applies to ALL packages (even safe/conservative)
    effective_mode = debug_clean_mode
    if effective_mode == 'off':
        cfg_mode = config.get("debug_clean_mode")
        if cfg_mode in ('safe', 'aggressive'):
            effective_mode = cfg_mode
    if effective_mode != 'off':
        rules.append(DebugCleaner(mode=effective_mode))

    # ===================================================================
    # Package: destructive — adds aggressive rules (may break code)
    # ===================================================================
    if package == 'destructive':
        if enable_import_cleaning or config.get("enable_import_cleaning", False):
            rules.append(ImportCleaningRule(RuleConfig(enabled=True)))
        if enable_naming or config.get("enable_naming", False):
            rules.append(NamingConventionRule(RuleConfig(enabled=True)))
        if enable_refactoring or config.get("enable_refactoring", False):
            rules.append(RefactoringRule(RuleConfig(enabled=True)))
        if enable_comment_clean or config.get("enable_comment_clean", False):
            rules.append(CommentCleaner(RuleConfig(enabled=True)))
        if enable_redundant or config.get("enable_redundant", False):
            rules.append(RedundantExpressionRule(RuleConfig(enabled=True)))
        if enable_dead_code or config.get("enable_dead_code", False):
            rules.append(DeadCodeRule(RuleConfig(enabled=True)))
        if enable_match_case or config.get("enable_match_case", False):
            rules.append(MatchCaseRule(RuleConfig(enabled=True)))

    return RuleEngine(rules)


# ----------------------------------------------------------------------
# CLI commands
# ----------------------------------------------------------------------


@click.group()
@click.version_option(version=__version__, prog_name='pyneat')
@click.option('--color', type=click.Choice(['auto', 'always', 'never']), default='auto',
              help='Control colored output: auto (default), always, or never')
def cli(color: str):
    """PyNeat - Neat Python AI Code Cleaner."""
    ctx = click.get_current_context()
    ctx.color = color == 'always'


@click.pass_context
@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--in-place', '-i', is_flag=True, help='Modify file in place')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--package', '-p', type=click.Choice(['safe', 'conservative', 'destructive']), default='safe',
              help='Rule package: safe (default), conservative (adds cleanup rules), destructive (adds aggressive rules)')
@click.option('--enable-all', is_flag=True,
              help='Enable ALL --enable-* flags. Also sets --package destructive')
@click.option('--enable-security', is_flag=True, help='Enable security scanning')
@click.option('--enable-quality', is_flag=True, help='Enable code quality checks')
@click.option('--enable-performance', is_flag=True, help='Enable performance checks')
@click.option('--enable-unused', is_flag=True, help='Enable unused import detection')
@click.option('--enable-redundant', is_flag=True, help='Enable redundant expression simplification')
@click.option('--enable-is-not-none', is_flag=True, help='Enable is not None comparison fix')
@click.option('--enable-magic-numbers', is_flag=True, help='Enable magic number detection')
@click.option('--enable-dead-code', is_flag=True, help='Enable dead code detection')
@click.option('--enable-fstring', is_flag=True, help='Enable f-string conversion')
@click.option('--enable-range-len', is_flag=True, help='Enable range(len()) fix')
@click.option('--enable-typing', is_flag=True, help='Enable type hints suggestions')
@click.option('--enable-match-case', is_flag=True, help='Enable match-case suggestions (Python 3.10+)')
@click.option('--enable-dataclass', is_flag=True, help='Enable @dataclass suggestions')
@click.option('--enable-import-cleaning', is_flag=True,
              help='Enable import standardization and deduplication')
@click.option('--enable-naming', is_flag=True,
              help='Enable PEP8 naming convention enforcement (class renaming)')
@click.option('--enable-refactoring', is_flag=True,
              help='Enable nested-if refactoring and except-block fixes')
@click.option('--enable-comment-clean', is_flag=True,
              help='Enable removal of empty TODO/AI boilerplate comments')
@click.option('--safe-debug-clean', 'debug_mode', flag_value='safe',
              help='Smart debug removal - only removes debug-like prints')
@click.option('--aggressive-clean', 'debug_mode', flag_value='aggressive',
              help='Remove ALL print/console.log calls')
@click.option('--keep-all-prints', 'debug_mode', flag_value='off', default=True,
              help='Keep all print calls (default, disables DebugCleaner)')
@click.option('--dry-run', is_flag=True, help='Preview changes without writing files')
@click.option('--diff', '-d', is_flag=True, help='Show unified diff of changes')
@click.option('--check-conflicts', is_flag=True, help='Detect overlapping modifications between rules')
@click.option('--clear-cache', is_flag=True, help='Clear the module-level AST cache before processing')
@click.option('--export-manifest', is_flag=True, help='Export PYNAGENT manifest JSON file')
def clean(input_file: str, output: str, in_place: bool, verbose: bool,
          package: str,
          enable_all: bool,
          enable_security: bool, enable_quality: bool, enable_performance: bool,
          enable_unused: bool, enable_redundant: bool, enable_is_not_none: bool,
          enable_magic_numbers: bool, enable_dead_code: bool,
          enable_fstring: bool, enable_range_len: bool,
          enable_typing: bool, enable_match_case: bool,
          enable_dataclass: bool,
          enable_import_cleaning: bool,
          enable_naming: bool,
          enable_refactoring: bool,
          enable_comment_clean: bool,
          debug_mode: str, dry_run: bool, diff: bool,
          check_conflicts: bool, clear_cache: bool, export_manifest: bool):
    """Clean AI-generated code."""
    input_path = Path(input_file)

    if enable_all:
        enable_import_cleaning = True
        enable_naming = True
        enable_refactoring = True
        enable_comment_clean = True
        enable_redundant = True
        enable_dead_code = True
        enable_match_case = True
        debug_mode = 'safe'

    if clear_cache:
        clear_module_cache()

    config = _load_config()
    engine = _build_engine(
        config, package, enable_security, enable_quality, enable_performance,
        enable_unused, enable_redundant, enable_is_not_none, enable_magic_numbers,
        enable_dead_code, enable_fstring, enable_range_len,
        enable_typing, enable_match_case, enable_dataclass,
        enable_import_cleaning, enable_naming, enable_refactoring,
        enable_comment_clean,
        debug_clean_mode=debug_mode,
    )

    if verbose:
        stats = engine.get_rule_stats()
        cache_stats = engine.get_cache_stats()
        click.echo(f"[TARGET] Loaded {stats['enabled_rules']}/{stats['total_rules']} rules")
        click.echo(f"[CACHE] Entries: {cache_stats['cache_entries']}, Hits: {cache_stats['cache_hits']}, Misses: {cache_stats['cache_misses']}, Hit Rate: {cache_stats['hit_rate_pct']}%")
        for rule in stats['rules']:
            status = "[OK]" if rule['enabled'] else "[X]"
            click.echo(f"  {status} {rule['name']} [p={rule['priority']}]: {rule['description']}")

    result = engine.process_file(input_path, check_conflicts=check_conflicts)

    if not result.success:
        click.echo(f"[ERROR] Error: {result.error}", err=True)
        return 1

    # Handle --dry-run and --diff modes
    if dry_run:
        click.echo(f"[DRY-RUN] Would clean: {input_file}")
        if result.changes_made:
            click.echo("[CHANGES] Changes that would be made:")
            for change in result.changes_made:
                if "SECURITY:" in change or "AUTO-FIX:" in change:
                    click.secho(f"  [!] {change}", fg="yellow")
                else:
                    click.echo(f"  * {change}")
        else:
            click.echo("[INFO] No changes needed - code already clean!")

        if diff:
            click.echo("\n" + "=" * 60)
            click.echo("DIFF:")
            click.echo("=" * 60)
            click.echo(show_diff(
                result.original.content,
                result.transformed_content,
                str(input_path)
            ))
        return 0

    # Export manifest if requested
    if export_manifest:
        manifest_path = input_path.with_suffix('.pyneat.manifest.json')
        try:
            manifest_data = {
                'version': __version__,
                'file': str(input_path),
                'rules_enabled': [r['name'] for r in engine.get_rule_stats()['rules'] if r['enabled']],
                'changes_count': len(result.changes_made) if result.changes_made else 0,
            }
            import json
            with open(manifest_path, 'w', encoding='utf-8') as f:
                json.dump(manifest_data, f, indent=2)
            click.echo(f"[MANIFEST] Exported: {manifest_path}")
        except Exception as e:
            click.echo(f"[WARN] Manifest export failed: {e}", err=True)

    if diff:
        click.echo("=" * 60)
        click.echo("DIFF:")
        click.echo("=" * 60)
        click.echo(show_diff(
            result.original.content,
            result.transformed_content,
            str(input_path)
        ))

    if in_place:
        output_path = input_path
    elif output:
        output_path = Path(output)
    else:
        output_path = input_path.with_name(f"{input_path.stem}.clean{input_path.suffix}")

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result.transformed_content)

        if verbose or not in_place:
            click.echo(f"[OK] Cleaned: {input_path} -> {output_path}")
            if result.changes_made:
                click.echo("[CHANGES] Changes made:")
                for change in result.changes_made:
                    if "SECURITY:" in change or "AUTO-FIX:" in change:
                        click.secho(f"  [!] {change}", fg="yellow")
                    else:
                        click.echo(f"  * {change}")
            else:
                click.echo("[INFO] No changes needed - code already clean!")

    except Exception as e:
        click.echo(f"[ERROR] Write failed: {str(e)}", err=True)
        return 1

    return 0


def _process_single_file(
    file_path: Path,
    engine: RuleEngine,
    dir_path: Path,
) -> dict:
    """Process a single file and return a result dict. Used for parallel execution."""
    result = engine.process_file(file_path)
    rel_path = str(file_path.relative_to(dir_path))
    return {
        'file_path': file_path,
        'rel_path': rel_path,
        'result': result,
    }


@cli.command()
@click.argument('dir_path', type=click.Path(exists=True))
@click.option('--pattern', '-p', default="*.py", help='Glob pattern to match files')
@click.option('--in-place', '-i', is_flag=True, help='Modify files in place')
@click.option('--backup', '-b', is_flag=True, help='Create backup before in-place editing')
@click.option('--backup-suffix', default=".bak", help='Backup file suffix (default: .bak)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--package', type=click.Choice(['safe', 'conservative', 'destructive']), default='safe',
              help='Rule package: safe (default), conservative (adds cleanup rules), destructive (adds aggressive rules)')
@click.option('--enable-all', is_flag=True,
              help='Enable ALL --enable-* flags. Also sets --package destructive')
@click.option('--enable-security', is_flag=True, help='Enable security scanning')
@click.option('--enable-quality', is_flag=True, help='Enable code quality checks')
@click.option('--enable-performance', is_flag=True, help='Enable performance checks')
@click.option('--enable-unused', is_flag=True, help='Enable unused import detection')
@click.option('--enable-redundant', is_flag=True, help='Enable redundant expression simplification')
@click.option('--enable-is-not-none', is_flag=True, help='Enable is not None comparison fix')
@click.option('--enable-magic-numbers', is_flag=True, help='Enable magic number detection')
@click.option('--enable-dead-code', is_flag=True, help='Enable dead code detection')
@click.option('--enable-fstring', is_flag=True, help='Enable f-string conversion')
@click.option('--enable-range-len', is_flag=True, help='Enable range(len()) fix')
@click.option('--enable-typing', is_flag=True, help='Enable type hints suggestions')
@click.option('--enable-match-case', is_flag=True, help='Enable match-case suggestions (Python 3.10+)')
@click.option('--enable-dataclass', is_flag=True, help='Enable @dataclass suggestions')
@click.option('--enable-import-cleaning', is_flag=True,
              help='Enable import standardization and deduplication')
@click.option('--enable-naming', is_flag=True,
              help='Enable PEP8 naming convention enforcement (class renaming)')
@click.option('--enable-refactoring', is_flag=True,
              help='Enable nested-if refactoring and except-block fixes')
@click.option('--enable-comment-clean', is_flag=True,
              help='Enable removal of empty TODO/AI boilerplate comments')
@click.option('--safe-debug-clean', 'debug_mode', flag_value='safe',
              help='Smart debug removal - only removes debug-like prints')
@click.option('--aggressive-clean', 'debug_mode', flag_value='aggressive',
              help='Remove ALL print/console.log calls')
@click.option('--keep-all-prints', 'debug_mode', flag_value='off', default=True,
              help='Keep all print calls (default, disables DebugCleaner)')
@click.option('--dry-run', is_flag=True, help='Preview changes without writing files')
@click.option('--diff', '-d', is_flag=True, help='Show unified diff of changes')
@click.option('--parallel', '-P', is_flag=True, help='Enable parallel processing (auto-detect CPU cores)')
@click.option('--workers', '-w', type=int, default=None, help='Number of parallel workers (default: auto)')
@click.option('--clear-cache', is_flag=True, help='Clear the module-level AST cache before processing')
@click.option('--export-manifest', is_flag=True, help='Export PYNAGENT manifest JSON file')
@click.pass_context
def clean_dir(ctx, dir_path: str, pattern: str, in_place: bool, backup: bool,
              backup_suffix: str, verbose: bool,
              package: str,
              enable_all: bool,
              enable_security: bool, enable_quality: bool, enable_performance: bool,
              enable_unused: bool, enable_redundant: bool, enable_is_not_none: bool,
              enable_magic_numbers: bool, enable_dead_code: bool,
              enable_fstring: bool, enable_range_len: bool,
              enable_typing: bool, enable_match_case: bool,
              enable_dataclass: bool,
              enable_import_cleaning: bool,
              enable_naming: bool,
              enable_refactoring: bool,
              enable_comment_clean: bool,
              debug_mode: str, dry_run: bool, diff: bool,
              parallel: bool, workers: Optional[int],
              clear_cache: bool, export_manifest: bool):
    """Clean all Python files in a directory recursively."""
    if enable_all:
        enable_import_cleaning = True
        enable_naming = True
        enable_refactoring = True
        enable_comment_clean = True
        enable_redundant = True
        enable_dead_code = True
        enable_match_case = True
        enable_unused = True
        enable_fstring = True
        debug_mode = 'safe'

    if clear_cache:
        clear_module_cache()

    config = _load_config()
    engine = _build_engine(
        config, package, enable_security, enable_quality, enable_performance,
        enable_unused, enable_redundant, enable_is_not_none, enable_magic_numbers,
        enable_dead_code, enable_fstring, enable_range_len,
        enable_typing, enable_match_case, enable_dataclass,
        enable_import_cleaning, enable_naming, enable_refactoring,
        enable_comment_clean,
        debug_clean_mode=debug_mode,
    )

    if verbose:
        stats = engine.get_rule_stats()
        cache_stats = engine.get_cache_stats()
        click.echo(f"[TARGET] Package: {package}, Loaded {stats['enabled_rules']}/{stats['total_rules']} rules")
        click.echo(f"[CACHE] Entries: {cache_stats['cache_entries']}, Hits: {cache_stats['cache_hits']}, Misses: {cache_stats['cache_misses']}, Hit Rate: {cache_stats['hit_rate_pct']}%")
        for rule in stats['rules']:
            status = "[OK]" if rule['enabled'] else "[X]"
            click.echo(f"  {status} {rule['name']} [p={rule['priority']}]: {rule['description']}")

    path = Path(dir_path)
    skip = ["__pycache__", ".venv", "venv", ".git", "node_modules", ".pytest_cache", ".egg-info"]

    # Create backup directory if needed
    backup_dir = None
    if in_place and backup and not dry_run:
        backup_dir = path / f".pyneat_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        backup_dir.mkdir(exist_ok=True)
        click.echo(f"[BACKUP] Backup directory: {backup_dir}")

    if diff or dry_run:
        # Process files individually to get original content for diff
        files = list(path.rglob(pattern))

        results: list[dict] = []
        total_changes = 0

        click.echo(f"\nProcessing: {len(files)} file(s)")

        for file_path in sorted(files):
            if any(skip_name in file_path.parts for skip_name in skip):
                continue

            rel_path = str(file_path.relative_to(path))
            result = engine.process_file(file_path)

            if result.success:
                total_changes += len(result.changes_made)
                icon = "[+]" if len(result.changes_made) > 0 else "[=]"
                click.echo(f"  {icon} {rel_path} ({len(result.changes_made)} changes)")

                if dry_run and len(result.changes_made) > 0:
                    click.echo("  [DRY-RUN] Changes that would be made:")
                    for change in result.changes_made:
                        if "SECURITY:" in change or "AUTO-FIX:" in change:
                            click.secho(f"    [!] {change}", fg="yellow")
                        else:
                            click.echo(f"    * {change}")

                if diff and result.original.content != result.transformed_content:
                    click.echo("\n" + "=" * 60)
                    click.echo(f"DIFF: {rel_path}")
                    click.echo("=" * 60)
                    click.echo(show_diff(
                        result.original.content,
                        result.transformed_content,
                        rel_path
                    ))
            else:
                click.echo(f"  [E] {rel_path}: {result.error}")

            results.append({
                'file': rel_path,
                'success': result.success,
                'changes': len(result.changes_made),
                'error': result.error,
            })

        success_count = sum(1 for r in results if r['success'])
        failed_count = sum(1 for r in results if not r['success'])

        click.echo(f"\nSummary: {success_count} ok, {failed_count} failed, {total_changes} total changes")
        return 0

    # Default behavior (no dry-run, no diff)
    files = list(path.rglob(pattern))
    files = [f for f in files if not any(skip_name in f.parts for skip_name in skip)]

    click.echo(f"\nProcessing: {len(files)} file(s)")

    total_changes = 0
    written_count = 0

    if parallel or workers:
        # Parallel processing
        max_w = workers if workers else None
        click.echo(f"[PARALLEL] Using {max_w or os.cpu_count() or 4} workers")
        workers_count = max_w or os.cpu_count() or 4

        with ThreadPoolExecutor(max_workers=workers_count) as executor:
            futures = {
                executor.submit(_process_single_file, fp, engine, path): fp
                for fp in sorted(files)
            }
            # Use as_completed to print results as they finish
            results: list[dict] = []
            for future in as_completed(futures):
                fp = futures[future]
                try:
                    item = future.result()
                    result = item['result']
                    rel_path = item['rel_path']
                except Exception as e:
                    result = None
                    rel_path = str(fp.relative_to(path))

                if result and result.success:
                    total_changes += len(result.changes_made)
                    icon = "[+]" if len(result.changes_made) > 0 else "[=]"
                    click.echo(f"  {icon} {rel_path} ({len(result.changes_made)} changes)")

                    if in_place and result.original.content != result.transformed_content:
                        if backup and backup_dir:
                            backup_path = backup_dir / rel_path
                            backup_path.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(fp, backup_path)

                        try:
                            with open(fp, 'w', encoding='utf-8') as fh:
                                fh.write(result.transformed_content)
                            written_count += 1
                        except Exception as e:
                            click.echo(f"    [ERROR] Failed to write: {e}")
                else:
                    err = result.error if result else str(e)
                    click.echo(f"  [E] {rel_path}: {err}")

                results.append({
                    'file': rel_path,
                    'success': result.success if result else False,
                    'changes': len(result.changes_made) if result else 0,
                    'error': result.error if result else str(e),
                })
    else:
        # Sequential processing
        results: list[dict] = []
        for file_path in sorted(files):
            rel_path = str(file_path.relative_to(path))
            result = engine.process_file(file_path)

            if result.success:
                total_changes += len(result.changes_made)
                icon = "[+]" if len(result.changes_made) > 0 else "[=]"
                click.echo(f"  {icon} {rel_path} ({len(result.changes_made)} changes)")

                if in_place and result.original.content != result.transformed_content:
                    if backup and backup_dir:
                        backup_path = backup_dir / rel_path
                        backup_path.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(file_path, backup_path)

                    try:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(result.transformed_content)
                        written_count += 1
                    except Exception as e:
                        click.echo(f"    [ERROR] Failed to write: {e}")
            else:
                click.echo(f"  [E] {rel_path}: {result.error}")

            results.append({
                'file': rel_path,
                'success': result.success,
                'changes': len(result.changes_made),
                'error': result.error,
            })

    success_count = sum(1 for r in results if r['success'])
    failed_count = sum(1 for r in results if not r['success'])

    click.echo(f"\nSummary: {success_count} ok, {failed_count} failed, {total_changes} total changes")

    if in_place:
        if backup and backup_dir:
            click.echo(f"[OK] --in-place completed with backup in: {backup_dir}")
        else:
            click.echo(f"[OK] --in-place completed (no backup created)")
        click.echo(f"[OK] Files modified: {written_count}")

    # Export manifest if requested
    if export_manifest:
        manifest_path = Path(dir_path) / '.pyneat.manifest.json'
        try:
            import json
            manifest_data = {
                'version': __version__,
                'dir': str(dir_path),
                'pattern': pattern,
                'files_processed': success_count,
                'files_failed': failed_count,
                'total_changes': total_changes,
            }
            with open(manifest_path, 'w', encoding='utf-8') as f:
                json.dump(manifest_data, f, indent=2)
            click.echo(f"[MANIFEST] Exported: {manifest_path}")
        except Exception as e:
            click.echo(f"[WARN] Manifest export failed: {e}", err=True)

    return 0


@cli.command()
def rules():
    """List available cleaning rules by package."""
    click.echo("=" * 60)
    click.echo("PACKAGE SYSTEM")
    click.echo("=" * 60)
    click.echo("")
    click.echo("  pyneat clean file.py                    # Default: safe package")
    click.echo("  pyneat clean file.py --package conservative  # Adds cleanup rules")
    click.echo("  pyneat clean file.py --package destructive   # Adds aggressive rules")
    click.echo("")
    click.echo("=" * 60)
    click.echo("PACKAGE: safe (default)")
    click.echo("=" * 60)
    click.echo("Always enabled, won't break your code.")
    click.echo("")
    click.echo("  * is_not_none        - Fixes != None to is not None (PEP8)")
    click.echo("  * range_len_pattern  - Fixes range(len()) anti-pattern")
    click.echo("  * security           - Detects os.system, pickle, secrets")
    click.echo("  * typing             - Suggests type annotations")
    click.echo("  * quality            - Detects magic numbers, empty except")
    click.echo("  * performance        - Detects inefficient loops")
    click.echo("")
    click.echo("=" * 60)
    click.echo("PACKAGE: conservative (--package conservative)")
    click.echo("=" * 60)
    click.echo("Adds cleanup rules. Safe to use, may change code style.")
    click.echo("")
    click.echo("  --enable-unused       - Removes unused imports")
    click.echo("  --enable-fstring      - Converts .format() to f-strings")
    click.echo("  --enable-dataclass    - Suggests @dataclass decorator")
    click.echo("  --enable-magic-numbers - Adds MAGIC comments to large numbers")
    click.echo("")
    click.echo("=" * 60)
    click.echo("PACKAGE: destructive (--package destructive)")
    click.echo("=" * 60)
    click.echo("Adds aggressive rules. MAY BREAK CODE - always review changes.")
    click.echo("")
    click.echo("  --enable-import-cleaning - Rewrite/reorder all imports")
    click.echo("  --enable-naming        - Rename classes (only class def, safe)")
    click.echo("  --enable-refactoring   - Refactor nested if, change except behavior")
    click.echo("  --enable-comment-clean - Remove TODO/FIXME with content")
    click.echo("  --enable-redundant     - Simplify x==True, ==False (may change truthiness)")
    click.echo("  --enable-dead-code     - Delete unused functions/classes")
    click.echo("  --enable-debug-clean   - Remove print/debug calls (see debug modes)")
    click.echo("  --enable-match-case    - Suggests match-case (Python 3.10+)")
    click.echo("")
    click.echo("=" * 60)
    click.echo("DEBUG CLEANER MODES")
    click.echo("=" * 60)
    click.echo("  --keep-all-prints    (default) Keeps all print calls")
    click.echo("  --safe-debug-clean     Only removes debug-like prints")
    click.echo("  --aggressive-clean    Removes ALL print/console.log calls")
    click.echo("")
    click.echo("=" * 60)
    click.echo("TIPS")
    click.echo("=" * 60)
    click.echo("  --dry-run / --diff    Preview changes before writing")
    click.echo("  --backup / -b          Backup files before in-place editing")
    click.echo("  --enable-all           Enable all rules (use with caution)")
    click.echo("  --check-conflicts      Detect overlapping modifications")


# --------------------------------------------------------------------------
# Security scan commands
# --------------------------------------------------------------------------


@cli.command()
@click.argument('target', type=click.Path(exists=True))
@click.option('--severity', is_flag=True, help='Show severity levels (CRITICAL/HIGH/MEDIUM/LOW/INFO)')
@click.option('--cvss', is_flag=True, help='Show CVSS scores and vectors')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'sarif']),
              default='text', help='Output format')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium']),
              default=None, help='Exit with code 1 if issues >= severity found')
@click.option('--skip-deps', is_flag=True, help='Skip dependency vulnerability scan')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--rust/--no-rust', 'use_rust', default=None,
              help='Force enable/disable Rust scanner (default: auto-detect)')
def check(target, severity, cvss, output, format, fail_on, skip_deps, verbose, use_rust):
    """Security scan - detect vulnerabilities without auto-fix.

    Runs the full security pack (50+ rules) against the target file or directory.
    Shows findings sorted by severity with CWE/OWASP mapping and fix guidance.

    Examples:
        pyneat check app.py
        pyneat check src/ --severity --cvss
        pyneat check . --fail-on critical --output report.json
        pyneat check . --format sarif --output results.sarif
    """
    from pyneat.rules.security import SecurityScannerRule
    from pyneat.rules.security_registry import SECURITY_RULES_REGISTRY
    from pyneat.config import IgnoreManager
    from pyneat.core.engine import RuleEngine
    from pyneat.core.types import SecurityFinding, SecuritySeverity
    import json
    import time

    target_path = Path(target)
    ignore_mgr = IgnoreManager()

    # Try Rust scanner first if available and not disabled
    rust_results = []
    if use_rust is None or use_rust:
        from pyneat.scanner.rust_scanner import get_scanner
        scanner = get_scanner()
        if scanner.is_available:
            if verbose:
                click.echo(f"Using Rust scanner (v{scanner.version}) for security scan")
            rust_results = scanner.scan_file(str(target_path))
        elif use_rust:
            click.echo("Warning: Rust scanner requested but not available", err=True)

    # Build security engine for Python fallback
    engine = RuleEngine([SecurityScannerRule()])

    start_time = time.time()
    all_findings: List[SecurityFinding] = []
    total_files = 0

    # Scan code files
    if target_path.is_file():
        files_to_scan = [target_path]
    else:
        files_to_scan = list(target_path.rglob("*.py"))
        files_to_scan = [f for f in files_to_scan if not any(
            skip in f.parts for skip in ["__pycache__", ".venv", "venv", ".git"]
        )]

    for file_path in sorted(files_to_scan):
        total_files += 1
        result = engine.process_file(file_path)

        for finding in result.security_findings:
            # Update finding with file info
            updated_finding = SecurityFinding(
                rule_id=finding.rule_id,
                severity=finding.severity,
                confidence=finding.confidence,
                cwe_id=finding.cwe_id,
                owasp_id=finding.owasp_id,
                cvss_score=finding.cvss_score,
                cvss_vector=finding.cvss_vector,
                file=str(file_path),
                start_line=finding.start_line,
                end_line=finding.end_line,
                snippet=finding.snippet,
                problem=finding.problem,
                fix_constraints=finding.fix_constraints,
                do_not=finding.do_not,
                verify=finding.verify,
                resources=finding.resources,
                can_auto_fix=finding.can_auto_fix,
                auto_fix_available=finding.auto_fix_available,
                auto_fix_before=finding.auto_fix_before,
                auto_fix_after=finding.auto_fix_after,
                auto_fix_diff=finding.auto_fix_diff,
            )
            # Check ignores
            if not ignore_mgr.should_ignore(
                updated_finding.rule_id, file_path, updated_finding.start_line
            ):
                all_findings.append(updated_finding)

    # Scan dependencies if not skipped
    dep_findings = []
    if not skip_deps:
        from pyneat.tools.security.dependency_scanner import DependencyScanner
        scanner = DependencyScanner()
        if target_path.is_file():
            parent_dir = target_path.parent
        else:
            parent_dir = target_path
        dep_findings = scanner.scan_directory(parent_dir)

    elapsed = time.time() - start_time

    # Aggregate by severity
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "dep": len(dep_findings)}
    for f in all_findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    if format == 'json':
        output_data = {
            "scan_version": "1.0.0",
            "timestamp": __import__('datetime').datetime.now().isoformat(),
            "target": str(target_path),
            "total_files": total_files,
            "scan_duration_seconds": round(elapsed, 2),
            "summary": summary,
            "findings": [f.to_dict() for f in all_findings],
            "dependency_findings": [d.to_dict() for d in dep_findings],
        }
        json_output = json.dumps(output_data, indent=2)
        if output:
            Path(output).write_text(json_output, encoding="utf-8")
            click.echo(f"[OK] Results written to {output}")
        else:
            click.echo(json_output)
        return 0

    # Text format (default)
    _print_security_banner(summary, total_files, elapsed)

    # Print findings grouped by severity
    severity_order = [
        (SecuritySeverity.CRITICAL, "CRITICAL", "red"),
        (SecuritySeverity.HIGH, "HIGH", "red"),
        (SecuritySeverity.MEDIUM, "MEDIUM", "yellow"),
        (SecuritySeverity.LOW, "LOW", "blue"),
        (SecuritySeverity.INFO, "INFO", "cyan"),
    ]

    for sev_class, sev_label, color in severity_order:
        findings_for_sev = [f for f in all_findings if f.severity == sev_class]
        if not findings_for_sev:
            continue

        click.echo("")
        click.secho(f"  [{sev_label}] {len(findings_for_sev)} issues", fg=color, bold=True)

        for f in findings_for_sev:
            location = f"{f.file}:{f.start_line}" if f.file else f"line {f.start_line}"
            click.echo(f"    {f.rule_id} - {f.problem}")
            click.echo(f"      at {location}")
            if severity:
                extra = f"  CWE={f.cwe_id} CVSS={f.cvss_score}"
                if f.owasp_id:
                    extra += f" OWASP={f.owasp_id}"
                click.echo(f"      {extra}")
            if cvss:
                click.echo(f"      CVSS: {f.cvss_vector}")

            # Show fix guidance
            if f.fix_constraints:
                click.echo(f"      Fix: {f.fix_constraints[0]}")

    # Print dependency findings
    if dep_findings:
        click.echo("")
        click.secho("  DEPENDENCY SCAN", fg="yellow", bold=True)
        for dep in dep_findings:
            severity_str = dep.severity.upper()
            click.echo(f"    [{severity_str}] {dep.package}=={dep.version}")
            click.echo(f"      {dep.description}")
            if dep.cve_id:
                click.echo(f"      CVE: {dep.cve_id}")
            if dep.ghsa_id:
                click.echo(f"      GHSA: {dep.ghsa_id}")
            if dep.fixed_version:
                click.echo(f"      Fix: Upgrade to >={dep.fixed_version}")

    # Summary line
    click.echo("")
    total_issues = sum(summary.values()) - summary.get("dep", 0)
    total_deps = summary.get("dep", 0)
    click.echo(f"  Total: {total_issues} code issues, {total_deps} dependency issues")

    # Determine exit code
    exit_code = 0
    if fail_on:
        fail_severities = {
            "critical": 1,
            "high": 2,
            "medium": 3,
        }
        fail_threshold = fail_severities.get(fail_on, 0)
        current_threshold = 999
        for sev, label in severity_order:
            count = summary.get(sev, 0)
            if count > 0:
                current_threshold = fail_severities.get(sev, 0)
                break

        if current_threshold <= fail_threshold:
            exit_code = 1
            click.echo("")
            click.secho(f"  [FAIL] Found {sev_label} issue(s) - exiting with code 1", fg="red", bold=True)

    return exit_code


def _print_security_banner(summary: Dict[str, int], total_files: int, elapsed: float) -> None:
    """Print the security scan results banner."""
    click.echo("")
    click.echo("+======================================================================+")
    click.echo("|              PYNEAT SECURITY SCAN RESULTS                    |")
    click.echo("+======================================================================+")
    click.echo(f"|  Total files scanned: {total_files:<42}|")
    click.echo(f"|  Scan time: {elapsed:.2f}s{' ' * 47}|")
    click.echo("+======================================================================+")

    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    info = summary.get("info", 0)
    dep = summary.get("dep", 0)

    def fmt(label, count):
        return f"|  [{label}] {count:<48}|"

    click.echo(fmt("CRITICAL", f"{critical} issues"))
    click.echo(fmt("HIGH", f"{high} issues"))
    click.echo(fmt("MEDIUM", f"{medium} issues"))
    click.echo(fmt("LOW", f"{low} issues"))
    click.echo(fmt("INFO", f"{info} issues"))
    click.echo("+======================================================================+")
    if dep > 0:
        click.echo(f"|  Dependency issues: {dep:<44}|")
    click.echo("+======================================================================+")


@cli.command()
@click.argument('rule_id')
@click.option('--file', '-f', type=click.Path(exists=True), help='File containing the issue')
@click.option('--line', '-l', type=int, help='Line number of the issue')
def explain(rule_id, file, line):
    """Show detailed fix guidance for a security rule.

    Displays problem description, fix constraints, common mistakes to avoid,
    verification steps, and documentation links.

    Examples:
        pyneat explain SEC-001
        pyneat explain SEC-014 --file app.py --line 42
    """
    from pyneat.rules.security_registry import get_security_rule, SECURITY_RULES_REGISTRY

    # Support both SEC-001 and SEC001 formats
    normalized_id = rule_id.upper()
    if not normalized_id.startswith("SEC-"):
        normalized_id = f"SEC-{normalized_id[3:5]}" if len(normalized_id) >= 5 else normalized_id

    meta = get_security_rule(normalized_id)
    if not meta:
        # List all available rules
        click.echo(f"[ERROR] Unknown rule: {rule_id}")
        click.echo("")
        click.echo("Available rules:")
        for rid in sorted(SECURITY_RULES_REGISTRY.keys()):
            click.echo(f"  {rid}: {SECURITY_RULES_REGISTRY[rid].name}")
        return 1

    click.echo("")
    click.secho(f"  {meta.id}: {meta.name}", fg="cyan", bold=True)
    click.echo(f"  Severity: {meta.severity.upper()}")
    if meta.cwe_id:
        click.echo(f"  CWE: {meta.cwe_id} ({meta.cwe_name})")
    if meta.owasp_id:
        click.echo(f"  OWASP: {meta.owasp_id} - {meta.owasp_name}")
    click.echo(f"  CVSS: {meta.cvss_base} ({meta.cvss_vector})")
    click.echo("")
    click.secho("  Description:", bold=True)
    click.echo(f"  {meta.description}")
    click.echo("")
    click.secho("  Fix Constraints:", bold=True)
    for constraint in meta.fix_constraints:
        click.echo(f"  * {constraint}")
    click.echo("")
    click.secho("  Do NOT:", fg="red", bold=True)
    for dont in meta.do_not:
        click.echo(f"  * {dont}")
    click.echo("")
    click.secho("  How to Verify:", fg="green", bold=True)
    for verify_item in meta.verify:
        click.echo(f"  * {verify_item}")
    click.echo("")
    click.secho("  Documentation:", bold=True)
    for resource in meta.resources:
        click.echo(f"  * {resource}")
    if meta.can_auto_fix:
        click.echo("")
        click.secho("  [AUTO-FIX AVAILABLE]", fg="green")
    else:
        click.echo("")
        click.secho("  [NO AUTO-FIX - Manual remediation required]", fg="yellow")

    # Show snippet if file/line provided
    if file and line:
        try:
            lines = Path(file).read_text(encoding="utf-8").splitlines()
            if 0 < line <= len(lines):
                click.echo("")
                click.secho(f"  Code at {file}:{line}:", bold=True)
                for i in range(max(0, line - 3), min(len(lines), line + 2)):
                    prefix = ">>>" if i + 1 == line else "   "
                    click.echo(f"  {prefix} {i + 1:4d} | {lines[i]}")
        except Exception:
            pass

    return 0


@cli.command()
@click.argument('rule_id')
@click.option('--file', '-f', type=click.Path(), help='Specific file (per-instance ignore)')
@click.option('--line', '-l', type=int, help='Line number (per-instance)')
@click.option('--global', 'is_global', is_flag=True, help='Disable rule for entire project')
@click.option('--reason', '-r', type=str, required=True, help='Reason for ignoring (required)')
def ignore(rule_id, file, line, is_global, reason):
    """Ignore a security rule (per-instance or globally).

    Per-instance ignore: ignores SEC-001 at a specific file+line location.
    Global ignore: disables the rule entirely for this project.

    Examples:
        pyneat ignore SEC-001 --file deploy.py --line 42 --reason "already sanitized"
        pyneat ignore SEC-003 --global --reason "intentional eval in sandbox"
    """
    from pyneat.config import IgnoreManager

    manager = IgnoreManager()

    if is_global:
        manager.add_global(rule_id, reason)
        click.secho(f"[OK] Disabled {rule_id} globally", fg="green")
        click.echo(f"     Reason: {reason}")
        click.echo(f"     To re-enable: pyneat ignore --remove {rule_id}")
    elif file and line:
        manager.add_per_instance(rule_id, Path(file), line, reason)
        click.secho(f"[OK] Ignored {rule_id} at {file}:{line}", fg="green")
        click.echo(f"     Reason: {reason}")
    else:
        click.secho("[ERROR] Must specify --file and --line for per-instance ignore, or --global", fg="red")
        click.echo("")
        click.echo("Usage:")
        click.echo("  Per-instance: pyneat ignore SEC-001 --file app.py --line 42 --reason 'safe'")
        click.echo("  Global:       pyneat ignore SEC-003 --global --reason 'intentional'")
        return 1

    return 0


@cli.command()
@click.argument('target', type=click.Path(exists=True))
@click.option('--format', '-f', type=click.Choice(['json', 'sarif', 'html']),
              default='json', help='Report format')
@click.option('--output', '-o', type=click.Path(), required=True, help='Output file path')
def report(target, format, output):
    """Generate a security report for CI/CD integration.

    Supports SARIF format for GitHub Code Scanning, Azure DevOps, and GitLab.
    Supports JSON format for custom integrations.

    Examples:
        pyneat report . --format sarif --output security.sarif
        pyneat report . --format json --output report.json
    """
    from pyneat.rules.security import SecurityScannerRule
    from pyneat.core.engine import RuleEngine
    from pyneat.config import IgnoreManager
    import json
    import time

    target_path = Path(target)
    ignore_mgr = IgnoreManager()
    engine = RuleEngine([SecurityScannerRule()])

    start_time = time.time()
    all_findings = []
    total_files = 0

    if target_path.is_file():
        files_to_scan = [target_path]
    else:
        files_to_scan = list(target_path.rglob("*.py"))
        files_to_scan = [f for f in files_to_scan if not any(
            skip in f.parts for skip in ["__pycache__", ".venv", "venv", ".git"]
        )]

    for file_path in sorted(files_to_scan):
        total_files += 1
        result = engine.process_file(file_path)

        for finding in result.security_findings:
            if not ignore_mgr.should_ignore(finding.rule_id, file_path, finding.start_line):
                updated = finding
                all_findings.append(updated)

    elapsed = time.time() - start_time

    if format == 'sarif':
        _generate_sarif_report(all_findings, target_path, total_files, elapsed, output)
    else:
        _generate_json_report(all_findings, target_path, total_files, elapsed, output)

    click.echo(f"[OK] Report written to {output}")
    return 0


def _generate_sarif_report(findings, target_path, total_files, elapsed, output_path):
    """Generate SARIF format report."""
    import json
    from datetime import datetime

    rules = {}
    results = []

    for f in findings:
        rule_id = f"PYNEAT/{f.rule_id}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.rule_id,
                "shortDescription": {
                    "text": f.problem
                },
                "fullDescription": {
                    "text": f"Security issue: {f.rule_id} - {f.problem}"
                },
                "defaultConfiguration": {
                    "level": _sarif_level(f.severity)
                },
                "help": {
                    "text": f"CWE-{f.cwe_id}" if f.cwe_id else "",
                    "markdown": f"**Fix:** {'; '.join(f.fix_constraints)}"
                },
                "properties": {
                    "tags": [f.severity, f"CWE-{f.cwe_id}" if f.cwe_id else ""],
                    "precision": "high" if f.confidence > 0.9 else "medium",
                }
            }

        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f.file,
                    "uriBaseId": "%SRCROOT%"
                },
                "region": {
                    "startLine": f.start_line,
                    "endLine": f.end_line if f.end_line else f.start_line,
                    "snippet": {"text": f.snippet} if f.snippet else None
                }
            }
        }

        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(f.severity),
            "message": {
                "text": f.problem,
                "markdown": f"**{f.rule_id}: {f.problem}**\n\nCWE-{f.cwe_id} | CVSS {f.cvss_score}"
            },
            "locations": [location],
            "properties": {
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
            }
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PyNeat",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/pyneat/pyneat",
                    "rules": list(rules.values())
                }
            },
            "results": results,
            "properties": {
                "totalFiles": total_files,
                "scanDuration": elapsed,
            }
        }]
    }

    Path(output_path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def _sarif_level(severity: str) -> str:
    """Convert severity to SARIF level."""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity, "warning")


def _generate_json_report(findings, target_path, total_files, elapsed, output_path):
    """Generate JSON format report."""
    import json
    from datetime import datetime

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    report_data = {
        "report_version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "target": str(target_path),
        "total_files": total_files,
        "scan_duration_seconds": round(elapsed, 2),
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
    }

    Path(output_path).write_text(json.dumps(report_data, indent=2), encoding="utf-8")


@cli.command(name='security-db')
@click.option('--update', '-u', is_flag=True, help='Update CVE and GitHub Advisory databases')
@click.option('--status', is_flag=True, help='Show database status')
@click.option('--force', is_flag=True, help='Force update (ignore cache age)')
def security_db(update, status, force):
    """Manage security databases (CVE, GitHub Advisory).

    Examples:
        pyneat security-db --status
        pyneat security-db --update
        pyneat security-db --update --force
    """
    from pyneat.tools.security.advisory_db import CVEDatabase, GitHubAdvisoryDB
    import click

    cve_db = CVEDatabase()
    gh_db = GitHubAdvisoryDB()

    if status or (not update):
        click.echo("")
        click.secho("  Security Database Status", bold=True)
        click.echo("")

        cve_status = cve_db.get_status()
        click.secho("  NVD CVE Database:", bold=True)
        click.echo(f"    Total records: {cve_status['total_records']}")
        click.echo(f"    Last updated: {cve_status['age']}")
        if cve_status['severity_counts']:
            counts = cve_status['severity_counts']
            click.echo(f"    By severity: CRITICAL={counts.get('CRITICAL',0)} "
                       f"HIGH={counts.get('HIGH',0)} MEDIUM={counts.get('MEDIUM',0)} "
                       f"LOW={counts.get('LOW',0)}")
        click.echo(f"    Cache: {cve_status['cache_file']}")
        click.echo("")

        gh_status = gh_db.get_status()
        click.secho("  GitHub Advisory Database:", bold=True)
        click.echo(f"    Total records: {gh_status['total_records']}")
        click.echo(f"    Last updated: {gh_status['age']}")
        if gh_status['ecosystem_counts']:
            for eco, count in sorted(gh_status['ecosystem_counts'].items()):
                click.echo(f"    {eco}: {count}")
        click.echo(f"    Cache: {gh_status['cache_file']}")

    if update:
        click.echo("")
        click.secho("  Updating databases...", bold=True)

        click.echo("  Fetching CVE data from NVD...")
        try:
            new_cve = cve_db.update(force=force)
            click.secho(f"    Added {new_cve} new CVE records", fg="green")
        except Exception as e:
            click.secho(f"    CVE update failed: {e}", fg="red")

        click.echo("  Fetching GitHub Advisories...")
        try:
            new_gh = gh_db.update(force=force)
            click.secho(f"    Added {new_gh} new advisory records", fg="green")
        except Exception as e:
            click.secho(f"    GitHub Advisory update failed: {e}", fg="red")

        click.echo("")
        click.secho("  Update complete!", fg="green")
        click.echo("  Run 'pyneat security-db --status' to verify.")

    return 0


if __name__ == '__main__':
    cli()
