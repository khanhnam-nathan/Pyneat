"""Command-line interface for AI Cleaner."""

import sys
import os
import shutil
import difflib
import click
from pathlib import Path
from datetime import datetime

from pyneat.core.engine import RuleEngine
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


def _build_engine(config: dict, enable_security: bool, enable_quality: bool,
                  enable_performance: bool, enable_unused: bool,
                  enable_redundant: bool, enable_is_not_none: bool,
                  enable_magic_numbers: bool,
                  debug_clean_mode: str = 'safe') -> RuleEngine:
    """Build a RuleEngine from config dict and CLI flags.
    
    debug_clean_mode:
    - 'safe': (default) Only removes debug-like prints (keywords, log levels, variable dumps)
    - 'aggressive': Removes ALL print/console.log calls
    - 'off': Keeps all print calls (disables DebugCleaner)
    """
    rules = [
        ImportCleaningRule(RuleConfig(enabled=True)),
        NamingConventionRule(RuleConfig(enabled=True)),
        RefactoringRule(RuleConfig(enabled=True)),
        DebugCleaner(mode=debug_clean_mode),
        CommentCleaner(RuleConfig(enabled=True)),
    ]

    if enable_security or config.get("enable_security", False):
        rules.append(SecurityScannerRule(RuleConfig(enabled=True)))

    if enable_quality or config.get("enable_quality", False):
        rules.append(CodeQualityRule(RuleConfig(enabled=True)))

    if enable_performance or config.get("enable_performance", False):
        rules.append(PerformanceRule(RuleConfig(enabled=True)))

    if enable_unused or config.get("enable_unused_imports", False):
        # InitFileProtectionRule runs BEFORE UnusedImportRule to mark
        # __all__-related imports as protected markers. Order matters!
        rules.append(InitFileProtectionRule(RuleConfig(enabled=True)))
        rules.append(UnusedImportRule(RuleConfig(enabled=True)))

    if enable_redundant or config.get("enable_redundant", False):
        rules.append(RedundantExpressionRule(RuleConfig(enabled=True)))

    if enable_is_not_none or config.get("enable_is_not_none", False):
        rules.append(IsNotNoneRule(RuleConfig(enabled=True)))

    if enable_magic_numbers or config.get("enable_magic_numbers", False):
        rules.append(MagicNumberRule(RuleConfig(enabled=True)))

    return RuleEngine(rules)


# ----------------------------------------------------------------------
# CLI commands
# ----------------------------------------------------------------------


@click.group()
def cli():
    """PyNeat - Neat Python AI Code Cleaner."""
    pass


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--in-place', '-i', is_flag=True, help='Modify file in place')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--enable-security', is_flag=True, help='Enable security scanning')
@click.option('--enable-quality', is_flag=True, help='Enable code quality checks')
@click.option('--enable-performance', is_flag=True, help='Enable performance checks')
@click.option('--enable-unused', is_flag=True, help='Enable unused import detection')
@click.option('--enable-redundant', is_flag=True, help='Enable redundant expression simplification')
@click.option('--enable-is-not-none', is_flag=True, help='Enable is not None comparison fix')
@click.option('--enable-magic-numbers', is_flag=True, help='Enable magic number detection')
@click.option('--safe-debug-clean', 'debug_mode', flag_value='safe', default=True, help='Smart debug removal (default) - only removes debug-like prints')
@click.option('--aggressive-clean', 'debug_mode', flag_value='aggressive', help='Remove ALL print/console.log calls')
@click.option('--keep-all-prints', 'debug_mode', flag_value='off', help='Keep all print calls (disable DebugCleaner)')
@click.option('--dry-run', is_flag=True, help='Preview changes without writing files')
@click.option('--diff', '-d', is_flag=True, help='Show unified diff of changes')
def clean(input_file: str, output: str, in_place: bool, verbose: bool,
          enable_security: bool, enable_quality: bool, enable_performance: bool,
          enable_unused: bool, enable_redundant: bool, enable_is_not_none: bool,
          enable_magic_numbers: bool, debug_mode: str, dry_run: bool, diff: bool):
    """Clean AI-generated code."""
    input_path = Path(input_file)

    config = _load_config()
    engine = _build_engine(
        config, enable_security, enable_quality, enable_performance,
        enable_unused, enable_redundant, enable_is_not_none, enable_magic_numbers,
        debug_clean_mode=debug_mode,
    )

    if verbose:
        stats = engine.get_rule_stats()
        click.echo(f"[TARGET] Loaded {stats['enabled_rules']}/{stats['total_rules']} rules")
        for rule in stats['rules']:
            status = "[OK]" if rule['enabled'] else "[X]"
            click.echo(f"  {status} {rule['name']}: {rule['description']}")

    result = engine.process_file(input_path)

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


@cli.command()
@click.argument('dir_path', type=click.Path(exists=True))
@click.option('--pattern', '-p', default="*.py", help='Glob pattern to match files')
@click.option('--in-place', '-i', is_flag=True, help='Modify files in place')
@click.option('--backup', '-b', is_flag=True, help='Create backup before in-place editing')
@click.option('--backup-suffix', default=".bak", help='Backup file suffix (default: .bak)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--enable-security', is_flag=True, help='Enable security scanning')
@click.option('--enable-quality', is_flag=True, help='Enable code quality checks')
@click.option('--enable-performance', is_flag=True, help='Enable performance checks')
@click.option('--enable-unused', is_flag=True, help='Enable unused import detection')
@click.option('--enable-redundant', is_flag=True, help='Enable redundant expression simplification')
@click.option('--enable-is-not-none', is_flag=True, help='Enable is not None comparison fix')
@click.option('--enable-magic-numbers', is_flag=True, help='Enable magic number detection')
@click.option('--safe-debug-clean', 'debug_mode', flag_value='safe', default=True, help='Smart debug removal (default)')
@click.option('--aggressive-clean', 'debug_mode', flag_value='aggressive', help='Remove ALL print/console.log calls')
@click.option('--keep-all-prints', 'debug_mode', flag_value='off', help='Keep all print calls (disable DebugCleaner)')
@click.option('--dry-run', is_flag=True, help='Preview changes without writing files')
@click.option('--diff', '-d', is_flag=True, help='Show unified diff of changes')
def clean_dir(dir_path: str, pattern: str, in_place: bool, backup: bool,
              backup_suffix: str, verbose: bool,
              enable_security: bool, enable_quality: bool, enable_performance: bool,
              enable_unused: bool, enable_redundant: bool, enable_is_not_none: bool,
              enable_magic_numbers: bool, debug_mode: str, dry_run: bool, diff: bool):
    """Clean all Python files in a directory recursively."""
    config = _load_config()
    engine = _build_engine(
        config, enable_security, enable_quality, enable_performance,
        enable_unused, enable_redundant, enable_is_not_none, enable_magic_numbers,
        debug_clean_mode=debug_mode,
    )

    if verbose:
        stats = engine.get_rule_stats()
        click.echo(f"[TARGET] Loaded {stats['enabled_rules']}/{stats['total_rules']} rules")

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

    results: list[dict] = []
    total_changes = 0
    written_count = 0

    for file_path in sorted(files):
        rel_path = str(file_path.relative_to(path))
        result = engine.process_file(file_path)

        if result.success:
            total_changes += len(result.changes_made)
            icon = "[+]" if len(result.changes_made) > 0 else "[=]"
            click.echo(f"  {icon} {rel_path} ({len(result.changes_made)} changes)")

            # Write file if in-place mode and changes were made
            if in_place and result.original.content != result.transformed_content:
                # Create backup if requested
                if backup and backup_dir:
                    backup_path = backup_dir / rel_path
                    backup_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(file_path, backup_path)

                # Write cleaned content
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

    return 0


@cli.command()
def rules():
    """List available cleaning rules."""
    click.echo("Always-on rules:")
    click.echo("  * ImportCleaningRule   - Standardizes and deduplicates import statements")
    click.echo("  * NamingConventionRule - Enforces PEP8 naming conventions")
    click.echo("  * RefactoringRule      - Refactors complex nested code structures")
    click.echo("  * CommentCleaner       - Removes empty TODO/AI boilerplate comments")
    click.echo("")
    click.echo("DebugCleaner modes (mutually exclusive flags):")
    click.echo("  --safe-debug-clean    (default) Only removes debug-like prints")
    click.echo("  --aggressive-clean   Removes ALL print/console.log calls")
    click.echo("  --keep-all-prints    Keeps all print calls (no removal)")
    click.echo("")
    click.echo("Optional rules (use flags):")
    click.echo("  --enable-security     SecurityScannerRule  - Detects SQL injection, secrets, eval()")
    click.echo("  --enable-quality      CodeQualityRule     - Detects magic numbers, empty except")
    click.echo("  --enable-performance  PerformanceRule     - Detects inefficient loops")
    click.echo("  --enable-unused       UnusedImportRule    - Removes genuinely unused imports (AST)")
    click.echo("  --enable-redundant    RedundantExpressionRule - Simplifies x == True, str(str(x))")
    click.echo("  --enable-is-not-none   IsNotNoneRule       - Fixes != None to is not None")
    click.echo("  --enable-magic-numbers MagicNumberRule    - Detects magic numbers (> 100)")


if __name__ == '__main__':
    cli()
