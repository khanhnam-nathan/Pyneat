"""Command-line interface for AI Cleaner.

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

For commercial licensing, contact: khanhnam.copywriting@gmail.com
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
from pyneat.core.incremental_cache import IncrementalCache
from pyneat import __version__
from pyneat.core.types import RuleConfig, AgentMarker
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
from pyneat.plugins.loader import PluginLoader

# ----------------------------------------------------------------------
# Logo
# ----------------------------------------------------------------------

def _print_logo() -> None:
    """Print minimalist PyNEAT logo at the top of terminal output."""
    click.echo("")
    click.echo(click.style(" PyNEAT ", fg="white", bg="cyan", bold=True) +
                click.style(f"  v{__version__}  ", fg="cyan", bold=False) +
                click.style("Python AI Code Cleaner & Security Scanner", fg="bright_black"))
    click.echo("")


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


def _inject_pyneat_comments(content: str, markers: list, language: str) -> str:
    """Inject PYNAGENT YAML comments for each AgentMarker into the source code.

    Each marker is injected as a multi-line YAML comment block immediately
    before the line it references. Duplicate markers (same line) are
    deduplicated.

    Args:
        content: The source code content.
        markers: List of AgentMarker objects.
        language: Programming language for comment syntax.

    Returns:
        Modified content with PYNAGENT comments injected.
    """
    lines = content.splitlines(keepends=True)
    # Handle files without trailing newline
    if lines and not lines[-1].endswith('\n'):
        trailing_newline = False
        lines[-1] = lines[-1] + '\n'
    else:
        trailing_newline = True

    # Group markers by line number, deduplicate
    markers_by_line: dict[int, list] = {}
    seen: set = set()
    for m in markers:
        key = (m.line, m.issue_type, m.rule_id)
        if key not in seen:
            seen.add(key)
            markers_by_line.setdefault(m.line, []).append(m)

    # Build annotation lines per target line
    insert_map: dict[int, list[str]] = {}
    for line_no, line_markers in markers_by_line.items():
        for m in line_markers:
            yaml_comment = m.to_yaml_comment(language=language)
            insert_map.setdefault(line_no, []).append(yaml_comment)

    # Insert comments — process from bottom to top to preserve line numbers
    result_lines: list[str] = []
    offset = 0  # Track how many comment lines have been inserted above

    for i, line in enumerate(lines):
        real_line = i + 1
        if real_line in insert_map:
            for comment in insert_map[real_line]:
                result_lines.append(comment + '\n')
        result_lines.append(line)

    final = ''.join(result_lines)
    if not trailing_newline and final.endswith('\n'):
        final = final[:-1]
    return final


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
                  debug_clean_mode: str = 'off',
                  plugin_loader: Optional[PluginLoader] = None) -> RuleEngine:
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

    return RuleEngine(rules, plugin_loader=plugin_loader)


# ----------------------------------------------------------------------
# CLI commands
# ----------------------------------------------------------------------


@click.group()
@click.version_option(version=__version__, prog_name='pyneat')
@click.option('--color', type=click.Choice(['auto', 'always', 'never']), default='auto',
              help='Control colored output: auto (default), always, or never')
def cli(color: str):
    """PyNeat - Neat Python AI Code Cleaner."""
    import sys
    if sys.platform == 'win32':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    ctx = click.get_current_context()
    ctx.color = color == 'always'


@click.pass_context
@cli.command()
@click.argument('input_file', type=str, default='.', required=False)
@click.option('--output', '-o', type=str, default=None, help='Output file path')
@click.option('--lang', '-l', 'lang_opt', type=str, default=None,
              help='Language: javascript, typescript, go, java, rust, csharp, php, ruby, python')
@click.option('--in-place', '-i', is_flag=True, help='Modify file in place')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Suppress interactive menu and hints')
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
@click.option('--export-manifest', is_flag=True, help='Export PYNAGENT manifest YAML file')
@click.option('--annotate', is_flag=True,
              help='Inject PYNAGENT YAML comments into source code for agent handoff')
def clean(input_file: str, output: str, lang_opt: str, in_place: bool, verbose: bool,
          quiet: bool,
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
          check_conflicts: bool, clear_cache: bool, export_manifest: bool, annotate: bool):
    """Clean AI-generated code.

    Supports multi-language cleaning via --lang flag (JS, TS, Go, Java, Rust, C#, PHP, Ruby).
    """
    _print_logo()
    input_path = Path(input_file)
    if not input_path.is_absolute():
        # Try as-is first (relative to cwd)
        if not input_path.exists():
            # Try in current directory specifically
            cwd_path = Path.cwd() / input_file
            if cwd_path.exists():
                input_path = cwd_path
            elif input_path.suffix and '.' in input_file:
                # Looks like a filename without path - search recursively in cwd
                matches = list(Path.cwd().rglob(input_file))
                if len(matches) == 1:
                    input_path = matches[0]
                elif len(matches) > 1:
                    click.echo(f"[ERROR] Multiple files found matching '{input_file}':", err=True)
                    for m in matches[:5]:
                        click.echo(f"  - {m}", err=True)
                    if len(matches) > 5:
                        click.echo(f"  ... and {len(matches) - 5} more", err=True)
                    return 1
                else:
                    click.echo(f"[ERROR] File not found: {input_file}", err=True)
                    click.echo(f"  Searched in: {Path.cwd()}", err=True)
                    return 1

    if not input_path.exists():
        click.echo(f"[ERROR] File not found: {input_file}", err=True)
        return 1

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

    # Load plugins
    loader = PluginLoader()
    loader.load_all()

    engine = _build_engine(
        config, package, enable_security, enable_quality, enable_performance,
        enable_unused, enable_redundant, enable_is_not_none, enable_magic_numbers,
        enable_dead_code, enable_fstring, enable_range_len,
        enable_typing, enable_match_case, enable_dataclass,
        enable_import_cleaning, enable_naming, enable_refactoring,
        enable_comment_clean,
        debug_clean_mode=debug_mode,
        plugin_loader=loader,
    )

    # Multi-language: add universal rules
    use_universal = bool(lang_opt)
    if use_universal:
        try:
            from pyneat.rules.universal import (
                HardcodedSecretsRule, DebugArtifactsRule, TodoCommentRule,
            )
            engine.add_rule(HardcodedSecretsRule())
            engine.add_rule(DebugArtifactsRule())
            engine.add_rule(TodoCommentRule())
        except ImportError:
            pass

    # Multi-language: collect files if directory + --lang
    if lang_opt and input_path.is_dir():
        LANG_EXT_GLOBS = {
            "javascript": ["*.js", "*.jsx"],
            "typescript": ["*.ts", "*.tsx"],
            "go": ["*.go"],
            "java": ["*.java"],
            "rust": ["*.rs"],
            "csharp": ["*.cs"],
            "php": ["*.php"],
            "ruby": ["*.rb"],
            "python": ["*.py"],
        }
        lang_key = lang_opt.lower()
        if lang_key not in LANG_EXT_GLOBS:
            click.echo(f"  {click.style('[!]', fg='yellow')} Unknown language: {lang_opt}")
            return 1
        files_to_clean = []
        for glob_pat in LANG_EXT_GLOBS[lang_key]:
            files_to_clean.extend(input_path.rglob(glob_pat))
        files_to_clean = sorted([f for f in files_to_clean if not any(
            skip in f.parts for skip in ["__pycache__", ".venv", "venv", ".git"]
        )])
        if not files_to_clean:
            click.echo(f"  {click.style('[!]', fg='yellow')} No .{lang_key} files found")
            return 1

        # Process each file
        total_changes = 0
        for f in files_to_clean:
            lang = lang_opt.lower()
            r = engine.process_file(f, language=lang)
            if r.changes_made:
                if verbose:
                    for ch in r.changes_made:
                        click.echo(f"  [+] {f.name}: {ch}")
                total_changes += len(r.changes_made)

        if total_changes > 0:
            click.echo(f"  Found {total_changes} issue(s) across {len(files_to_clean)} file(s)")
        else:
            click.echo(f"  All clean across {len(files_to_clean)} file(s)")
        return 0

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

    # Export manifest if requested (Phase 1.2 — rich AgentMarker manifest)
    if export_manifest:
        manifest_path = input_path.with_suffix('.pyneat.manifest.yaml')
        try:
            markers = getattr(result, 'agent_markers', []) or []
            yaml_data = {
                'version': '2.0',
                'scan_id': f"clean-{int(time.time())}",
                'tool': 'pyneat',
                'tool_version': __version__,
                'created_at': datetime.now().isoformat(),
                'file': str(input_path),
                'rules_enabled': [r['name'] for r in engine.get_rule_stats()['rules'] if r['enabled']],
                'changes_count': len(result.changes_made) if result.changes_made else 0,
                'summary': {
                    'total': len(markers),
                    'critical': len([m for m in markers if m.severity == 'critical']),
                    'high': len([m for m in markers if m.severity == 'high']),
                    'medium': len([m for m in markers if m.severity == 'medium']),
                    'low': len([m for m in markers if m.severity == 'low']),
                    'info': len([m for m in markers if m.severity == 'info']),
                },
                'markers': [_marker_to_dict(m) for m in markers],
            }
            import yaml as yaml_mod
            with open(manifest_path, 'w', encoding='utf-8') as f:
                yaml_mod.dump(yaml_data, f, default_flow_style=False, sort_keys=False)
            click.echo(f"[MANIFEST] Exported: {manifest_path} ({len(markers)} markers)")
        except Exception as e:
            click.echo(f"[WARN] Manifest export failed: {e}", err=True)

    # Inject PYNAGENT YAML comments into source code (Phase 1.3 — agent annotation)
    if annotate:
        markers = getattr(result, 'agent_markers', []) or []
        if markers:
            annotated_content = _inject_pyneat_comments(
                result.transformed_content, markers, lang_opt or "python"
            )
            output_path_for_annotate = output_path
        else:
            click.echo("[INFO] No markers to annotate — skipping annotation")
            annotated_content = None

        if annotated_content is not None:
            result = result._replace(transformed_content=annotated_content)

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

    # Hiển thị menu gợi ý tính năng khác
    ctx = click.get_current_context()
    # Skip menu in quiet mode
    if not quiet:
        show_feature_menu("clean", f"{len(result.changes_made)} changes made", ctx)

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
        'agent_markers': getattr(result, 'agent_markers', []) or [],
    }


@cli.command()
@click.argument('dir_path', type=click.Path(exists=True), default='.', required=False)
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
@click.option('--incremental', is_flag=True, default=False,
              help='Only process files that changed since last scan (uses .pyneat-cache/)')
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
              clear_cache: bool, export_manifest: bool, incremental: bool):
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

    # Load plugins
    loader = PluginLoader()
    loader.load_all()

    engine = _build_engine(
        config, package, enable_security, enable_quality, enable_performance,
        enable_unused, enable_redundant, enable_is_not_none, enable_magic_numbers,
        enable_dead_code, enable_fstring, enable_range_len,
        enable_typing, enable_match_case, enable_dataclass,
        enable_import_cleaning, enable_naming, enable_refactoring,
        enable_comment_clean,
        debug_clean_mode=debug_mode,
        plugin_loader=loader,
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

        if incremental:
            cache = IncrementalCache().load()
            changed_files = cache.filter_changed(files)
            unchanged_count = len(files) - len(changed_files)
            files = changed_files
            click.echo(f"[INCREMENTAL] Skipped {unchanged_count} unchanged file(s), processing {len(files)} changed file(s)")

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

        if incremental:
            cache.save()

        click.echo(f"\nSummary: {success_count} ok, {failed_count} failed, {total_changes} total changes")
        return 0

    # Default behavior (no dry-run, no diff)
    files = list(path.rglob(pattern))
    files = [f for f in files if not any(skip_name in f.parts for skip_name in skip)]

    if incremental:
        cache = IncrementalCache().load()
        total_count = len(files)
        files = cache.filter_changed(files)
        unchanged_count = total_count - len(files)
        click.echo(f"[INCREMENTAL] Skipped {unchanged_count} unchanged file(s), processing {len(files)} changed file(s)")
    else:
        cache = None  # type: ignore

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
                'agent_markers': getattr(result, 'agent_markers', []) or [],
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

    if incremental:
        cache.save()
    cache = None  # type: ignore
    if export_manifest:
        manifest_path = Path(dir_path) / '.pyneat.manifest.yaml'
        try:
            all_markers: list = []
            for r in results:
                mks = r.get('agent_markers', [])
                if mks:
                    all_markers.extend(mks)
            yaml_data = {
                'version': '2.0',
                'scan_id': f"clean-{int(time.time())}",
                'tool': 'pyneat',
                'tool_version': __version__,
                'created_at': datetime.now().isoformat(),
                'dir': str(dir_path),
                'pattern': pattern,
                'files_processed': success_count,
                'files_failed': failed_count,
                'total_changes': total_changes,
                'summary': {
                    'total': len(all_markers),
                    'critical': len([m for m in all_markers if m.severity == 'critical']),
                    'high': len([m for m in all_markers if m.severity == 'high']),
                    'medium': len([m for m in all_markers if m.severity == 'medium']),
                    'low': len([m for m in all_markers if m.severity == 'low']),
                    'info': len([m for m in all_markers if m.severity == 'info']),
                },
                'markers': [_marker_to_dict(m) for m in all_markers],
            }
            import yaml as yaml_mod
            with open(manifest_path, 'w', encoding='utf-8') as f:
                yaml_mod.dump(yaml_data, f, default_flow_style=False, sort_keys=False)
            click.echo(f"[MANIFEST] Exported: {manifest_path} ({len(all_markers)} markers)")
        except Exception as e:
            click.echo(f"[WARN] Manifest export failed: {e}", err=True)
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


def _make_dep_finding(df: dict) -> 'DependencyFinding':
    """Convert a Rust DependencyFinding dict to a Python DependencyFinding object."""
    from pyneat.core.types import DependencyFinding

    kind = df.get("kind", "")
    cve_id = df.get("cve_id")
    ghsa_id = df.get("ghsa_id")
    description = df.get("description", "")

    severity_map = {"cve": "high", "license": "medium"}
    sev = severity_map.get(kind, "info")

    source = "CVE" if kind == "cve" else "License"
    if cve_id and ghsa_id:
        source = "Both"
    elif ghsa_id:
        source = "GitHub-Advisory"

    rule_id_map = {
        "cve": "SEC-DEP-001",
        "license": "SEC-DEP-002",
    }

    return DependencyFinding(
        rule_id=rule_id_map.get(kind, "SEC-DEP-UNK"),
        severity=sev,
        package=df.get("package", ""),
        version=df.get("version", ""),
        ecosystem=df.get("ecosystem", ""),
        cve_id=cve_id,
        ghsa_id=ghsa_id,
        description=description,
        fixed_version=df.get("fixed_version"),
        source=source,
        recommendation=f"Upgrade to >={df.get('fixed_version', 'latest')}" if df.get("fixed_version") else "Review and update dependency",
    )


@cli.command()
@click.argument('target', type=str, default='.', required=False)
@click.option('--lang', '-l', 'lang_opt', type=str, default=None,
              help='Language: javascript, typescript, go, java, rust, csharp, php, ruby, python')
@click.option('--severity', is_flag=True, help='Show severity levels (CRITICAL/HIGH/MEDIUM/LOW/INFO)')
@click.option('--cvss', is_flag=True, help='Show CVSS scores and vectors')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'sarif']),
              default='text', help='Output format')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium']),
              default=None, help='Exit with code 1 if issues >= severity found')
@click.option('--skip-deps', is_flag=True, help='Skip dependency vulnerability scan')
@click.option('--deps/--no-deps', 'use_deps', default=True,
              help='Enable dependency scanning (on by default, use --no-deps to disable)')
@click.option('--check-cve/--no-check-cve', default=False,
              help='Check packages against OSV.dev for CVE vulnerabilities')
@click.option('--check-license/--no-check-license', default=False,
              help='Check license compliance of dependencies')
@click.option('--lock-files', is_flag=True,
              help='Discover and list lock files in the target directory')
@click.option('--rule', '-r', 'rule_filter', multiple=True,
              help='Only run specific rules (e.g., --rule SEC-001 --rule SEC-002)')
@click.option('--exclude', '-e', multiple=True,
              help='Exclude files matching pattern (e.g., --exclude test_ --exclude .venv)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Suppress interactive menu and hints')
@click.option('--rust/--no-rust', 'use_rust', default=None,
              help='Force enable/disable Rust scanner (default: auto-detect)')
def check(target, lang_opt, severity, cvss, output, format, fail_on, skip_deps, use_deps, check_cve, check_license, lock_files, rule_filter, exclude, verbose, quiet, use_rust):
    """Security scan - detect vulnerabilities without auto-fix.

    Runs the full security pack (50+ rules) against the target file or directory.
    Supports multi-language scanning via --lang flag (JS, TS, Go, Java, Rust, C#, PHP, Ruby).

    Examples:
        pyneat check app.py
        pyneat check src/ --severity --cvss
        pyneat check . --lang javascript
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

    _print_logo()

    # Resolve target path - try current dir first, then recursive search
    target_path = Path(target)
    if not target_path.is_absolute():
        # Try as-is first (relative to cwd)
        if not target_path.exists():
            # Try in current directory specifically
            cwd_path = Path.cwd() / target
            if cwd_path.exists():
                target_path = cwd_path
            elif target_path.suffix and '.' in target:
                # Looks like a filename without path - search recursively in cwd
                matches = list(Path.cwd().rglob(target))
                if len(matches) == 1:
                    target_path = matches[0]
                elif len(matches) > 1:
                    click.echo(f"[ERROR] Multiple files found matching '{target}':", err=True)
                    for m in matches[:5]:
                        click.echo(f"  - {m}", err=True)
                    if len(matches) > 5:
                        click.echo(f"  ... and {len(matches) - 5} more", err=True)
                    return 1
                else:
                    click.echo(f"[ERROR] File not found: {target}", err=True)
                    click.echo(f"  Searched in: {Path.cwd()}", err=True)
                    return 1

    ignore_mgr = IgnoreManager()

    # Rust scanner is the primary engine for performance
    # Python engine is only used as fallback when Rust is unavailable or --no-rust is set
    rust_available = False
    if use_rust is not False:  # None or True = try Rust
        from pyneat.scanner.rust_scanner import get_scanner
        scanner = get_scanner()
        if scanner.is_available:
            rust_available = True
            if verbose:
                click.echo(f"  Using Rust scanner (v{scanner.version})")
        elif use_rust is True:
            click.echo("  Warning: Rust scanner requested but not available", err=True)

    # Python engine is ONLY used when Rust is unavailable or --no-rust is set
    # Use cases: rule development/testing, or environments without Rust binary
    if rust_available:
        engine = None  # No Python engine needed - Rust handles everything
    else:
        engine = RuleEngine([SecurityScannerRule()])
    # For multi-language mode, also add universal rules (cross-language)
    use_universal = bool(lang_opt)
    if use_universal:
        try:
            from pyneat.rules.universal import (
                HardcodedSecretsRule, DebugArtifactsRule, TodoCommentRule,
            )
            engine.add_rule(HardcodedSecretsRule())
            engine.add_rule(DebugArtifactsRule())
            engine.add_rule(TodoCommentRule())
        except ImportError:
            click.echo("Warning: Universal rules not installed, running Python-only scan")

    start_time = time.time()
    all_findings: List[SecurityFinding] = []
    all_changes: List[str] = []  # For universal rule findings
    total_files = 0

    # Multi-language glob patterns
    LANG_EXT_GLOBS = {
        "javascript": ["*.js", "*.jsx"],
        "typescript": ["*.ts", "*.tsx"],
        "go": ["*.go"],
        "java": ["*.java"],
        "rust": ["*.rs"],
        "csharp": ["*.cs"],
        "php": ["*.php"],
        "ruby": ["*.rb"],
        "python": ["*.py"],
    }

    # Scan code files
    if target_path.is_file():
        files_to_scan = [target_path]
    else:
        if lang_opt:
            lang_key = lang_opt.lower()
            if lang_key not in LANG_EXT_GLOBS:
                click.echo(f"  {click.style('[!]', fg='yellow')} Unknown language: {lang_opt}")
                click.echo(f"  Supported: {', '.join(LANG_EXT_GLOBS.keys())}")
                return 1
            globs = LANG_EXT_GLOBS[lang_key]
            files_to_scan = []
            for glob_pat in globs:
                files_to_scan.extend(target_path.rglob(glob_pat))
        else:
            files_to_scan = list(target_path.rglob("*.py"))

        files_to_scan = [f for f in files_to_scan if not any(
            skip in f.parts for skip in ["__pycache__", ".venv", "venv", ".git"]
        )]

    # Apply exclude patterns
    if exclude:
        def matches_exclude(f):
            fstr = str(f)
            for pat in exclude:
                if pat in fstr:
                    return True
            return False
        files_to_scan = [f for f in files_to_scan if not matches_exclude(f)]

    # Progress display
    total_file_count = len(files_to_scan)
    if total_file_count > 3 and not verbose:
        click.echo(f"  Scanning {total_file_count} files...")

    for idx, file_path in enumerate(sorted(files_to_scan)):
        total_files += 1
        if verbose or (total_file_count > 10 and total_file_count <= 50 and total_file_count > 3):
            click.echo(f"  [{total_files}/{total_file_count}] {file_path.name}", nl=False)
        lang = lang_opt.lower() if lang_opt else "auto"

        if rust_available:
            # Rust is primary - scan each file individually
            from pyneat.scanner.rust_scanner import get_scanner
            scanner = get_scanner()
            file_rust_results = scanner.scan_file(str(file_path))

            for rust_finding in file_rust_results:
                start_byte = rust_finding.get("start", 0)
                end_byte = rust_finding.get("end", start_byte)
                try:
                    file_content = Path(str(file_path)).read_text(encoding="utf-8")
                except Exception:
                    file_content = ""
                start_line = file_content[:start_byte].count('\n') + 1 if start_byte > 0 else 1
                end_line = file_content[:end_byte].count('\n') + 1 if end_byte > 0 else start_line
                sev_str = rust_finding.get("severity", "info")
                sev_map = {"critical": SecuritySeverity.CRITICAL, "high": SecuritySeverity.HIGH,
                           "medium": SecuritySeverity.MEDIUM, "low": SecuritySeverity.LOW}
                sev = sev_map.get(sev_str, SecuritySeverity.INFO)
                cvss_score = rust_finding.get("cvss_score")
                rust_finding_obj = SecurityFinding(
                    rule_id=rust_finding.get("rule_id", "SEC-UNK"),
                    severity=sev,
                    confidence=0.95,
                    cwe_id=rust_finding.get("cwe_id") or "",
                    owasp_id=rust_finding.get("owasp_id") or "",
                    cvss_score=float(cvss_score) if cvss_score else 0.0,
                    cvss_vector=f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if cvss_score else "",
                    file=str(file_path),
                    start_line=start_line,
                    end_line=end_line,
                    snippet=rust_finding.get("snippet", "")[:200],
                    problem=rust_finding.get("problem", "Security issue detected"),
                    fix_constraints=(rust_finding.get("fix_hint", "Fix this security issue"),),
                    do_not=("Do not ignore this finding.",),
                    verify=("Review and fix the code.",),
                    resources=(),
                    can_auto_fix=rust_finding.get("auto_fix", rust_finding.get("auto_fix_available", False)),
                    auto_fix_available=rust_finding.get("auto_fix", rust_finding.get("auto_fix_available", False)),
                    auto_fix_before=rust_finding.get("snippet", "")[:200] if rust_finding.get("replacement") else None,
                    auto_fix_after=rust_finding.get("replacement", "")[:200] if rust_finding.get("replacement") else None,
                )
                if rule_filter and rust_finding_obj.rule_id not in rule_filter:
                    continue
                if not ignore_mgr.should_ignore(rust_finding_obj.rule_id, file_path, rust_finding_obj.start_line):
                    all_findings.append(rust_finding_obj)

            if verbose or (total_file_count > 10 and total_file_count <= 50 and total_file_count > 3):
                issue_count = len(file_rust_results)
                if issue_count > 0:
                    click.echo(f"  ... {issue_count} issues", fg="yellow")
                else:
                    click.echo("  ... ok", fg="green")
        else:
            # Python engine only runs when Rust is unavailable
            result = engine.process_file(file_path, language=lang)
            if verbose or (total_file_count > 10 and total_file_count <= 50 and total_file_count > 3):
                issue_count = len(result.security_findings)
                if issue_count > 0:
                    click.echo(f"  ... {issue_count} issues", fg="yellow")
                else:
                    click.echo("  ... ok", fg="green")

            for finding in result.security_findings:
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
                if rule_filter and updated_finding.rule_id not in rule_filter:
                    continue
                if not ignore_mgr.should_ignore(updated_finding.rule_id, file_path, updated_finding.start_line):
                    all_findings.append(updated_finding)

            # Collect universal rule findings
            if use_universal and result.changes_made:
                all_changes.extend(result.changes_made)

    # Scan dependencies if not skipped
    dep_findings = []
    # Lock file discovery (no scanning, just list)
    if lock_files:
        try:
            from pyneat import discover_lockfiles as rust_discover
            lock_json = rust_discover(str(target_path))
            import json as json_mod
            lock_data = json_mod.loads(lock_json)
            if lock_data:
                click.echo("")
                click.secho("  DISCOVERED LOCK FILES", fg="cyan", bold=True)
                for lf in lock_data:
                    click.echo(f"    {lf.get('ecosystem', 'unknown')}: {lf.get('path', lf.get('file_name', '?'))}")
            else:
                click.echo("")
                click.secho("  No lock files found.", fg="yellow")
        except ImportError:
            click.echo("")
            click.secho("  Lock file discovery requires the Rust backend.", fg="yellow")
            click.echo("  Install with: pip install pyneat[rust]")

    # Full dependency scan
    if not skip_deps and use_deps:
        # Try Rust backend first for deep scanning
        try:
            from pyneat import scan_dependencies as rust_scan_deps
            rust_result = rust_scan_deps(str(target_path), check_cve=check_cve, check_license=check_license)
            import json as json_mod
            rust_data = json_mod.loads(rust_result)
            if rust_data.get("dependency_findings"):
                for df in rust_data["dependency_findings"]:
                    dep_findings.append(_make_dep_finding(df))
        except ImportError:
            pass

        # Fallback to Python scanner
        if not dep_findings:
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

    # Aggregate findings by severity
    for f in all_findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

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

    # Print universal rule findings (multi-language mode)
    if use_universal and all_changes:
        click.echo("")
        click.secho("  UNIVERSAL RULE FINDINGS", fg="cyan", bold=True)
        seen = set()
        for change in all_changes:
            if change not in seen:
                seen.add(change)
                if "[UNI-" in change:
                    click.echo(f"    {change}")

    # Summary line
    click.echo("")
    total_issues = sum(summary.values()) - summary.get("dep", 0)
    if use_universal:
        total_issues += len(all_changes)
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
        sev_label = ""
        for sev, label, _ in severity_order:
            count = summary.get(sev, 0)
            if count > 0:
                current_threshold = fail_severities.get(sev, 0)
                sev_label = label
                break

        if current_threshold <= fail_threshold:
            exit_code = 1
            click.echo("")
            click.secho(f"  [FAIL] Found {sev_label} issue(s) - exiting with code 1", fg="red", bold=True)

    # Hiển thị menu gợi ý tính năng khác (skip in quiet mode)
    if not quiet:
        ctx = click.get_current_context()
        show_feature_menu("check", f"{sum(summary.values()) - summary.get('dep', 0)} issues found", ctx)

    return exit_code


def _print_security_banner(summary: Dict[str, int], total_files: int, elapsed: float) -> None:
    """Print the security scan results banner."""
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    info = summary.get("info", 0)
    dep = summary.get("dep", 0)
    total = critical + high + medium + low + info

    click.echo("")
    click.echo(click.style("┌─", fg="bright_black") + "─" * 64 + click.style("┐", fg="bright_black"))
    click.echo(click.style("│", fg="bright_black") + f"  {click.style('Security Scan Results', bold=True)}".ljust(66) + click.style("│", fg="bright_black"))
    click.echo(click.style("├─", fg="bright_black") + "─" * 64 + click.style("┤", fg="bright_black"))
    click.echo(click.style("│", fg="bright_black") +
                f"  {total} issues  ·  {total_files} file{'s' if total_files != 1 else ''}  ·  {elapsed:.2f}s".ljust(66) +
                click.style("│", fg="bright_black"))
    click.echo(click.style("└─", fg="bright_black") + "─" * 64 + click.style("┘", fg="bright_black"))
    click.echo("")

    def sev_line(sev, label, count):
        icon = {"critical": "✗", "high": "⚠", "medium": "·", "low": "○", "info": "○"}.get(sev, "·")
        fg = {"critical": "red", "high": "yellow", "medium": "magenta", "low": "blue", "info": "bright_black"}.get(sev, "white")
        bar = "█" * min(count, 10)
        return f"  {click.style(icon, fg=fg)} {click.style(label.upper(), bold=True)}  {bar}  {count}"

    if critical > 0:
        click.echo(sev_line("critical", "CRITICAL", critical))
    if high > 0:
        click.echo(sev_line("high", "HIGH", high))
    if medium > 0:
        click.echo(sev_line("medium", "MEDIUM", medium))
    if low > 0:
        click.echo(sev_line("low", "LOW", low))
    if info > 0:
        click.echo(sev_line("info", "INFO", info))
    if dep > 0:
        click.echo(f"  {click.style('◆', fg='cyan')} DEPENDENCY  {dep}")
    click.echo("")


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
@click.argument('target', type=str, default='.', required=False)
@click.option('--format', '-f', type=click.Choice(['json', 'sarif', 'html', 'yaml', 'junit', 'gitlab', 'sonarqube', 'markdown']),
              default='json', help='Report format')
@click.option('--output', '-o', type=click.Path(), required=True, help='Output file path')
@click.option('--rust/--no-rust', 'use_rust', default=None,
              help='Force enable/disable Rust scanner (default: auto-detect, Rust is primary)')
def report(target, format, output, use_rust):
    """Generate a security report for CI/CD integration.

    Supports multiple formats for different tools:
      - sarif:   GitHub Code Scanning, Azure DevOps, GitLab SAST
      - json:    Custom integrations
      - yaml:    PyNEAT manifest (full AgentMarker data)
      - junit:   CI/CD test suites (JUnit XML)
      - gitlab:  GitLab SAST format
      - sonarqube: SonarQube Generic Issue Import
      - html:    Human-readable HTML report
      - markdown: Markdown summary

    Examples:
        pyneat report . --format sarif --output security.sarif
        pyneat report . --format yaml --output report.pyneat.yaml
        pyneat report . --format junit --output results.xml
    """
    from pyneat.core.engine import RuleEngine
    from pyneat.config import IgnoreManager
    from pyneat.core.manifest import (
        export_to_sarif, export_to_html_report, export_to_junit_xml,
        export_to_gitlab_sast, export_to_sonarqube, export_to_markdown,
    )
    from pyneat.core.types import AgentMarker, SecuritySeverity, security_finding_to_marker
    import json
    import time

    _print_logo()
    import yaml

    # Resolve target path
    target_path = Path(target)
    if not target_path.is_absolute() and not target_path.exists():
        cwd_path = Path.cwd() / target
        if cwd_path.exists():
            target_path = cwd_path
        elif target_path.suffix and '.' in target:
            matches = list(Path.cwd().rglob(target))
            if len(matches) == 1:
                target_path = matches[0]
            elif len(matches) > 1:
                click.echo(f"[ERROR] Multiple files found matching '{target}':", err=True)
                for m in matches[:5]:
                    click.echo(f"  - {m}", err=True)
                if len(matches) > 5:
                    click.echo(f"  ... and {len(matches) - 5} more", err=True)
                return 1

    if not target_path.exists():
        click.echo(f"[ERROR] Target not found: {target}", err=True)
        click.echo(f"  Searched in: {Path.cwd()}", err=True)
        return 1

    # Rust is primary scanner; Python only used as fallback
    rust_available = False
    if use_rust is not False:
        from pyneat.scanner.rust_scanner import get_scanner
        scanner = get_scanner()
        rust_available = scanner.is_available

    ignore_mgr = IgnoreManager()

    if not rust_available:
        from pyneat.rules.security import SecurityScannerRule
        engine = RuleEngine([SecurityScannerRule()])
    else:
        engine = None

    start_time = time.time()
    all_markers: List[AgentMarker] = []
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

        if rust_available:
            from pyneat.scanner.rust_scanner import get_scanner
            scanner = get_scanner()
            rust_results = scanner.scan_file(str(file_path))

            for rf in rust_results:
                start_byte = rf.get("start", 0)
                end_byte = rf.get("end", start_byte)
                try:
                    fc = Path(str(file_path)).read_text(encoding="utf-8")
                except Exception:
                    fc = ""
                sl = fc[:start_byte].count('\n') + 1 if start_byte > 0 else 1
                el = fc[:end_byte].count('\n') + 1 if end_byte > 0 else sl
                sev_str = rf.get("severity", "info")
                sev_map = {"critical": SecuritySeverity.CRITICAL, "high": SecuritySeverity.HIGH,
                           "medium": SecuritySeverity.MEDIUM, "low": SecuritySeverity.LOW}
                sev = sev_map.get(sev_str, SecuritySeverity.INFO)
                cvss_score = rf.get("cvss_score")
                from pyneat.core.types import security_finding_to_marker
                marker = AgentMarker(
                    rule_id=rf.get("rule_id", "SEC-UNK"),
                    severity=sev_str,
                    file=str(file_path),
                    line=sl,
                    end_line=el,
                    message=rf.get("problem", "Security issue detected"),
                    fix_suggestion=rf.get("fix_hint", ""),
                    cwe=rf.get("cwe_id") or "",
                    owasp=rf.get("owasp_id") or "",
                    can_auto_fix=False,
                    auto_fix_available=False,
                    auto_fix_before=rf.get("snippet", "")[:200] if rf.get("replacement") else None,
                    auto_fix_after=rf.get("replacement", "")[:200] if rf.get("replacement") else None,
                )
                if not ignore_mgr.should_ignore(marker.rule_id, file_path, marker.line):
                    all_markers.append(marker)
        else:
            result = engine.process_file(file_path)

            for finding in result.security_findings:
                if not ignore_mgr.should_ignore(finding.rule_id, file_path, finding.start_line):
                    marker = security_finding_to_marker(
                        finding, language="python", file_path=str(file_path)
                    )
                    all_markers.append(marker)

            # Also aggregate direct agent_markers from rules
            if hasattr(result, 'agent_markers') and result.agent_markers:
                for m in result.agent_markers:
                    all_markers.append(m)

    elapsed = time.time() - start_time

    # Generate report based on format
    if format == 'sarif':
        sarif_output = export_to_sarif(
            markers=all_markers,
            source_file=target_path,
            tool_name="PyNEAT",
            tool_version=__version__,
        )
        Path(output_path if (output_path := output) else output).write_text(
            json.dumps(sarif_output, indent=2), encoding="utf-8"
        )
    elif format == 'yaml':
        yaml_data = {
            'version': '2.0',
            'scan_id': f"scan-{int(time.time())}",
            'tool': 'pyneat',
            'tool_version': __version__,
            'created_at': __import__('datetime').datetime.now().isoformat(),
            'project': str(target_path),
            'total_files': total_files,
            'scan_duration_seconds': round(elapsed, 2),
            'summary': {
                'total': len(all_markers),
                'critical': len([m for m in all_markers if m.severity == 'critical']),
                'high': len([m for m in all_markers if m.severity == 'high']),
                'medium': len([m for m in all_markers if m.severity == 'medium']),
                'low': len([m for m in all_markers if m.severity == 'low']),
                'info': len([m for m in all_markers if m.severity == 'info']),
            },
            'markers': [_marker_to_dict(m) for m in all_markers],
        }
        Path(output).write_text(yaml.dump(yaml_data, default_flow_style=False, sort_keys=False), encoding="utf-8")
    elif format == 'junit':
        junit_xml = export_to_junit_xml(
            markers=all_markers,
            source_file=target_path,
            test_name=f"PyNEAT Security Scan ({target_path.name})",
        )
        Path(output).write_text(junit_xml, encoding="utf-8")
    elif format == 'gitlab':
        gitlab_data = export_to_gitlab_sast(
            markers=all_markers,
            project=str(target_path),
        )
        Path(output).write_text(json.dumps(gitlab_data, indent=2), encoding="utf-8")
    elif format == 'sonarqube':
        sq_data = export_to_sonarqube(
            markers=all_markers,
            source_file=target_path,
        )
        Path(output).write_text(json.dumps(sq_data, indent=2), encoding="utf-8")
    elif format == 'html':
        html_output = export_to_html_report(
            markers=all_markers,
            title=f"PyNEAT Security Report — {target_path.name}",
        )
        Path(output).write_text(html_output, encoding="utf-8")
    elif format == 'markdown':
        md_output = export_to_markdown(
            markers=all_markers,
            title=f"PyNEAT Security Report — {target_path.name}",
            source_file=target_path,
        )
        Path(output).write_text(md_output, encoding="utf-8")
    else:
        _generate_json_report(all_findings, target_path, total_files, elapsed, output)

    click.echo(f"[OK] Report written to {output}")
    return 0


def _marker_to_dict(m: AgentMarker) -> dict:
    """Convert an AgentMarker to a serializable dict for YAML/JSON export."""
    return {
        'marker_id': m.marker_id,
        'issue_type': m.issue_type,
        'rule_id': m.rule_id,
        'severity': m.severity,
        'line': m.line,
        'file_path': m.file_path,
        'language': m.language,
        'why': m.why,
        'hint': m.hint,
        'impact': m.impact,
        'confidence': m.confidence,
        'confidence_note': m.confidence_note,
        'can_auto_fix': m.can_auto_fix,
        'snippet': m.snippet,
        'fix_constraints': list(m.fix_constraints) if m.fix_constraints else [],
        'do_not': list(m.do_not) if m.do_not else [],
        'verify': list(m.verify) if m.verify else [],
        'resources': list(m.resources) if m.resources else [],
        'cwe_id': m.cwe_id,
        'owasp_id': m.owasp_id,
        'cvss_score': m.cvss_score,
        'detected_at': m.detected_at,
    }


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


# --------------------------------------------------------------------------
# Multi-Language Demo
# --------------------------------------------------------------------------

LANG_MAP = {
    "javascript": ("js", "JavaScript"),
    "typescript": ("ts", "TypeScript"),
    "go": ("go", "Go"),
    "java": ("java", "Java"),
    "rust": ("rs", "Rust"),
    "csharp": ("cs", "C#"),
    "php": ("php", "PHP"),
    "ruby": ("rb", "Ruby"),
    "python": ("py", "Python"),
}


# --------------------------------------------------------------------------
# Interactive Feature Menu
# --------------------------------------------------------------------------

def show_feature_menu(last_command: str = "", context: str = "", ctx: click.Context = None) -> None:
    """Show interactive menu guiding users to other features.

    Args:
        last_command: The command that was just run (e.g., "check", "clean")
        context: Optional context about what was scanned/analyzed
    """
    import select
    import threading
    import sys

    suggestions = _get_menu_suggestions(last_command, context)
    click.echo("")
    click.echo("")
    click.echo("  " + click.style("Explore More", fg="bright_black", bold=True))
    for key, (icon, title, desc, cmd) in suggestions.items():
        click.echo(f"  {click.style(f'[{key}]', fg='cyan', bold=True)} {icon} {click.style(title, bold=True)}")
        click.echo(f"      {desc}")
        click.echo(f"      → {click.style(cmd, fg='green')}")
        click.echo("")
    click.echo(f"  {click.style('[q]', fg='yellow', bold=True)} Exit  {click.style('(auto-exit in 10s)', fg='bright_black')}")
    click.echo("")

    # Non-blocking input with timeout (thread-based for cross-platform)
    choice_ref = [None]
    def read_input():
        try:
            line = sys.stdin.readline()
            choice_ref[0] = line.strip().upper()
        except Exception:
            pass

    t = threading.Thread(target=read_input, daemon=True)
    t.start()
    t.join(timeout=10)

    choice = choice_ref[0]
    if choice is None or choice in ('Q', 'QUIT', 'EXIT', ''):
        return
    _handle_menu_choice(choice, suggestions, ctx)


def _get_menu_suggestions(last_command: str, context: str) -> Dict[str, tuple]:
    """Get smart menu suggestions based on the last command.

    Returns dict of {key: (icon, title, description, command_example)}
    """
    # Chữ cái A, B, C, D cố định — luôn hiển thị 4 lựa chọn
    all_options = {
        'A': ('🔒', 'Security Check',
               'Quét lỗ hổng: SQL injection, path traversal, hardcoded secrets...',
               'pyneat check file.py'),
        'B': ('🧹', 'Clean Code',
               'Thêm type hints, xóa unused imports, số magic, debug prints...',
               'pyneat clean file.py'),
        'C': ('📖', 'Explain Rule',
               'Nguyên nhân, cách fix, CWE/OWASP, verification steps...',
               'pyneat explain SEC-001'),
        'D': ('📊', 'Export Report (JSON/SARIF)',
               'Tích hợp CI/CD: GitHub Code Scanning, GitLab SAST...',
               'pyneat report . -f sarif -o security.sarif'),
    }

    # Smart suggestions dựa trên command vừa chạy - LUÔN dùng A, B, C, D, E
    if last_command == 'check':
        ordered = ['A', 'B', 'C', 'D']
    elif last_command == 'clean':
        ordered = ['A', 'B', 'C', 'D']
    elif last_command == 'explain':
        ordered = ['A', 'B', 'C', 'D']
    elif last_command == 'rules':
        ordered = ['A', 'B', 'C', 'D']
    elif last_command == 'report':
        ordered = ['A', 'B', 'C', 'D']
    else:
        ordered = ['A', 'B', 'C', 'D']

    return {k: all_options[k] for k in ordered if k in all_options}


def _handle_menu_choice(choice: str, suggestions: Dict[str, tuple], ctx: click.Context) -> None:
    """Handle user's menu choice - run the command directly."""
    # Command map: key -> command_name (phải khớp với menu gợi ý)
    # A=Security Check -> check
    # B=Clean Code -> clean
    # C=Explain Rule -> explain
    # D=Export Report -> report
    choice_map = {
        'A': 'check',
        'B': 'clean',
        'C': 'explain',
        'D': 'report',
    }

    if choice in choice_map:
        cmd_name = choice_map[choice]
        click.echo("")
        click.echo(f"  Running: {click.style('pyneat ' + cmd_name + ' --help', fg='cyan', bold=True)}")
        click.echo("")

        # Lấy CLI group từ parent context
        try:
            cli_ctx = ctx.parent if ctx and ctx.parent else click.get_current_context()
            if cli_ctx.parent:
                cli_ctx = cli_ctx.parent
            
            sub_cmd = cli_ctx.command.commands.get(cmd_name)
            if sub_cmd:
                # Tạo context mới với --help
                sub_ctx = sub_cmd.make_context(cmd_name, ['--help'])
                sub_cmd.invoke(sub_ctx)
            else:
                click.echo(f"  {click.style('[!]', fg='red')} Command '{cmd_name}' not found")
        except SystemExit as e:
            # Help command thường exit(0) - không hiển thị lỗi
            pass
        except Exception as e:
            # Chỉ hiển thị lỗi nếu có message thực sự
            if str(e) and str(e) != '0':
                click.echo(f"  {click.style('[!]', fg='red')} Error: {e}")
    else:
        click.echo("")
        click.echo(f"  {click.style('[!]', fg='yellow', bold=True)} Invalid option.")
        click.echo(f"     Press 'q' or Enter to exit.")
        click.echo("")
        click.echo("  📚 Docs: https://pyneat.dev/docs")


@cli.command(name='audit-deps')
@click.option('--path', default='requirements.txt', help='Path to requirements.txt or project directory')
@click.option('--format', '-f', type=click.Choice(['summary', 'json', 'sarif', 'sbom']),
              default='summary', help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--sbom-format', default='cyclonedx-json',
              type=click.Choice(['cyclonedx-json', 'cyclonedx-xml', 'spdx-json']),
              help='SBOM format when using --format sbom')
def audit_deps(path, format, output, sbom_format):
    """Audit project dependencies for known vulnerabilities using OSV database.

    This command scans your requirements.txt or installed packages against
    the OSV vulnerability database to find known security issues.

    Examples:
        pyneat audit-deps
        pyneat audit-deps --format json --output vulns.json
        pyneat audit-deps --format sbom --output sbom.json
        pyneat audit-deps --path requirements.txt --format sarif --output report.sarif
    """
    from pyneat.tools.vulnerability_scanner import DependencyScanner

    scanner = DependencyScanner()

    # Parse requirements or scan installed packages
    if path and path.endswith('.txt'):
        deps = DependencyScanner._parse_requirements(path)
        scanner.scan_packages(deps)
    else:
        click.echo("Scanning installed packages...")
        scanner.scan_installed_packages()

    # Generate output
    out = None
    if format == 'summary':
        scanner.print_summary()
    elif format == 'json':
        out = scanner.generate_json_report()
    elif format == 'sarif':
        out = scanner.generateSarif()
    elif format == 'sbom':
        out = scanner.generate_sbom(sbom_format)

    if output and out:
        with open(output, 'w') as f:
            f.write(out)
        click.echo(f"\nReport written to {output}")
    elif out:
        click.echo(out)


@cli.command(name='sbom')
@click.option('--path', default='requirements.txt', help='Path to requirements.txt')
@click.option('--format', '-f', type=click.Choice(['cyclonedx-json', 'cyclonedx-xml', 'spdx-json']),
              default='cyclonedx-json', help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--include-vulns/--no-vulns', default=True,
              help='Include vulnerability data in SBOM')
def sbom_cmd(path, format, output, include_vulns):
    """Generate Software Bill of Materials (SBOM) in CycloneDX or SPDX format.

    Examples:
        pyneat sbom --format cyclonedx-json --output sbom.json
        pyneat sbom --format spdx-json --output sbom.json
    """
    from pyneat.tools.vulnerability_scanner import DependencyScanner

    scanner = DependencyScanner()

    # Parse requirements
    if path and path.endswith('.txt'):
        deps = DependencyScanner._parse_requirements(path)
        scanner.scan_packages(deps)
    else:
        scanner.scan_installed_packages()

    out = scanner.generate_sbom(format, include_vulnerabilities=include_vulns)

    if output:
        with open(output, 'w') as f:
            f.write(out)
        click.echo(f"SBOM written to {output}")
    else:
        click.echo(out)


@cli.command(name='mcp')
@click.option('--stdio', 'transport', flag_value='stdio', default=True,
              help='Use stdio transport (default, for Cursor MCP integration)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging to stderr')
def mcp(transport: str, verbose: bool):
    """Start the PyNEAT MCP server over stdio (JSON-RPC 2.0).

    This command starts the Model Context Protocol server, allowing Cursor
    and other MCP-compatible editors to invoke PyNEAT as a tool.

    \b
    Example Cursor MCP configuration:
      {
        "mcpServers": {
          "pyneat": {
            "command": "python",
            "args": ["-m", "pyneat.tools.mcp_server"]
          }
        }
      }

    Or use the CLI shortcut:
      pyneat mcp
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    from pyneat.tools.mcp_server import main
    main()


@cli.command(name='lsp')
@click.option('--stdio', is_flag=True, default=True,
              help='Use stdio transport (default, for IDE integration)')
@click.option('--tcp', is_flag=True, help='Use TCP transport')
@click.option('--port', type=int, default=4444, help='TCP port (default: 4444)')
@click.option('--scan-on-save', is_flag=True, help='Scan file on save (default: enabled)')
@click.option('--scan-on-type', is_flag=True, help='Scan as you type (requires debounce)')
@click.option('--debounce-ms', type=int, default=500,
              help='Delay in ms before scanning after keystroke (default: 500)')
@click.option('--severity', type=click.Choice(['critical', 'high', 'medium', 'low', 'info']),
              default='medium', help='Minimum severity to report (default: medium)')
@click.option('--rules', type=str, default='',
              help='Comma-separated list of rule IDs to enable (default: all)')
def lsp(stdio, tcp, port, scan_on_save, scan_on_type, debounce_ms, severity, rules):
    """Start PyNEAT LSP server for real-time IDE security scanning.

    This starts the Language Server Protocol (LSP) server that provides:
    - Real-time security diagnostics as you edit code
    - Hover tooltips with rule explanations
    - Quick-fix code actions for auto-fixable issues
    - Debounced scanning to avoid performance impact

    Usage:
        pyneat lsp                  # Start with defaults (stdio mode)
        pyneat lsp --tcp --port 4444  # TCP mode on port 4444

    For IDE integration, the extension will automatically start the LSP server.
    See .vscode-extension/ for the VS Code extension.

    Examples:
        pyneat lsp --severity high --debounce-ms 300
        pyneat lsp --rules SEC-001,SEC-002,SEC-003
    """
    try:
        from pyneat import run_lsp_server
    except ImportError:
        click.secho("[ERROR] PyNEAT Rust backend not installed.", fg="red", bold=True)
        click.echo("  Install with: pip install pyneat[rust]")
        click.echo("  Or build from source: cd pyneat-rs && cargo build --release")
        return 1

    click.echo(f"Starting PyNEAT LSP server...")
    if stdio:
        click.echo(f"  Transport: stdio (for IDE integration)")
    else:
        click.echo(f"  Transport: TCP on port {port}")
    click.echo(f"  Severity threshold: {severity}")
    click.echo(f"  Debounce: {debounce_ms}ms")
    click.echo(f"  Scan on save: {scan_on_save}")
    click.echo(f"  Scan on type: {scan_on_type}")
    if rules:
        click.echo(f"  Rules: {rules}")

    try:
        run_lsp_server(
            scan_on_save=scan_on_save,
            scan_on_type=scan_on_type,
            debounce_ms=debounce_ms,
            severity=severity,
            rules=rules if rules else None,
        )
    except KeyboardInterrupt:
        click.echo("\nPyNEAT LSP server stopped.")
    except Exception as e:
        click.secho(f"[ERROR] LSP server error: {e}", fg="red", bold=True)
        return 1

    return 0


if __name__ == '__main__':
    cli()
