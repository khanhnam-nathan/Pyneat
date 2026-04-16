"""CLI entry point for pyneat.tools.github_fuzz.

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

Usage:
    python -m pyneat.tools.github_fuzz
    python -m pyneat.tools.github_fuzz --repos django/django psf/requests
    python -m pyneat.tools.github_fuzz --combinations all --max-files 50
    python -m pyneat.tools.github_fuzz --dry-download
    python -m pyneat.tools.github_fuzz --resume ./cache.json

Run a fuzz test loop that downloads Python files from GitHub repos,
runs pyneat with multiple rule combinations, and generates debug reports.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click

# Add pyneat to path if running as a standalone script
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from pyneat.tools.github_fuzz import (
    FuzzConfig,
    run_fuzz,
    DEFAULT_REPOS,
    RULE_COMBINATIONS,
    COMBINATION_PRESETS,
)
from pyneat.tools.github_fuzz.debug_logger import FuzzLogger
from pyneat import __version__ as pyneat_version


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_header():
    click.echo(click.style("=" * 60, fg="cyan"))
    click.echo(click.style("  PyNeat GitHub Fuzz Tester", fg="cyan", bold=True))
    click.echo(click.style(f"  Version {pyneat_version}", fg="cyan"))
    click.echo(click.style("=" * 60, fg="cyan"))
    click.echo("")


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version="1.0.0", prog_name="pyneat-fuzz")
@click.option("--color/--no-color", default=True, help="Force colour output")
def cli(color: bool):
    """PyNeat GitHub Fuzz Tester.

    Continuously downloads Python files from popular GitHub repos,
    runs pyneat with all rule combinations, detects bugs, and writes
    detailed debug reports.
    """
    if not color:
        os.environ["NO_COLOR"] = "1"


@cli.command()
@click.option(
    "--repos", "-r",
    multiple=True,
    default=[],
    help="GitHub repos in 'owner/name' format (e.g. django/django). "
         "Can be specified multiple times. Defaults to top-5 repos.",
)
@click.option(
    "--combinations", "-c",
    type=click.Choice(["safe", "conservative", "destructive", "all", "quick"]),
    default="safe",
    help="Which rule combination preset to use.",
)
@click.option(
    "--custom-combinations",
    multiple=True,
    default=[],
    help="Specific combination IDs to test (e.g. base debug_safe). "
         "Use 'all' to see available IDs.",
)
@click.option(
    "--output", "-o",
    type=click.Path(file_okay=False, dir_okay=True),
    default="pyneat_fuzz_results",
    help="Output directory for reports.",
)
@click.option(
    "--github-token", "-t",
    default=None,
    help="GitHub Personal Access Token. Increases rate limit from 60→5000 req/hr. "
         "Can also be set via GITHUB_TOKEN env variable.",
)
@click.option(
    "--max-files", "-m",
    type=int,
    default=200,
    help="Maximum Python files to download per repo.",
)
@click.option(
    "--timeout", "-T",
    type=float,
    default=30.0,
    help="Timeout per file per combination (seconds). Files exceeding this are marked 'timeout'.",
)
@click.option(
    "--workers", "-w",
    type=int,
    default=4,
    help="Number of parallel workers.",
)
@click.option(
    "--resume", "-R",
    type=click.Path(exists=True),
    default=None,
    help="Resume from a previously saved cache file (JSON).",
)
@click.option(
    "--dry-download",
    is_flag=True,
    help="Only download files, do not run any fuzz tests.",
)
@click.option(
    "--verbose/--quiet",
    default=True,
    help="Show progress bars and detailed output.",
)
@click.option(
    "--list-combinations",
    is_flag=True,
    help="List all available rule combinations and exit.",
)
@click.pass_context
def run(
    ctx: click.Context,
    repos: tuple,
    combinations: str,
    custom_combinations: tuple,
    output: str,
    github_token: str,
    max_files: int,
    timeout: float,
    workers: int,
    resume: str,
    dry_download: bool,
    verbose: bool,
    list_combinations: bool,
) -> None:
    """Run the GitHub fuzz test loop.

    Downloads Python files from popular GitHub repos and runs pyneat
    with all configured rule combinations to detect crashes, regressions,
    and performance issues.

    Examples:

      # Run with defaults (top-5 repos, safe rules only)
      python -m pyneat.tools.github_fuzz run

      # Test all repos with all rule combinations
      python -m pyneat.tools.github_fuzz run --repos django/django psf/requests --combinations all

      # Use a GitHub token to avoid rate limiting
      python -m pyneat.tools.github_fuzz run --github-token ghp_xxxx

      # Resume from a previous download
      python -m pyneat.tools.github_fuzz run --resume ./cache.json
    """
    _print_header()

    if list_combinations:
        click.echo("Available rule combinations:\n")
        for i, combo in enumerate(RULE_COMBINATIONS, 1):
            flags_str = ", ".join(f"{k}={v}" for k, v in combo.flags.items())
            click.echo(f"  [{i:2d}] {click.style(combo.id, fg='yellow', bold=True)}")
            click.echo(f"       Name: {combo.name}")
            if flags_str:
                click.echo(f"       Flags: {flags_str}")
            click.echo("")
        return

    # Build config
    repo_list = list(repos) if repos else DEFAULT_REPOS[:5]

    custom_ids = list(custom_combinations) if custom_combinations else None

    config = FuzzConfig(
        repos=repo_list,
        combination_preset=combinations,
        custom_combinations=custom_ids,
        output_dir=output,
        github_token=github_token,
        max_files_per_repo=max_files,
        timeout_seconds=timeout,
        max_workers=workers,
        resume_from=resume,
        dry_download=dry_download,
        verbose=verbose,
    )

    if verbose:
        click.echo("Configuration:")
        click.echo(f"  Repos              : {', '.join(repo_list[:3])}{'...' if len(repo_list) > 3 else ''}")
        click.echo(f"  Combination preset : {combinations}")
        if custom_ids:
            click.echo(f"  Custom IDs        : {', '.join(custom_ids)}")
        click.echo(f"  Max files/repo     : {max_files}")
        click.echo(f"  Timeout/file       : {timeout}s")
        click.echo(f"  Workers            : {workers}")
        click.echo(f"  Output directory   : {output}")
        click.echo(f"  GitHub token       : {'set' if github_token else 'not set (unauthenticated)'}")
        click.echo(f"  Dry download       : {dry_download}")
        click.echo("")

    # Run fuzz
    try:
        results = run_fuzz(config)
    except KeyboardInterrupt:
        click.echo(click.style("\n[Interrupted] Stopping fuzz test...", fg="yellow"))
        sys.exit(130)
    except Exception as e:
        click.echo(click.style(f"\n[FATAL] {type(e).__name__}: {e}", fg="red"))
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # Summary
    total = len(results)
    crashes = sum(1 for r in results if r.status == "crash")
    regressions = sum(1 for r in results if r.status == "regression")
    timeouts = sum(1 for r in results if r.status == "timeout")
    no_ops = sum(1 for r in results if r.status == "no_op")
    successes = sum(1 for r in results if r.status == "success")

    click.echo("")
    click.echo(click.style("=" * 40, fg="cyan"))
    click.echo(click.style("  SUMMARY", fg="cyan", bold=True))
    click.echo(click.style("=" * 40, fg="cyan"))

    click.echo(f"  Total tests  : {total}")
    click.echo(f"  Crashes      : {click.style(str(crashes), fg='red' if crashes else 'green')}")
    click.echo(f"  Regressions  : {click.style(str(regressions), fg='red' if regressions else 'green')}")
    click.echo(f"  Timeouts     : {click.style(str(timeouts), fg='yellow' if timeouts else 'green')}")
    click.echo(f"  No-ops       : {no_ops}")
    click.echo(f"  Successes    : {successes}")

    if crashes > 0 or regressions > 0:
        click.echo("")
        click.echo(click.style("  [!] Issues found! Check the generated reports:", fg="yellow"))
        json_file = Path(output) / f"PYNEAT_FUZZ_REPORT_"
        txt_file = Path(output) / f"PYNEAT_FUZZ_SUMMARY_"
        click.echo(f"    JSON: {output}/PYNEAT_FUZZ_REPORT_*.json")
        click.echo(f"    TXT : {output}/PYNEAT_FUZZ_SUMMARY_*.txt")
        sys.exit(1)
    else:
        click.echo("")
        click.echo(click.style("  All tests passed!", fg="green"))
        sys.exit(0)


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option(
    "--preset", "-p",
    type=click.Choice(["safe", "conservative", "destructive", "all", "quick"]),
    default="quick",
    help="Rule combination preset to test.",
)
def test(file_path: str, preset: str) -> None:
    """Quick fuzz test of a single local Python file.

    Useful for reproducing crashes found during a full fuzz run.

    Examples:

      python -m pyneat.tools.github_fuzz test ./myfile.py
      python -m pyneat.tools.github_fuzz test ./myfile.py --preset all
    """
    _print_header()

    content = Path(file_path).read_text(encoding="utf-8")

    from pyneat.tools.github_fuzz.fuzz_runner import test_single_file

    click.echo(f"Testing {file_path} ({len(content)} bytes) with preset '{preset}'...\n")

    results = test_single_file(
        content=content,
        file_path=file_path,
        repo="local",
        combination_preset=preset,
    )

    for r in results:
        status_color = {
            "success": "green",
            "no_op": "blue",
            "crash": "red",
            "regression": "red",
            "timeout": "yellow",
            "unsupported": "blue",
        }.get(r.status, "white")

        click.echo(
            f"  [{click.style(r.combination_id, fg='yellow', bold=True)}] "
            f"{click.style(r.status.upper(), fg=status_color)} "
            f"— {r.elapsed_ms:.1f}ms"
        )

        if r.status in ("crash", "regression"):
            click.echo(f"    Error: {r.exception_type or r.syntax_error}")
            click.echo(f"    Message: {r.exception_message or ''}")
            if r.traceback:
                click.echo(click.style(r.traceback[:500], fg="red"))

    crashes = sum(1 for r in results if r.status == "crash")
    regressions = sum(1 for r in results if r.status == "regression")

    click.echo("")
    if crashes > 0 or regressions > 0:
        click.echo(click.style(f"  {crashes} crash(es), {regressions} regression(s) found!", fg="red"))
        sys.exit(1)
    else:
        click.echo(click.style("  All combinations passed!", fg="green"))


@cli.command()
def combinations() -> None:
    """List all available rule combinations."""
    _print_header()
    click.echo("Available rule combinations:\n")

    presets = {
        "safe": ("Base (safe rules only)", COMBINATION_PRESETS["safe"]),
        "conservative": ("Base + debug + conservative rules", COMBINATION_PRESETS["conservative"]),
        "destructive": ("Destructive rules", COMBINATION_PRESETS["destructive"]),
        "all": ("All combinations", COMBINATION_PRESETS["all"]),
        "quick": ("Quick test (base + dead_code)", COMBINATION_PRESETS["quick"]),
    }

    for preset_name, (desc, combos) in presets.items():
        click.echo(f"{click.style(preset_name.upper(), fg='cyan', bold=True)} - {desc}")
        for combo in combos:
            flags_str = " ".join(f"{k}={v}" for k, v in combo.flags.items())
            click.echo(f"  {click.style(f'[{combo.id}]', fg='yellow')} {combo.name}")
            if flags_str:
                click.echo(f"    -> {flags_str}")
        click.echo("")


# ---------------------------------------------------------------------------
# Watch mode: continuously run fuzz tests
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--repos", "-r",
    multiple=True,
    default=[],
    help="GitHub repos to watch (owner/name format).",
)
@click.option(
    "--combinations", "-c",
    type=click.Choice(["safe", "conservative", "destructive", "all", "quick"]),
    default="all",
    help="Rule combination preset.",
)
@click.option(
    "--interval", "-i",
    type=int,
    default=3600,
    help="Seconds between fuzz runs (default: 3600 = 1 hour).",
)
@click.option(
    "--max-files", "-m",
    type=int,
    default=20,
    help="Max files per repo per run.",
)
@click.option(
    "--workers", "-w",
    type=int,
    default=4,
    help="Parallel workers.",
)
@click.option(
    "--timeout", "-T",
    type=float,
    default=30.0,
    help="Timeout per file.",
)
@click.option(
    "--output", "-o",
    type=click.Path(file_okay=False, dir_okay=True),
    default="pyneat_fuzz_results",
    help="Output directory for reports.",
)
@click.option(
    "--github-token", "-t",
    default=None,
    help="GitHub token.",
)
@click.pass_context
def watch(
    ctx: click.Context,
    repos: tuple,
    combinations: str,
    interval: int,
    max_files: int,
    workers: int,
    timeout: float,
    output: str,
    github_token: str,
) -> None:
    """Watch mode: continuously run fuzz tests in the background.

    Polls GitHub repos at a regular interval and runs fuzz tests.
    Reports are saved to the output directory with timestamps.
    Press Ctrl+C to stop.

    Examples:

      # Watch django/django every hour
      python -m pyneat.tools.github_fuzz watch --repos django/django

      # Watch multiple repos every 30 minutes
      python -m pyneat.tools.github_fuzz watch --repos django/django psf/requests --interval 1800
    """
    import time as time_module

    _print_header()

    if not repos:
        repos = list(DEFAULT_REPOS[:3])
    else:
        repos = list(repos)

    click.echo(click.style("  WATCH MODE", fg="cyan", bold=True))
    click.echo(f"  Repos     : {', '.join(repos)}")
    click.echo(f"  Combos   : {combinations}")
    click.echo(f"  Interval : {interval}s ({interval // 60}min)")
    click.echo(f"  Workers  : {workers}")
    click.echo(f"  Output   : {output}")
    click.echo("")
    click.echo(click.style("  Starting watch loop... Press Ctrl+C to stop.", fg="yellow"))
    click.echo("")

    run_count = 0
    total_crashes = 0
    total_regressions = 0

    try:
        while True:
            run_count += 1
            ts = time_module.strftime("%Y-%m-%d %H:%M:%S")
            click.echo(click.style(f"[{ts}] Run #{run_count}: Starting fuzz...", fg="cyan"))

            config = FuzzConfig(
                repos=repos,
                combination_preset=combinations,
                output_dir=output,
                github_token=github_token,
                max_files_per_repo=max_files,
                timeout_seconds=timeout,
                max_workers=workers,
                verbose=False,
            )

            try:
                results = run_fuzz(config)
            except Exception as e:
                click.echo(click.style(f"  [ERROR] {type(e).__name__}: {e}", fg="red"))
                time_module.sleep(interval)
                continue

            crashes = sum(1 for r in results if r.status == "crash")
            regressions = sum(1 for r in results if r.status == "regression")
            successes = sum(1 for r in results if r.status == "success")
            unsupported = sum(1 for r in results if r.status == "unsupported")
            total_crashes += crashes
            total_regressions += regressions

            if crashes > 0:
                click.echo(click.style(f"  [CRASH] {crashes} crash(es) found!", fg="red"))
            if regressions > 0:
                click.echo(click.style(f"  [REGRESSION] {regressions} regression(s) found!", fg="red"))
            if crashes == 0 and regressions == 0:
                click.echo(click.style(f"  [OK] {successes} success(es), {unsupported} unsupported", fg="green"))

            click.echo(
                f"  Cumulative: {total_crashes} crashes, {total_regressions} regressions "
                f"(all time)"
            )
            click.echo(f"  Sleeping for {interval}s...\n")
            time_module.sleep(interval)

    except KeyboardInterrupt:
        click.echo("")
        click.echo(click.style("  [Stopped] Watch loop ended.", fg="yellow"))
        click.echo(f"  Total runs: {run_count}")
        click.echo(f"  Total crashes: {total_crashes}")
        click.echo(f"  Total regressions: {total_regressions}")
        sys.exit(0 if total_crashes == 0 and total_regressions == 0 else 1)


# ---------------------------------------------------------------------------
# CI mode: fail-fast fuzz test for CI/CD pipelines
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--repos", "-r",
    multiple=True,
    default=[],
    help="GitHub repos to test.",
)
@click.option(
    "--combinations", "-c",
    type=click.Choice(["safe", "conservative", "destructive", "all", "quick"]),
    default="all",
    help="Rule combination preset.",
)
@click.option(
    "--max-files", "-m",
    type=int,
    default=50,
    help="Max files per repo.",
)
@click.option(
    "--workers", "-w",
    type=int,
    default=8,
    help="Parallel workers.",
)
@click.option(
    "--timeout", "-T",
    type=float,
    default=30.0,
    help="Timeout per file.",
)
@click.option(
    "--output", "-o",
    type=click.Path(file_okay=False, dir_okay=True),
    default="pyneat_fuzz_results",
    help="Output directory.",
)
@click.option(
    "--github-token", "-t",
    default=None,
    help="GitHub token.",
)
@click.option(
    "--fail-on-unsupported/--no-fail-on-unsupported",
    default=False,
    help="Fail if Python 2 or unsupported files are encountered.",
)
@click.pass_context
def ci(
    ctx: click.Context,
    repos: tuple,
    combinations: str,
    max_files: int,
    workers: int,
    timeout: float,
    output: str,
    github_token: str,
    fail_on_unsupported: bool,
) -> None:
    """CI mode: fast fuzz test that exits non-zero on crash or regression.

    Designed for CI/CD pipelines. Downloads files, runs fuzz tests, and
    exits with code 1 if any crashes or regressions are found.

    Examples:

      # CI check on pull request
      python -m pyneat.tools.github_fuzz ci --repos django/django

      # Strict mode: fail on Python 2 files too
      python -m pyneat.tools.github_fuzz ci --repos django/django --fail-on-unsupported
    """
    import json
    from datetime import datetime, timezone

    _print_header()

    if not repos:
        repos = list(DEFAULT_REPOS[:3])
    else:
        repos = list(repos)

    click.echo(click.style("  CI MODE", fg="cyan", bold=True))
    click.echo(f"  Repos   : {', '.join(repos)}")
    click.echo(f"  Combos  : {combinations}")
    click.echo(f"  Workers : {workers}")
    click.echo(f"  Output  : {output}")
    click.echo("")

    config = FuzzConfig(
        repos=repos,
        combination_preset=combinations,
        output_dir=output,
        github_token=github_token,
        max_files_per_repo=max_files,
        timeout_seconds=timeout,
        max_workers=workers,
        verbose=False,
    )

    click.echo(click.style("  Running fuzz tests...\n", fg="yellow"))

    try:
        results = run_fuzz(config)
    except Exception as e:
        click.echo(click.style(f"\n[FATAL] {type(e).__name__}: {e}", fg="red"))
        import traceback
        traceback.print_exc()
        sys.exit(2)

    # Categorize
    crashes = [r for r in results if r.status == "crash"]
    regressions = [r for r in results if r.status == "regression"]
    unsupported = [r for r in results if r.status == "unsupported"]
    successes = [r for r in results if r.status == "success"]
    timeouts = [r for r in results if r.status == "timeout"]
    no_ops = [r for r in results if r.status == "no_op"]

    # Print summary
    click.echo(click.style("=" * 50, fg="cyan"))
    click.echo(click.style("  CI RESULTS", fg="cyan", bold=True))
    click.echo(click.style("=" * 50, fg="cyan"))
    click.echo(f"  Total tests    : {len(results)}")
    click.echo(f"  Crashes       : {click.style(str(len(crashes)), fg='red' if crashes else 'green')}")
    click.echo(f"  Regressions   : {click.style(str(len(regressions)), fg='red' if regressions else 'green')}")
    click.echo(f"  Unsupported   : {len(unsupported)} {'[IGNORED]' if not fail_on_unsupported else '[FAILING]' if fail_on_unsupported else ''}")
    click.echo(f"  Successes     : {len(successes)}")
    click.echo(f"  Timeouts      : {len(timeouts)}")
    click.echo(f"  No-ops       : {len(no_ops)}")

    # Detailed crash output for CI
    if crashes:
        click.echo("")
        click.echo(click.style("  CRASHES:", fg="red", bold=True))
        for c in crashes[:5]:
            click.echo(f"    {c.repo}/{c.file} [{c.combination_id}]")
            click.echo(f"    {c.exception_type}: {c.exception_message[:80]}")
            if c.traceback:
                click.echo(click.style(c.traceback[:300], fg="red"))

    # Detailed regression output for CI
    if regressions:
        click.echo("")
        click.echo(click.style("  REGRESSIONS:", fg="red", bold=True))
        for r in regressions[:5]:
            click.echo(f"    {r.repo}/{r.file} [{r.combination_id}]")
            click.echo(f"    {r.syntax_error}")

    # Write CI artifact (for CI systems like GitHub Actions)
    ci_artifact = Path(output) / "ci_results.json"
    ci_artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_tests": len(results),
        "crashes": len(crashes),
        "regressions": len(regressions),
        "unsupported": len(unsupported),
        "successes": len(successes),
        "timeouts": len(timeouts),
        "no_ops": len(no_ops),
        "exit_code": 1 if (crashes or regressions or (fail_on_unsupported and unsupported)) else 0,
        "crash_files": [{"repo": c.repo, "file": c.file, "combo": c.combination_id} for c in crashes],
        "regression_files": [{"repo": r.repo, "file": r.file, "combo": r.combination_id} for r in regressions],
    }
    with open(ci_artifact, "w", encoding="utf-8") as f:
        json.dump(artifact_data, f, indent=2)

    click.echo("")
    click.echo(f"  CI artifact: {ci_artifact}")

    # Exit code
    exit_code = 1 if (crashes or regressions or (fail_on_unsupported and unsupported)) else 0
    if exit_code == 0:
        click.echo(click.style("\n  [PASS] No crashes or regressions found.", fg="green"))
    else:
        click.echo(click.style("\n  [FAIL] Crashes or regressions detected!", fg="red"))
        click.echo(click.style("  Check CI artifact for details.", fg="yellow"))

    sys.exit(exit_code)



# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()