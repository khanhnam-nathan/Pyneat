"""PyNEAT CLI test command.

Run this via: python -m pyneat.cli.testing.run_tests
Or after installation: pyneat test --lang python

Copyright (c) 2026 PyNEAT Authors
"""

import sys
import click

# Add parent dir to path for imports
sys.path.insert(0, str(__file__).rsplit("/", 3)[0])

from pyneat.cli.testing.cli_tester import CLITester
from pyneat.cli.testing.test_cases import (
    get_test_cases,
    get_test_cases_for_command,
    get_all_test_cases,
    ALL_LANGUAGES,
)


@click.command()
@click.option(
    '--lang',
    '-l',
    'lang',
    type=str,
    default=None,
    help='Language to test: python, javascript, typescript, go, java, rust, csharp, php, ruby',
)
@click.option(
    '--cmd',
    '-c',
    'command',
    type=str,
    default=None,
    help='Command to test: clean, check (default: both)',
)
@click.option(
    '--all',
    'all_langs',
    is_flag=True,
    help='Test all supported languages',
)
@click.option(
    '--verbose',
    '-v',
    is_flag=True,
    help='Show verbose output including passing tests',
)
@click.option(
    '--debug',
    is_flag=True,
    help='Show command output on failures',
)
@click.option(
    '--case',
    '-t',
    'case_name',
    type=str,
    default=None,
    help='Run only the test case matching this name (partial match)',
)
@click.option(
    '--stop-on-failure',
    is_flag=True,
    help='Stop on first failure',
)
def test(
    lang,
    command,
    all_langs,
    verbose,
    debug,
    case_name,
    stop_on_failure,
):
    """Run PyNEAT CLI tests for one or more languages.

    This command tests the CLI end-to-end by running actual pyneat commands
    as subprocesses, rather than importing modules directly. This ensures
    the user experience is correct.

    Examples:
        pyneat test                          # Test all languages
        pyneat test --lang python           # Test Python only
        pyneat test --lang javascript       # Test JavaScript only
        pyneat test --lang python --cmd check  # Test only check command
        pyneat test --all --verbose         # All languages, verbose
        pyneat test --lang python --case "pickle"  # Single test case
        pyneat test --lang python --debug   # Show output on failure
    """
    tester = CLITester(verbose=verbose)
    languages_to_test: list[str]

    if all_langs:
        languages_to_test = ALL_LANGUAGES
    elif lang:
        languages_to_test = [lang.lower()]
    else:
        click.echo("Please specify --lang <language> or --all")
        click.echo(f"Supported languages: {', '.join(ALL_LANGUAGES)}")
        sys.exit(1)

    all_passed = 0
    all_failed = 0

    for language in languages_to_test:
        cases_map = get_test_cases(language)

        if not cases_map:
            click.echo(f"  {click.style('[!]', fg='yellow')} No test cases for: {language}")
            continue

        commands_to_test = [command] if command else list(cases_map.keys())

        lang_passed = 0
        lang_failed = 0
        lang_results: list = []

        click.echo("")
        click.echo(f"  {click.style('='*60, fg='cyan')}")
        click.echo(f"  {click.style(f'Language: {language.upper()}', bold=True, fg='cyan')}")
        click.echo(f"  {click.style('='*60, fg='cyan')}")

        for cmd in commands_to_test:
            cases = cases_map.get(cmd, [])

            if case_name:
                cases = [c for c in cases if case_name.lower() in c.name.lower()]

            if not cases:
                continue

            click.echo(f"\n  {click.style(f'Command: {cmd}', bold=True)} ({len(cases)} test cases)")

            for case in cases:
                result = tester.run_test_case(case)
                lang_results.append((language, cmd, case.name, result))

                if result.passed:
                    lang_passed += 1
                    if verbose:
                        click.echo(f"    {click.style('[OK]', fg='green')} {case.name}")
                else:
                    lang_failed += 1
                    click.echo(f"    {click.style('[FAIL]', fg='red')} {case.name}")
                    if result.error_message:
                        click.echo(f"         {result.error_message}")
                    if debug:
                        click.echo(f"         --- stdout ---")
                        for line in result.stdout.splitlines()[:10]:
                            click.echo(f"         {line}")
                        if result.stderr:
                            click.echo(f"         --- stderr ---")
                            for line in result.stderr.splitlines()[:10]:
                                click.echo(f"         {line}")

                if not result.passed and stop_on_failure:
                    click.echo(f"\n  {click.style('Stopped on first failure.', fg='yellow')}")
                    sys.exit(1)

        all_passed += lang_passed
        all_failed += lang_failed

        fg = "green" if lang_failed == 0 else "yellow"
        click.echo(f"\n  {language}: {click.style(str(lang_passed), fg='green', bold=True)} passed, "
                   f"{click.style(str(lang_failed), fg=fg, bold=True)} failed")

    click.echo("")
    click.echo(f"  {click.style('='*60, fg='bright_black')}")
    click.echo(f"  Total: {click.style(str(all_passed), fg='green', bold=True)} passed, "
               f"{click.style(str(all_failed), fg='red' if all_failed else 'green', bold=True)} failed")
    click.echo(f"  {click.style('='*60, fg='bright_black')}")

    if all_failed > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    test()
