"""Command-line interface for AI Cleaner."""

import click
from pathlib import Path
from pyneat.core.engine import RuleEngine
from pyneat.core.types import RuleConfig
from pyneat.rules.imports import ImportCleaningRule
from pyneat.rules.naming import NamingConventionRule
from pyneat.rules.refactoring import RefactoringRule
from pyneat.rules.security import SecurityScannerRule
from pyneat.rules.quality import CodeQualityRule
from pyneat.rules.performance import PerformanceRule

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
def clean(input_file: str, output: str, in_place: bool, verbose: bool,
          enable_security: bool, enable_quality: bool, enable_performance: bool):
    """Clean AI-generated code."""
    input_path = Path(input_file)
    
    # Setup rule engine with default rules
    rules = [
        ImportCleaningRule(RuleConfig(enabled=True)),
        NamingConventionRule(RuleConfig(enabled=True)),
        RefactoringRule(RuleConfig(enabled=True))
    ]
    
    # Add optional rules based on flags
    if enable_security:
        rules.append(SecurityScannerRule(RuleConfig(enabled=True)))
    
    if enable_quality:
        rules.append(CodeQualityRule(RuleConfig(enabled=True)))
    
    if enable_performance:
        rules.append(PerformanceRule(RuleConfig(enabled=True)))
    
    engine = RuleEngine(rules)
    
    if verbose:
        stats = engine.get_rule_stats()
        click.echo(f"[TARGET] Loaded {stats['enabled_rules']}/{stats['total_rules']} rules")
        for rule in stats['rules']:
            status = "[OK]" if rule['enabled'] else "[X]"
            click.echo(f"  {status} {rule['name']}: {rule['description']}")
    
    # Process the file
    result = engine.process_file(input_path)
    
    if not result.success:
        click.echo(f"[ERROR] Error: {result.error}", err=True)
        return 1
    
    # Determine output path
    if in_place:
        output_path = input_path
    elif output:
        output_path = Path(output)
    else:
        output_path = input_path.with_name(f"{input_path.stem}.clean{input_path.suffix}")
    
    # Write result
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result.transformed_content)
        
        # Show results
        if verbose or not in_place:
            click.echo(f"[OK] Cleaned: {input_path} -> {output_path}")
            if result.changes_made:
                click.echo("[CHANGES] Changes made:")
                for change in result.changes_made:
                    click.echo(f"  * {change}")
            else:
                click.echo("[INFO] No changes needed - code already clean!")
                
    except Exception as e:
        click.echo(f"[ERROR] Write failed: {str(e)}", err=True)
        return 1
    
    return 0

@cli.command()
def rules():
    """List available cleaning rules."""
    click.echo("Available rules:")
    click.echo("  * ImportCleaningRule - Standardizes import statements")
    click.echo("  * NamingConventionRule - Enforces PEP8 naming")
    click.echo("  * RefactoringRule - Refactors complex code structures")
    click.echo("  * SecurityScannerRule - Detects security vulnerabilities")
    click.echo("  * CodeQualityRule - Detects code quality issues") 
    click.echo("  * PerformanceRule - Detects performance issues")
    click.echo("\nUse --enable-security, --enable-quality, --enable-performance to enable optional rules")

if __name__ == '__main__':
    cli()
