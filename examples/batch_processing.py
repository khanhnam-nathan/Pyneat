#!/usr/bin/env python3
"""
PyNeat Batch Processing Example

This example demonstrates processing entire projects:
1. Scan multiple files in parallel
2. Aggregate results
3. Generate project-wide reports

Run: python examples/batch_processing.py
"""

import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyneat.core import RuleEngine
from pyneat.core.types import AgentMarker, MarkerIdGenerator
from pyneat.core.manifest import MarkerAggregator
from pyneat.rules import ALL_RULES


@dataclass
class FileResult:
    """Result of scanning a single file."""
    file_path: Path
    markers: List[AgentMarker]
    scan_time: float
    success: bool
    error: str = ""


def scan_file(file_path: Path, engine: RuleEngine, generator: MarkerIdGenerator) -> FileResult:
    """Scan a single file for issues."""
    start_time = time.time()
    try:
        content = file_path.read_text(encoding="utf-8")
        findings = engine.scan_code(content, language="python")

        markers = []
        for finding in findings:
            marker = AgentMarker(
                marker_id=generator.generate(finding.rule_id, "quality"),
                issue_type=finding.rule_id,
                rule_id=finding.rule_id,
                severity="medium",
                line=finding.line,
                snippet=finding.code_snippet,
                file_path=str(file_path),
            )
            markers.append(marker)

        scan_time = time.time() - start_time
        return FileResult(file_path, markers, scan_time, True)

    except Exception as e:
        scan_time = time.time() - start_time
        return FileResult(file_path, [], scan_time, False, str(e))


def run_batch_example():
    """Run batch processing example on test samples."""
    print("=" * 60)
    print("PyNeat Batch Processing Example")
    print("=" * 60)

    # Initialize engine
    engine = RuleEngine(rules=ALL_RULES)
    generator = MarkerIdGenerator()

    # Find test sample files
    samples_dir = Path(__file__).parent.parent / "test_samples" / "ai_bugs"
    python_files = list(samples_dir.glob("**/*.py"))[:10]  # Limit to 10 files

    if not python_files:
        print("\nNo test files found. Using sample code instead.")
        sample_files = [
            ("sample1.py", "import utils\nx != None\n"),
            ("sample2.py", "file = open('test.txt')\nprint(x)\n"),
        ]
    else:
        sample_files = [(f.name, None) for f in python_files]

    print(f"\n[1] Found {len(sample_files)} files to scan")

    # Scan files
    print("\n[2] Scanning files...")
    all_results = []

    for file_name, _ in sample_files:
        if python_files:
            # Scan actual files
            result = scan_file(python_files[len(all_results)], engine, generator)
        else:
            # Use sample code
            content = sample_files[len(all_results)][1]
            start_time = time.time()
            findings = engine.scan_code(content, language="python")
            markers = [
                AgentMarker(
                    marker_id=generator.generate(finding.rule_id, "quality"),
                    issue_type=finding.rule_id,
                    rule_id=finding.rule_id,
                    severity="medium",
                    line=finding.line,
                    snippet=finding.code_snippet,
                    file_path=file_name,
                )
                for finding in findings
            ]
            scan_time = time.time() - start_time
            result = FileResult(Path(file_name), markers, scan_time, True)

        all_results.append(result)
        status = "OK" if result.success else f"FAIL: {result.error}"
        print(f"    {result.file_path.name}: {len(result.markers)} issues in {result.scan_time:.3f}s [{status}]")

    # Aggregate all markers
    print("\n[3] Aggregating results...")
    all_markers = []
    for result in all_results:
        all_markers.extend(result.markers)

    if not all_markers:
        print("    No issues found!")
        return

    # Use MarkerAggregator for analysis
    aggregator = MarkerAggregator(all_markers)

    # Group by severity
    by_severity = aggregator.by_severity()
    print("\n[4] Issues by severity:")
    for severity in ["critical", "high", "medium", "low", "info"]:
        if severity in by_severity:
            count = len(by_severity[severity])
            print(f"    {severity.upper()}: {count}")

    # Group by file
    by_file = aggregator.by_file()
    print("\n[5] Issues by file:")
    for file_path, markers in sorted(by_file.items()):
        print(f"    {Path(file_path).name}: {len(markers)} issues")

    # Group by rule
    by_rule = aggregator.by_rule()
    print("\n[6] Most common rules violated:")
    sorted_rules = sorted(by_rule.items(), key=lambda x: len(x[1]), reverse=True)
    for rule_id, markers in sorted_rules[:5]:
        print(f"    {rule_id}: {len(markers)} occurrences")

    # Auto-fixable issues
    auto_fixable = aggregator.auto_fixable()
    print(f"\n[7] Auto-fixable issues: {len(auto_fixable)}")

    # Performance summary
    total_time = sum(r.scan_time for r in all_results)
    total_files = len(all_results)
    print(f"\n[8] Performance:")
    print(f"    Total files: {total_files}")
    print(f"    Total scan time: {total_time:.3f}s")
    print(f"    Average per file: {total_time/total_files:.3f}s")

    # Generate prioritized list
    print("\n[9] Top 5 priority issues:")
    prioritized = aggregator.prioritized()[:5]
    for i, marker in enumerate(prioritized, 1):
        print(f"    {i}. [{marker.severity}] {marker.issue_type} in {Path(marker.file_path or 'unknown').name}:{marker.line}")

    print("\n" + "=" * 60)
    print("Batch processing completed successfully!")
    print("=" * 60)

    return all_markers


if __name__ == "__main__":
    run_batch_example()
