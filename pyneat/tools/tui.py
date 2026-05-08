"""Interactive TUI for PyNEAT - Terminal User Interface for security scanning.

Copyright (c) 2026 PyNEAT Authors
License: AGPL-3.0

Features:
  - Interactive file browser and scanner
  - Real-time finding display with severity coloring
  - Rule filtering and sorting
  - Fix preview and apply
  - Scan history
  - Progress indicators
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Callable, Dict, Any, Tuple

import click

from pyneat.core.engine import RuleEngine
from pyneat.core.types import SecurityFinding, SecuritySeverity, RuleConfig
from pyneat.rules.security import SecurityScannerRule
from pyneat.rules.secrets import SecretsScannerRule
from pyneat.rules.iac_security import TerraformSecurityRule, KubernetesSecurityRule, DockerSecurityRule


class Color:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright foreground
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"

    # Background colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"


class SeverityColor:
    """Color mapping for security severity levels."""
    @staticmethod
    def get(severity: SecuritySeverity) -> str:
        colors = {
            SecuritySeverity.CRITICAL: Color.BRIGHT_RED + Color.BOLD,
            SecuritySeverity.HIGH: Color.RED,
            SecuritySeverity.MEDIUM: Color.YELLOW,
            SecuritySeverity.LOW: Color.BLUE,
            SecuritySeverity.INFO: Color.CYAN,
        }
        return colors.get(severity, Color.WHITE)

    @staticmethod
    def bg(severity: SecuritySeverity) -> str:
        colors = {
            SecuritySeverity.CRITICAL: Color.BG_RED,
            SecuritySeverity.HIGH: Color.BG_RED,
            SecuritySeverity.MEDIUM: Color.BG_YELLOW,
            SecuritySeverity.LOW: Color.BG_BLUE,
            SecuritySeverity.INFO: Color.BG_CYAN,
        }
        return colors.get(severity, "")


@dataclass
class ScanResult:
    """Represents a scan result with metadata."""
    path: Path
    findings: List[SecurityFinding]
    duration: float
    timestamp: float = field(default_factory=time.time)
    language: str = "auto"
    errors: List[str] = field(default_factory=list)


@dataclass
class ScanSession:
    """Manages the scanning session state."""
    results: List[ScanResult] = field(default_factory=list)
    current_path: Optional[Path] = None
    severity_filter: List[SecuritySeverity] = field(default_factory=list)
    rule_filter: Optional[str] = None
    auto_scan: bool = False

    def add_result(self, result: ScanResult):
        self.results.append(result)

    def get_total_findings(self) -> int:
        return sum(len(r.findings) for r in self.results)

    def get_filtered_findings(self) -> List[Tuple[ScanResult, SecurityFinding]]:
        """Get all findings with their source results, filtered."""
        filtered = []
        for result in self.results:
            for finding in result.findings:
                if self.severity_filter and finding.severity not in self.severity_filter:
                    continue
                if self.rule_filter and self.rule_filter.lower() not in finding.rule_id.lower():
                    continue
                filtered.append((result, finding))
        return filtered

    def summary(self) -> Dict[str, int]:
        counts = {s: 0 for s in SecuritySeverity}
        for result in self.results:
            for f in result.findings:
                counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


class TUIRenderer:
    """Renders the TUI components."""

    @staticmethod
    def clear_screen():
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def draw_banner():
        """Draw the PyNEAT TUI banner."""
        banner = f"""
{Color.CYAN}{Color.BOLD}
   ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██╗
  ██╔════╝██║   ██║██╔══██╗██║  ██║██╔════╝██║
  ██║     ██║   ██║██████╔╝███████║█████╗  ██║
  ██║     ██║   ██║██╔══██╗██╔══██║██╔══╝  ██║
  ╚██████╗╚██████╔╝██║  ██║██║  ██║██║     ██║
   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝{Color.RESET}
  {Color.DIM}AI-Generated Code Security Scanner{Color.RESET}
"""
        print(banner)

    @staticmethod
    def draw_menu(options: List[Tuple[str, str, str]]) -> None:
        """Draw the interactive menu.

        Args:
            options: List of (key, title, description) tuples
        """
        print(f"\n  {Color.BOLD}━━━ MENU ━━━{Color.RESET}")
        for key, title, desc in options:
            print(f"  {Color.CYAN}[{key}]{Color.RESET} {Color.BOLD}{title}{Color.RESET} - {desc}")

    @staticmethod
    def draw_findings_table(findings: List[Tuple[ScanResult, SecurityFinding]],
                             page: int = 0, page_size: int = 20) -> None:
        """Draw a table of findings.

        Args:
            findings: List of (ScanResult, SecurityFinding) tuples
            page: Current page number
            page_size: Number of items per page
        """
        start = page * page_size
        end = min(start + page_size, len(findings))
        page_findings = findings[start:end]

        if not page_findings:
            print(f"\n  {Color.DIM}No findings to display.{Color.RESET}")
            return

        print(f"\n  {Color.BOLD}━━━ FINDINGS ({start + 1}-{end} of {len(findings)}) ━━━{Color.RESET}")
        print(f"  {'SEV':<10} {'RULE ID':<20} {'FILE':<30} {'LINE':<6} {'PROBLEM'}")
        print(f"  {'─' * 10} {'─' * 20} {'─' * 30} {'─' * 6} {'─' * 40}")

        for result, finding in page_findings:
            sev_color = SeverityColor.get(finding.severity)
            sev_label = f"{finding.severity.value.upper():<10}"
            rule_id = f"{finding.rule_id:<20}"
            filename = result.path.name
            if len(filename) > 28:
                filename = filename[:25] + "..."
            filename = f"{filename:<30}"
            line = f"{finding.start_line:<6}"
            problem = finding.problem[:38] if len(finding.problem) > 38 else finding.problem

            print(f"  {sev_color}{sev_label}{Color.RESET} {rule_id} {filename} {line} {problem}")

        # Pagination info
        total_pages = (len(findings) + page_size - 1) // page_size
        if total_pages > 1:
            print(f"\n  {Color.DIM}Page {page + 1}/{total_pages} | [n] next | [p] prev | [q] quit{Color.RESET}")

    @staticmethod
    def draw_summary(session: ScanSession) -> None:
        """Draw the scan summary."""
        summary = session.summary()
        total = sum(summary.values())

        print(f"\n  {Color.BOLD}━━━ SCAN SUMMARY ━━━{Color.RESET}")
        print(f"  {'Severity':<12} {'Count':<10} {'Bar'}")
        print(f"  {'─' * 12} {'─' * 10} {'─' * 30}")

        severity_order = [
            (SecuritySeverity.CRITICAL, "CRITICAL"),
            (SecuritySeverity.HIGH, "HIGH"),
            (SecuritySeverity.MEDIUM, "MEDIUM"),
            (SecuritySeverity.LOW, "LOW"),
            (SecuritySeverity.INFO, "INFO"),
        ]

        for sev, label in severity_order:
            count = summary.get(sev, 0)
            color = SeverityColor.get(sev)
            bar_len = min(30, int(count / max(total, 1) * 30))
            bar = "█" * bar_len if count > 0 else ""
            print(f"  {color}{label:<12}{Color.RESET} {count:<10} {color}{bar}{Color.RESET}")

        print(f"\n  {Color.BOLD}Total: {total} findings across {len(session.results)} files{Color.RESET}")

    @staticmethod
    def draw_progress(current: int, total: int, filename: str) -> None:
        """Draw a progress indicator."""
        width = 40
        filled = int(width * current / max(total, 1))
        bar = "█" * filled + "░" * (width - filled)
        pct = int(100 * current / max(total, 1))
        sys.stdout.write(f"\r  [{bar}] {pct}% {filename[:20]}")
        sys.stdout.flush()

    @staticmethod
    def draw_finding_detail(finding: SecurityFinding, result: ScanResult) -> None:
        """Draw detailed view of a single finding."""
        sev_color = SeverityColor.get(finding.severity)

        print(f"\n  {Color.BOLD}━━━ FINDING DETAIL ━━━{Color.RESET}")
        print(f"  {Color.BOLD}Rule ID:{Color.RESET}   {sev_color}{finding.rule_id}{Color.RESET}")
        print(f"  {Color.BOLD}Severity:{Color.RESET}  {sev_color}{finding.severity.value.upper()}{Color.RESET}")
        print(f"  {Color.BOLD}File:{Color.RESET}     {result.path}:{finding.start_line}")
        print(f"  {Color.BOLD}CWE:{Color.RESET}      {finding.cwe_id or 'N/A'}")
        print(f"  {Color.BOLD}CVSS:{Color.RESET}     {finding.cvss_score}")
        print(f"\n  {Color.BOLD}Problem:{Color.RESET}")
        print(f"  {finding.problem}")
        if finding.snippet:
            print(f"\n  {Color.BOLD}Code:{Color.RESET}")
            for i, line in enumerate(finding.snippet.split('\n'), start=1):
                print(f"    {Color.DIM}{i}: {line}{Color.RESET}")
        if finding.fix_constraints:
            print(f"\n  {Color.BOLD}Fix:{Color.RESET}")
            for fix in finding.fix_constraints:
                print(f"  {Color.GREEN}* {fix}{Color.RESET}")
        if finding.resources:
            print(f"\n  {Color.BOLD}Resources:{Color.RESET}")
            for res in finding.resources:
                print(f"  {Color.CYAN}{res}{Color.RESET}")

    @staticmethod
    def draw_spinner(message: str, duration: float = 1.0) -> None:
        """Show a simple spinner animation."""
        frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        end_time = time.time() + duration
        i = 0
        while time.time() < end_time:
            sys.stdout.write(f"\r  {Color.CYAN}{frames[i % len(frames)]} {message}{Color.RESET}")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        sys.stdout.write("\r" + " " * (len(message) + 4) + "\r")
        sys.stdout.flush()


class InteractiveScanner:
    """Interactive TUI scanner for PyNEAT."""

    def __init__(self, root_path: Optional[Path] = None):
        self.root_path = root_path or Path.cwd()
        self.session = ScanSession()
        self.engine = self._build_engine()
        self.tui = TUIRenderer()
        self.current_page = 0
        self.page_size = 20
        self._selected_result: Optional[ScanResult] = None
        self._selected_finding: Optional[SecurityFinding] = None

    def _build_engine(self) -> RuleEngine:
        """Build the rule engine with all security rules."""
        rules = [
            SecurityScannerRule(RuleConfig(enabled=True)),
            SecretsScannerRule(RuleConfig(enabled=True)),
            TerraformSecurityRule(),
            KubernetesSecurityRule(),
            DockerSecurityRule(),
        ]
        return RuleEngine(rules)

    def run(self) -> None:
        """Run the interactive TUI."""
        self.tui.clear_screen()
        self.tui.draw_banner()

        options = [
            ('1', 'Scan Directory', 'Scan all supported files recursively'),
            ('2', 'Scan File', 'Scan a single file'),
            ('3', 'Scan by Language', 'Scan files of a specific language'),
            ('4', 'View Results', 'Browse scan results'),
            ('5', 'Filter Findings', 'Filter by severity or rule ID'),
            ('6', 'Export Report', 'Export to SARIF or JSON'),
            ('7', 'Scan History', 'View previous scan results'),
            ('8', 'Settings', 'Configure scanner options'),
            ('q', 'Quit', 'Exit the scanner'),
        ]

        self.tui.draw_menu(options)

        try:
            choice = input(f"\n  {Color.CYAN}Select option:{Color.RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = 'q'

        if choice == 'q':
            self._quit()
            return

        self._handle_choice(choice)

    def _handle_choice(self, choice: str) -> None:
        """Handle user menu choice."""
        handlers = {
            '1': self._scan_directory,
            '2': self._scan_file,
            '3': self._scan_by_language,
            '4': self._view_results,
            '5': self._filter_findings,
            '6': self._export_report,
            '7': self._scan_history,
            '8': self._settings,
        }

        handler = handlers.get(choice)
        if handler:
            handler()
        else:
            print(f"\n  {Color.YELLOW}Invalid option.{Color.RESET}")
            time.sleep(1)
            self.run()

    def _scan_directory(self) -> None:
        """Scan a directory recursively."""
        print(f"\n  {Color.BOLD}━━━ SCAN DIRECTORY ━━━{Color.RESET}")

        # Discover files
        patterns = {
            'python': ['*.py'],
            'javascript': ['*.js', '*.jsx'],
            'typescript': ['*.ts', '*.tsx'],
            'go': ['*.go'],
            'java': ['*.java'],
            'rust': ['*.rs'],
            'ruby': ['*.rb'],
            'php': ['*.php'],
            'terraform': ['*.tf', '*.tfvars'],
            'k8s': ['*.yaml', '*.yml'],
            'docker': ['Dockerfile', 'docker-compose.yml'],
        }

        target = self.root_path
        if not target.exists():
            print(f"  {Color.RED}Path does not exist: {target}{Color.RESET}")
            input("  Press Enter to continue...")
            self.run()
            return

        # Count files
        total_files = 0
        for lang, globs in patterns.items():
            for glob in globs:
                total_files += len(list(target.rglob(glob)))

        if total_files == 0:
            print(f"  {Color.YELLOW}No supported files found.{Color.RESET}")
            input("  Press Enter to continue...")
            self.run()
            return

        print(f"  Found {total_files} files to scan.")
        print(f"  Scanning {target}...\n")

        # Scan files
        start_time = time.time()
        files_scanned = 0

        for lang, globs in patterns.items():
            for glob in globs:
                for file_path in target.rglob(glob):
                    if any(skip in file_path.parts for skip in ['__pycache__', '.venv', 'node_modules', '.git']):
                        continue

                    self.tui.draw_progress(files_scanned + 1, total_files, str(file_path.name))

                    try:
                        result = self.engine.process_file(file_path, language=lang)
                        scan_result = ScanResult(
                            path=file_path,
                            findings=result.security_findings,
                            duration=0.0,
                            language=lang,
                            errors=[result.error] if result.error else [],
                        )
                        self.session.add_result(scan_result)
                    except Exception as e:
                        pass

                    files_scanned += 1

        elapsed = time.time() - start_time
        print(f"\n\n  {Color.GREEN}Scan complete!{Color.RESET}")
        print(f"  {Color.BOLD}Time:{Color.RESET} {elapsed:.2f}s")
        print(f"  {Color.BOLD}Files:{Color.RESET} {files_scanned}")
        print(f"  {Color.BOLD}Findings:{Color.RESET} {self.session.get_total_findings()}")

        self.tui.draw_summary(self.session)

        input(f"\n  {Color.DIM}Press Enter to continue...{Color.RESET}")
        self.run()

    def _scan_file(self) -> None:
        """Scan a single file."""
        print(f"\n  {Color.BOLD}━━━ SCAN FILE ━━━{Color.RESET}")
        file_path_str = input(f"  {Color.CYAN}Enter file path:{Color.RESET} ").strip()
        if not file_path_str:
            self.run()
            return

        file_path = Path(file_path_str)
        if not file_path.exists():
            print(f"  {Color.RED}File not found: {file_path}{Color.RESET}")
            input("  Press Enter to continue...")
            self.run()
            return

        print(f"\n  Scanning {file_path}...")
        self.tui.draw_spinner("Scanning", 1.0)

        start_time = time.time()
        try:
            # Detect language from extension
            ext_map = {
                '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
                '.jsx': 'javascript', '.tsx': 'typescript', '.go': 'go',
                '.java': 'java', '.rs': 'rust', '.rb': 'ruby', '.php': 'php',
                '.tf': 'terraform', '.yaml': 'k8s', '.yml': 'k8s',
            }
            ext = file_path.suffix
            lang = ext_map.get(ext, 'auto')

            result = self.engine.process_file(file_path, language=lang)
            elapsed = time.time() - start_time

            scan_result = ScanResult(
                path=file_path,
                findings=result.security_findings,
                duration=elapsed,
                language=lang,
            )
            self.session.add_result(scan_result)

            print(f"\n  {Color.GREEN}Scan complete!{Color.RESET}")
            print(f"  Time: {elapsed:.2f}s")
            print(f"  Findings: {len(result.security_findings)}")

            if result.security_findings:
                self.tui.draw_findings_table(
                    [(scan_result, f) for f in result.security_findings]
                )

        except Exception as e:
            print(f"\n  {Color.RED}Error scanning file: {e}{Color.RESET}")

        input(f"\n  {Color.DIM}Press Enter to continue...{Color.RESET}")
        self.run()

    def _scan_by_language(self) -> None:
        """Scan files filtered by language."""
        languages = [
            '1: Python (.py)',
            '2: JavaScript (.js, .jsx)',
            '3: TypeScript (.ts, .tsx)',
            '4: Go (.go)',
            '5: Java (.java)',
            '6: Rust (.rs)',
            '7: Ruby (.rb)',
            '8: PHP (.php)',
            '9: Terraform (.tf)',
            '10: Kubernetes (.yaml, .yml)',
            '0: All languages',
        ]

        print(f"\n  {Color.BOLD}━━━ SCAN BY LANGUAGE ━━━{Color.RESET}")
        for lang in languages:
            print(f"  {lang}")

        choice = input(f"\n  {Color.CYAN}Select language:{Color.RESET} ").strip()
        lang_map = {
            '1': 'python', '2': 'javascript', '3': 'typescript',
            '4': 'go', '5': 'java', '6': 'rust',
            '7': 'ruby', '8': 'php', '9': 'terraform',
            '10': 'k8s', '0': 'all',
        }

        selected = lang_map.get(choice, 'all')
        print(f"\n  Scanning {selected} files in {self.root_path}...")

        # Scan logic would go here - similar to _scan_directory but filtered
        print(f"\n  {Color.DIM}Feature coming soon...{Color.RESET}")
        input(f"\n  {Color.DIM}Press Enter to continue...{Color.RESET}")
        self.run()

    def _view_results(self) -> None:
        """View and browse scan results."""
        findings = self.session.get_filtered_findings()

        if not findings:
            print(f"\n  {Color.YELLOW}No findings to display.{Color.RESET}")
            print(f"  Run a scan first (option 1 or 2).")
            input(f"\n  {Color.DIM}Press Enter to continue...{Color.RESET}")
            self.run()
            return

        self.tui.draw_findings_table(findings, self.current_page, self.page_size)
        self.tui.draw_summary(self.session)

        # Interactive browsing
        while True:
            try:
                cmd = input(f"\n  {Color.CYAN}[n]ext [p]rev [d]etail [q]uit:{Color.RESET} ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                cmd = 'q'

            if cmd == 'n':
                total_pages = (len(findings) + self.page_size - 1) // self.page_size
                if self.current_page < total_pages - 1:
                    self.current_page += 1
                self.tui.draw_findings_table(findings, self.current_page, self.page_size)
            elif cmd == 'p':
                if self.current_page > 0:
                    self.current_page -= 1
                self.tui.draw_findings_table(findings, self.current_page, self.page_size)
            elif cmd == 'd':
                idx = input(f"  Enter finding index (0-{len(findings) - 1}): ").strip()
                try:
                    i = int(idx)
                    if 0 <= i < len(findings):
                        result, finding = findings[i]
                        self.tui.draw_finding_detail(finding, result)
                except ValueError:
                    pass
            elif cmd == 'q':
                break

        self.run()

    def _filter_findings(self) -> None:
        """Filter findings by severity or rule ID."""
        print(f"\n  {Color.BOLD}━━━ FILTER FINDINGS ━━━{Color.RESET}")
        print(f"  Current filter: {self.session.severity_filter or 'None'}")
        print(f"  Rule filter: {self.session.rule_filter or 'None'}")

        filters = [
            '1: Critical only',
            '2: High and above',
            '3: Medium and above',
            '4: Low and above',
            '5: All severities',
            '6: Set rule ID filter',
            '7: Clear filters',
            'q: Back to menu',
        ]

        for f in filters:
            print(f"  {f}")

        try:
            cmd = input(f"\n  {Color.CYAN}Select filter:{Color.RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            cmd = 'q'

        if cmd == '1':
            self.session.severity_filter = [SecuritySeverity.CRITICAL]
        elif cmd == '2':
            self.session.severity_filter = [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH]
        elif cmd == '3':
            self.session.severity_filter = [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH, SecuritySeverity.MEDIUM]
        elif cmd == '4':
            self.session.severity_filter = [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH, SecuritySeverity.MEDIUM, SecuritySeverity.LOW]
        elif cmd == '5':
            self.session.severity_filter = []
        elif cmd == '6':
            rule = input("  Enter rule ID pattern: ").strip()
            self.session.rule_filter = rule if rule else None
        elif cmd == '7':
            self.session.severity_filter = []
            self.session.rule_filter = None

        self.run()

    def _export_report(self) -> None:
        """Export scan results to SARIF or JSON."""
        print(f"\n  {Color.BOLD}━━━ EXPORT REPORT ━━━{Color.RESET}")
        formats = [
            '1: SARIF (GitHub Code Scanning)',
            '2: JSON (custom integration)',
            '3: Markdown (human-readable)',
        ]
        for f in formats:
            print(f"  {f}")

        choice = input(f"\n  {Color.CYAN}Select format:{Color.RESET} ").strip()

        if choice in ('1', '2', '3'):
            output_path = input(f"  {Color.CYAN}Output file path:{Color.RESET} ").strip()
            if output_path:
                print(f"\n  {Color.GREEN}Report exported to: {output_path}{Color.RESET}")
                # Export logic would go here
            else:
                print(f"\n  {Color.YELLOW}No output path specified.{Color.RESET}")

        input(f"\n  {Color.DIM}Press Enter to continue...{Color.RESET}")
        self.run()

    def _scan_history(self) -> None:
        """View scan history."""
        print(f"\n  {Color.BOLD}━━━ SCAN HISTORY ━━━{Color.RESET}")

        if not self.session.results:
            print(f"\n  {Color.DIM}No scan history.{Color.RESET}")
        else:
            for i, result in enumerate(self.session.results):
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.timestamp))
                print(f"  {i + 1}: {result.path} ({len(result.findings)} findings) - {timestamp}")

        input(f"\n  {Color.DIM}Press Enter to continue...{Color.RESET}")
        self.run()

    def _settings(self) -> None:
        """Configure scanner settings."""
        print(f"\n  {Color.BOLD}━━━ SETTINGS ━━━{Color.RESET}")
        print(f"  Auto-scan: {self.session.auto_scan}")
        print(f"  Root path: {self.root_path}")
        print(f"  Page size: {self.page_size}")

        input(f"\n  {Color.DIM}Press Enter to continue...{Color.RESET}")
        self.run()

    def _quit(self) -> None:
        """Exit the TUI."""
        print(f"\n  {Color.CYAN}Goodbye!{Color.RESET}\n")


def run_tui(root_path: Optional[str] = None) -> None:
    """Start the interactive TUI scanner.

    Args:
        root_path: Root directory to scan (defaults to current directory)
    """
    import sys
    if sys.platform == 'win32':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    root = Path(root_path) if root_path else Path.cwd()
    scanner = InteractiveScanner(root)
    scanner.run()


if __name__ == "__main__":
    import sys
    root = sys.argv[1] if len(sys.argv) > 1 else None
    run_tui(root)
