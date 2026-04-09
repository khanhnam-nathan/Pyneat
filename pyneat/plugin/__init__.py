"""PyNEAT Unified Plugin Architecture.

This module provides a unified interface for all IDE plugins to interact
with the PyNEAT core engine. All IDE integrations (VS Code, Neovim,
JetBrains, etc.) should use this interface.

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

For commercial licensing, contact: n.khanhnam@gmail.com
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

# Import core components
from pyneat.core.types import AgentMarker
from pyneat.core.manifest import (
    ManifestExporter,
    MarkerParser,
    export_to_sarif,
    export_to_codeclimate,
    export_to_markdown,
)


class PluginCapability(Enum):
    """Capabilities that a plugin can provide."""
    LINT = "lint"
    AUTO_FIX = "auto_fix"
    MANIFEST_EXPORT = "manifest_export"
    DIAGNOSTICS = "diagnostics"
    CODE_ACTIONS = "code_actions"
    HOVER_INFO = "hover_info"


@dataclass
class PluginConfig:
    """Configuration for PyNEAT plugin behavior.

    Attributes:
        enable_security: Enable security scanning (SEC-* rules)
        enable_ai_bugs: Enable AI bug pattern detection
        enable_conservative: Enable conservative rule package
        enable_destructive: Enable destructive rule package
        enable_quality: Enable quality rule package
        enable_performance: Enable performance rule package
        export_format: Default export format (json, sarif, codeclimate, markdown)
        manifest_suffix: Suffix for manifest files (.pyneat.manifest.json)
        max_line_length: Maximum line length warning threshold
    """
    enable_security: bool = True
    enable_ai_bugs: bool = True
    enable_conservative: bool = False
    enable_destructive: bool = False
    enable_quality: bool = True
    enable_performance: bool = False
    export_format: str = "json"
    manifest_suffix: str = ".pyneat.manifest.json"
    max_line_length: int = 120
    include_snippets: bool = True
    include_fix_hints: bool = True


@dataclass
class PluginDiagnostic:
    """A diagnostic issue from PyNEAT, ready for IDE display.

    This is the unified format that all plugins receive from PyNEAT,
    regardless of their IDE (VS Code, Neovim, JetBrains, etc.).
    """
    severity: str  # critical, high, medium, low, info
    code: str  # e.g., "SEC-001", "AI-BOUND-001"
    message: str  # Human-readable message
    file: str  # File path
    line: int  # 1-indexed line number
    end_line: Optional[int] = None  # For multi-line issues
    column: Optional[int] = None
    end_column: Optional[int] = None
    fix_available: bool = False
    fix_diff: Optional[str] = None  # Pre-computed fix diff
    rule_id: str = ""  # Rule that produced this diagnostic
    cwe_id: Optional[str] = None  # CWE security mapping

    def to_lsp_diagnostic(self) -> Dict[str, Any]:
        """Convert to Language Server Protocol diagnostic format."""
        return {
            "range": {
                "start": {
                    "line": max(0, self.line - 1),
                    "character": self.column or 0,
                },
                "end": {
                    "line": max(0, (self.end_line or self.line) - 1),
                    "character": self.end_column or 0,
                },
            },
            "severity": self._severity_to_lsp(),
            "code": self.code,
            "source": "PyNEAT",
            "message": self.message,
        }

    def _severity_to_lsp(self) -> int:
        """Convert PyNEAT severity to LSP severity constant."""
        return {
            "critical": 1,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }.get(self.severity, 2)


@dataclass
class PluginCodeAction:
    """A code action that can be applied to fix an issue.

    Unified format for code actions across all IDEs.
    """
    title: str  # Display title, e.g., "Fix: unused_import"
    kind: str = "quickfix"  # quickfix, refactor, action
    is_preferred: bool = False  # For security critical issues
    file: str = ""
    line: int = 1
    edit: Optional[Dict[str, Any]] = None  # Pre-filled edit
    command: Optional[Dict[str, Any]] = None  # Command to execute

    def to_lsp_code_action(self) -> Dict[str, Any]:
        """Convert to LSP CodeAction format."""
        action: Dict[str, Any] = {
            "title": self.title,
            "kind": self.kind,
            "isPreferred": self.is_preferred,
        }
        if self.edit:
            action["edit"] = self.edit
        if self.command:
            action["command"] = self.command
        return action


@runtime_checkable
class PyNEATPluginInterface(Protocol):
    """Protocol defining the PyNEAT plugin interface.

    All PyNEAT IDE plugins should implement this interface
    to ensure compatibility with the core engine.

    Example:
        class MyPlugin:
            def analyze(self, source: str, path: str) -> List[PluginDiagnostic]:
                ...

            def fix(self, source: str, path: str) -> str:
                ...
    """

    def analyze(
        self,
        source: str,
        path: str,
        config: Optional[PluginConfig] = None,
    ) -> List[PluginDiagnostic]:
        """Analyze source code and return diagnostics."""
        ...

    def fix(
        self,
        source: str,
        path: str,
        config: Optional[PluginConfig] = None,
    ) -> str:
        """Fix issues in source code and return cleaned code."""
        ...

    def get_capabilities(self) -> List[PluginCapability]:
        """Return list of capabilities this plugin provides."""
        ...


class PyNEATCore:
    """Core PyNEAT engine wrapper for plugins.

    This class provides a unified interface to the PyNEAT engine
    for all IDE plugins. It handles:
    - Loading the appropriate rules based on config
    - Converting results to plugin-friendly formats
    - Managing manifest files

    Example:
        core = PyNEATCore()
        diagnostics = core.analyze_file(Path("app.py"))
        for diag in diagnostics:
            print(f"{diag.severity}: {diag.message}")
    """

    def __init__(self, config: Optional[PluginConfig] = None):
        self.config = config or PluginConfig()
        self._engine = None  # Lazy load

    @property
    def engine(self):
        """Lazy-load the rule engine."""
        if self._engine is None:
            from pyneat.core.engine import RuleEngine
            self._engine = RuleEngine()
        return self._engine

    def analyze_file(
        self,
        path: Path,
        config: Optional[PluginConfig] = None,
    ) -> List[PluginDiagnostic]:
        """Analyze a file and return diagnostics.

        Args:
            path: Path to the Python file to analyze
            config: Optional plugin configuration

        Returns:
            List of PluginDiagnostic objects ready for IDE display
        """
        config = config or self.config
        content = path.read_text(encoding="utf-8")
        return self.analyze(content, str(path), config)

    def analyze(
        self,
        source: str,
        path: str,
        config: Optional[PluginConfig] = None,
    ) -> List[PluginDiagnostic]:
        """Analyze source code and return diagnostics.

        Args:
            source: Source code content
            path: File path (for reference in diagnostics)
            config: Optional plugin configuration

        Returns:
            List of PluginDiagnostic objects
        """
        config = config or self.config
        diagnostics: List[PluginDiagnostic] = []

        # Use the engine to analyze
        try:
            from pyneat.core.types import CodeFile, RuleConfig
            code_file = CodeFile(path=path, content=source)

            # Build rule config
            rule_config = RuleConfig(
                enabled=True,
                remove_debug=config.enable_quality,
                fix_style=True,
            )

            # Run engine
            results = self.engine.check_file(code_file)

            # Convert results to diagnostics
            for result in results.changes_made:
                diag = self._result_to_diagnostic(result, path)
                if diag:
                    diagnostics.append(diag)

        except Exception as e:
            # Return empty on error to not block IDE
            pass

        return diagnostics

    def _result_to_diagnostic(
        self,
        result: Any,
        path: str,
    ) -> Optional[PluginDiagnostic]:
        """Convert a RuleResult to PluginDiagnostic."""
        try:
            severity = getattr(result, "severity", "medium")
            message = getattr(result, "message", str(result))
            line = getattr(result, "line", 1)

            return PluginDiagnostic(
                severity=severity,
                code=getattr(result, "rule_id", "UNKNOWN"),
                message=message,
                file=path,
                line=line,
                rule_id=getattr(result, "rule_id", ""),
            )
        except Exception:
            return None

    def fix_file(
        self,
        path: Path,
        output: Optional[Path] = None,
        config: Optional[PluginConfig] = None,
    ) -> Path:
        """Fix issues in a file and optionally write to output.

        Args:
            path: Path to the file to fix
            output: Optional output path (if None, overwrites original)
            config: Optional plugin configuration

        Returns:
            Path to the fixed file
        """
        config = config or self.config
        content = path.read_text(encoding="utf-8")
        fixed = self.fix(content, str(path), config)

        output_path = output or path
        output_path.write_text(fixed, encoding="utf-8")
        return output_path

    def fix(
        self,
        source: str,
        path: str,
        config: Optional[PluginConfig] = None,
    ) -> str:
        """Fix issues in source code.

        Args:
            source: Source code content
            path: File path (for reference)
            config: Optional plugin configuration

        Returns:
            Fixed source code
        """
        config = config or self.config

        try:
            from pyneat.core.types import CodeFile
            code_file = CodeFile(path=path, content=source)
            result = self.engine.process(code_file)
            return result.transformed_content
        except Exception:
            return source

    def export_manifest(
        self,
        path: Path,
        format: str = "json",
        config: Optional[PluginConfig] = None,
    ) -> Optional[Path]:
        """Export manifest for a file.

        Args:
            path: Path to the source file
            format: Export format (json, sarif, codeclimate, markdown)
            config: Optional plugin configuration

        Returns:
            Path to the exported manifest file, or None on error
        """
        config = config or self.config
        content = path.read_text(encoding="utf-8")

        # Get markers from the file
        from_source = MarkerParser.from_source(content)
        manifest_path = path.with_suffix(path.suffix + config.manifest_suffix)

        if format == "sarif":
            sarif_data = export_to_sarif(
                from_source, path,
                tool_version="2.2.0-beta",
            )
            manifest_path = manifest_path.with_suffix(".sarif")
            import json
            manifest_path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
        elif format == "codeclimate":
            cc_data = export_to_codeclimate(from_source, path)
            manifest_path = manifest_path.with_suffix(".codeclimate.json")
            import json
            manifest_path.write_text(json.dumps(cc_data, indent=2), encoding="utf-8")
        elif format == "markdown":
            md_data = export_to_markdown(from_source, path, title=f"PyNEAT Report: {path.name}")
            manifest_path = manifest_path.with_suffix(".md")
            manifest_path.write_text(md_data, encoding="utf-8")
        else:
            # JSON (default)
            exporter = ManifestExporter()
            exporter.add_marker(
                from_source,
                path,
                content,
            )
            manifest_path = exporter.write(path)
            if manifest_path is None:
                return None

        return manifest_path

    def get_capabilities(self) -> List[PluginCapability]:
        """Return the capabilities of the core engine."""
        return [
            PluginCapability.LINT,
            PluginCapability.AUTO_FIX,
            PluginCapability.MANIFEST_EXPORT,
            PluginCapability.DIAGNOSTICS,
            PluginCapability.CODE_ACTIONS,
        ]


# --------------------------------------------------------------------------
# IDE-specific adapter helpers
# --------------------------------------------------------------------------

def create_vscode_adapter(core: PyNEATCore) -> Dict[str, Any]:
    """Create a VS Code extension adapter.

    Returns a dictionary with commands and functions that can be
    registered with VS Code's extension API.
    """
    return {
        "analyze": core.analyze,
        "fix": core.fix,
        "export_manifest": core.export_manifest,
        "diagnostics_to_vscode": lambda diagnostics: [
            d.to_lsp_diagnostic() for d in diagnostics
        ],
        "code_action_to_vscode": lambda action: action.to_lsp_code_action(),
    }


def create_neovim_adapter(core: PyNEATCore) -> Dict[str, Any]:
    """Create a Neovim Lua plugin adapter.

    Returns functions that can be called from Lua.
    """
    return {
        "analyze": core.analyze,
        "fix": core.fix,
        "export_manifest": core.export_manifest,
        "diagnostics_to_vim": lambda diagnostics: [
            {
                "lnum": d.line,
                "col": (d.column or 0) + 1,
                "text": f"[{d.severity.upper()}] {d.code}: {d.message}",
                "type": "E" if d.severity in ("critical", "high") else "W",
            }
            for d in diagnostics
        ],
    }


# --------------------------------------------------------------------------
# Entry point for plugin initialization
# --------------------------------------------------------------------------

def get_plugin(name: str = "core") -> PyNEATCore:
    """Get a PyNEAT plugin instance.

    Args:
        name: Plugin name ("core", "vscode", "neovim", "jetbrains")

    Returns:
        PyNEATCore instance configured for the plugin
    """
    return PyNEATCore()


__all__ = [
    "PluginCapability",
    "PluginConfig",
    "PluginDiagnostic",
    "PluginCodeAction",
    "PyNEATPluginInterface",
    "PyNEATCore",
    "create_vscode_adapter",
    "create_neovim_adapter",
    "get_plugin",
]
