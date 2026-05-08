"""PyNEAT tools package.

Copyright (c) 2026 PyNEAT Authors
License: AGPL-3.0

Provides:
  - OSV vulnerability database client
  - SBOM (Software Bill of Materials) generator
  - Dependency vulnerability scanner
  - Interactive TUI for security scanning
  - AI-powered fix suggestions
  - Policy engine for compliance checking
  - Webhook server for CI/CD integration
  - MCP server for Cursor IDE integration (JSON-RPC 2.0 over stdio)
"""

from pyneat.tools.osv_client import OsvClient, OsvVulnerability
from pyneat.tools.sbom_generator import SBOMGenerator, SBOMDocument, SBOMComponent
from pyneat.tools.vulnerability_scanner import DependencyScanner, DependencyInfo, VulnerabilityScanResult

# Lazy imports for optional tools (may require additional dependencies)
__all__ = [
    # Core tools
    "OsvClient",
    "OsvVulnerability",
    "SBOMGenerator",
    "SBOMDocument",
    "SBOMComponent",
    "DependencyScanner",
    "DependencyInfo",
    "VulnerabilityScanResult",
    # Optional tools (lazy-loaded)
    "InteractiveScanner",
    "FixSuggestionEngine",
    "PolicyEngine",
    "WebhookServer",
    "McpServer",
]


def __getattr__(name: str):
    """Lazy load optional tools to avoid hard dependencies."""
    if name == "InteractiveScanner":
        from pyneat.tools.tui import InteractiveScanner
        return InteractiveScanner
    if name == "FixSuggestionEngine":
        from pyneat.tools.ai_fixer import FixSuggestionEngine
        return FixSuggestionEngine
    if name == "PolicyEngine":
        from pyneat.tools.policy_engine import PolicyEngine
        return PolicyEngine
    if name == "WebhookServer":
        from pyneat.tools.webhook_server import WebhookServer
        return WebhookServer
    if name == "McpServer":
        from pyneat.tools.mcp_server import main as McpServer
        return McpServer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
