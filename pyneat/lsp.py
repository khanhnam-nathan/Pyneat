#!/usr/bin/env python3
"""
PyNEAT Language Server Protocol (LSP) Server

Provides real-time code analysis, diagnostics, and auto-fix capabilities
for VS Code, Neovim, and other LSP-compatible editors.

Install:
    pip install pyneat-cli[server]
    
Usage:
    python -m pyneat.lsp
    
In VS Code settings.json:
{
    "python.languageServer": "None",
    "pylance.enabled": false
}

Or use with nvim-lspconfig:
    lua require('lspconfig').pyneat.setup{}
"""

import argparse
import ast
import json
import sys
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import threading

# LSP Protocol
LSP_HEADER = "Content-Length: {}\r\n\r\n"
LSP_CONTENT_TYPE = "Content-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n"


class PyNEATLanguageServer:
    """PyNEAT LSP Server implementation."""

    capabilities = {
        "textDocumentSync": 1,  # Full sync
        "codeActionProvider": True,
        "codeLensProvider": {
            "resolveProvider": True
        },
        "completionProvider": {
            "resolveProvider": False,
            "triggerCharacters": ["."]
        },
        "diagnosticProvider": {
            "interFileDependencies": False,
            "workspaceDiagnostics": True
        },
        "documentFormattingProvider": True,
        "documentRangeFormattingProvider": True,
        "hoverProvider": True,
        "referencesProvider": True,
        "renameProvider": True,
        "workspaceSymbolProvider": True,
    }

    def __init__(self):
        import re
        self.documents: Dict[str, str] = {}
        self.workspace_root: Optional[str] = None
        self._shutdown = False
        self._diagnostics: Dict[str, List[Dict]] = {}  # uri -> diagnostics
        self._marker_regex = re.compile(r"#\s*PYNAGENT:\s*(\{[^}]+\})")

    def handle_message(self, message: str) -> Optional[str]:
        """Handle incoming LSP message."""
        try:
            data = json.loads(message)
            method = data.get("method", "")
            msg_id = data.get("id")
            params = data.get("params", {})

            if method == "initialize":
                return self._initialize(params, msg_id)
            elif method == "initialized":
                return None
            elif method == "shutdown":
                self._shutdown = True
                return self._response(msg_id, {"tag": None})
            elif method == "exit":
                return None
            elif method == "textDocument/didOpen":
                return self._did_open(params)
            elif method == "textDocument/didChange":
                return self._did_change(params)
            elif method == "textDocument/didClose":
                return self._did_close(params)
            elif method == "textDocument/codeAction":
                return self._code_action(params, msg_id)
            elif method == "textDocument/diagnostic":
                return self._diagnostic(params, msg_id)
            elif method == "textDocument/formatting":
                return self._formatting(params, msg_id)
            elif method == "textDocument/hover":
                return self._hover(params, msg_id)
            elif method == "workspace/symbol":
                return self._workspace_symbol(params, msg_id)
            else:
                return None

        except Exception as e:
            return self._error(-32603, str(e), msg_id)

    def _initialize(self, params: Dict, msg_id: Any) -> str:
        """Handle initialize request."""
        self.workspace_root = params.get("rootUri", "")

        return self._response(msg_id, {
            "capabilities": self.capabilities,
            "serverInfo": {
                "name": "PyNEAT Language Server",
                "version": "2.0.0"
            }
        })

    def _did_open(self, params: Dict) -> Optional[str]:
        """Handle text document open."""
        doc = params.get("textDocument", {})
        uri = doc.get("uri", "")
        content = doc.get("text", "")

        self.documents[uri] = content
        return self._publish_diagnostics(uri, content)

    def _did_change(self, params: Dict) -> Optional[str]:
        """Handle text document change."""
        doc = params.get("textDocument", {})
        uri = doc.get("uri", "")
        changes = params.get("contentChanges", [])

        if changes and uri in self.documents:
            self.documents[uri] = changes[-1].get("text", "")

        return self._publish_diagnostics(uri, self.documents.get(uri, ""))

    def _did_close(self, params: Dict) -> str:
        """Handle text document close."""
        doc = params.get("textDocument", {})
        uri = doc.get("uri", "")

        if uri in self.documents:
            del self.documents[uri]

        return self._publish_diagnostics(uri, "")

    def _diagnostic(self, params: Dict, msg_id: Any) -> str:
        """Handle document diagnostic request."""
        doc = params.get("textDocument", {})
        uri = doc.get("uri", "")
        content = self.documents.get(uri, "")

        diagnostics = self._analyze_code(content, uri)
        full = {
            "items": diagnostics,
            "kind": "full"
        }

        return self._response(msg_id, full)

    def _publish_diagnostics(self, uri: str, content: str) -> Optional[str]:
        """Publish diagnostics to client and cache them."""
        diagnostics = self._analyze_code(content, uri)
        self._diagnostics[uri] = diagnostics

        response = {
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": {
                "uri": uri,
                "diagnostics": diagnostics
            }
        }

        return self._send_response(response)

    def _analyze_code(self, content: str, uri: str) -> List[Dict]:
        """Analyze code and return diagnostics.

        Uses the full RuleEngine for comprehensive analysis.
        Falls back to basic AST detection if engine is unavailable.
        """
        diagnostics = []

        # Try using the full RuleEngine
        try:
            from pyneat.core.engine import RuleEngine
            from pyneat.core.types import CodeFile

            src_path = self._uri_to_path(uri) or "buffer"
            code_file = CodeFile(path=src_path, content=content)

            # Use the actual engine
            engine = RuleEngine()
            results = engine.check_file(code_file)

            # Convert results to LSP diagnostics
            for result in results.changes_made:
                diag = self._result_to_diagnostic(result)
                if diag:
                    diagnostics.append(diag)

            # Also check for agent markers
            from pyneat.core.manifest import MarkerParser
            markers = MarkerParser.from_source(content)
            for marker in markers:
                diag = self._marker_to_diagnostic(marker)
                diagnostics.append(diag)

        except ImportError:
            # Fallback to basic AST detection
            diagnostics = self._analyze_code_fallback(content)

        except Exception:
            # Fallback to basic AST detection on any error
            diagnostics = self._analyze_code_fallback(content)

        return diagnostics

    def _analyze_code_fallback(self, content: str) -> List[Dict]:
        """Fallback basic AST analysis when RuleEngine is unavailable."""
        diagnostics = []

        try:
            import ast
            tree = ast.parse(content)

            # Check for security issues
            for node in ast.walk(tree):
                # Check for eval/exec
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ("eval", "exec"):
                            diagnostics.append({
                                "range": self._node_to_range(node),
                                "severity": 1,  # Error
                                "code": "SEC-003",
                                "source": "PyNEAT",
                                "message": "Use of eval() or exec() can lead to code injection vulnerabilities"
                            })

                # Check for hardcoded passwords
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            name_lower = target.name.lower()
                            if any(keyword in name_lower for keyword in ["password", "passwd", "secret", "api_key"]):
                                diagnostics.append({
                                    "range": self._node_to_range(node),
                                    "severity": 2,  # Warning
                                    "code": "SEC-010",
                                    "source": "PyNEAT",
                                    "message": f"Potential hardcoded secret detected: {target.name}"
                                })

                # Check for SQL injection
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    for child in ast.walk(node):
                        if isinstance(child, ast.Attribute):
                            if child.attr in ["query", "sql"]:
                                diagnostics.append({
                                    "range": self._node_to_range(node),
                                    "severity": 2,
                                    "code": "SEC-020",
                                    "source": "PyNEAT",
                                    "message": "Potential SQL injection vulnerability"
                                })

        except SyntaxError as e:
            diagnostics.append({
                "range": {
                    "start": {"line": e.lineno or 0, "character": e.offset or 0},
                    "end": {"line": e.lineno or 0, "character": (e.offset or 0) + 1}
                },
                "severity": 1,
                "code": "E999",
                "source": "PyNEAT",
                "message": str(e)
            })

        return diagnostics

    def _result_to_diagnostic(self, result) -> Optional[Dict]:
        """Convert a RuleResult to LSP diagnostic format."""
        try:
            severity_map = {
                "critical": 1,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
            }

            severity = getattr(result, "severity", "medium")
            line = getattr(result, "line", 1)
            message = getattr(result, "message", str(result))
            code = getattr(result, "rule_id", "UNKNOWN")

            return {
                "range": {
                    "start": {"line": max(0, line - 1), "character": 0},
                    "end": {"line": max(0, line - 1), "character": 80}
                },
                "severity": severity_map.get(severity, 2),
                "code": code,
                "source": "PyNEAT",
                "message": message,
            }
        except Exception:
            return None

    def _marker_to_diagnostic(self, marker) -> Dict:
        """Convert an AgentMarker to LSP diagnostic format."""
        severity_map = {
            "critical": 1,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }

        return {
            "range": {
                "start": {"line": max(0, marker.line - 1), "character": 0},
                "end": {"line": max(0, marker.line - 1), "character": 80}
            },
            "severity": severity_map.get(marker.severity, 2),
            "code": marker.marker_id,
            "source": "PyNEAT",
            "message": f"[{marker.issue_type}] {marker.hint or marker.why}",
        }

    def _node_to_range(self, node: ast.AST) -> Dict:
        """Convert AST node to LSP range."""
        if hasattr(node, "lineno"):
            return {
                "start": {"line": node.lineno - 1, "character": node.col_offset or 0},
                "end": {
                    "line": getattr(node, "end_lineno", node.lineno) - 1,
                    "character": getattr(node, "end_col_offset", (node.col_offset or 0) + 1)
                }
            }
        return {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}}

    def _code_action(self, params: Dict, msg_id: Any) -> str:
        """Handle code action request with pre-filled edits."""
        doc = params.get("textDocument", {})
        uri = doc.get("uri", "")
        range_param = params.get("range", {})
        context = params.get("context", {})

        actions = []

        # Read manifest if exists
        manifest_markers = []
        try:
            src_path = self._uri_to_path(uri)
            if src_path:
                from pyneat.core.manifest import MarkerParser
                manifest_path = MarkerParser.find_manifest(src_path)
                if manifest_path:
                    manifest_markers = MarkerParser.from_manifest(manifest_path)
        except Exception:
            pass

        # Also parse PYNAGENT markers from source
        source_content = self.documents.get(uri, "")
        source_markers = []
        try:
            from pyneat.core.manifest import MarkerParser as MP2
            source_markers = MP2.from_source(source_content)
        except Exception:
            pass

        all_markers = manifest_markers + source_markers

        # Add actions for each marker
        for marker in all_markers:
            line = range_param.get("start", {}).get("line", 0)
            if marker.line - 1 != line:
                continue

            title = f"[PyNEAT] Fix: {marker.hint}" if marker.hint else f"[PyNEAT] Fix: {marker.issue_type}"
            kind = "quickfix"

            # Security critical issues are preferred
            is_preferred = marker.severity in ("critical", "high")

            action: Dict[str, Any] = {
                "title": title,
                "kind": kind,
                "isPreferred": is_preferred,
            }

            # Pre-filled edit if auto-fix is available
            if marker.auto_fix_available and marker.auto_fix_after:
                action["edit"] = {
                    "changes": {
                        uri: [{
                            "range": {
                                "start": {"line": marker.line - 1, "character": 0},
                                "end": {
                                    "line": marker.line,
                                    "character": 0
                                }
                            },
                            "newText": marker.auto_fix_after
                        }]
                    }
                }
            elif marker.can_auto_fix:
                # Suggest a generic fix command
                action["command"] = {
                    "title": title,
                    "command": "pyneat.fix",
                    "arguments": [uri, marker.marker_id, marker.issue_type]
                }

            actions.append(action)

        # Add fallback quick-fix actions based on diagnostics
        diagnostics = context.get("diagnostics", [])
        for diag in diagnostics:
            code = str(diag.get("code", ""))
            message = diag.get("message", "")

            if "eval" in message.lower() or "exec" in message.lower():
                actions.append({
                    "title": "Replace eval/exec with ast.literal_eval",
                    "kind": "quickfix",
                    "isPreferred": True,
                    "command": {
                        "title": "Replace with ast.literal_eval",
                        "command": "pyneat.fix",
                        "arguments": [uri, code, "eval"]
                    }
                })
            elif "secret" in message.lower() or "password" in message.lower() or "api_key" in message.lower():
                actions.append({
                    "title": "Move secret to environment variable",
                    "kind": "quickfix",
                    "command": {
                        "title": "Use os.environ",
                        "command": "pyneat.fix",
                        "arguments": [uri, code, "secret"]
                    }
                })
            elif "sql" in message.lower() or "injection" in message.lower():
                actions.append({
                    "title": "Use parameterized queries",
                    "kind": "quickfix",
                    "command": {
                        "title": "Fix SQL injection",
                        "command": "pyneat.fix",
                        "arguments": [uri, code, "sql_injection"]
                    }
                })

        return self._response(msg_id, actions)

    def _uri_to_path(self, uri: str) -> Optional[Any]:
        """Convert LSP URI to a Path object."""
        if uri.startswith("file://"):
            from pathlib import Path
            return Path(uri[7:].lstrip("/"))
        return None

    def _formatting(self, params: Dict, msg_id: Any) -> str:
        """Handle document formatting request."""
        doc = params.get("textDocument", {})
        uri = doc.get("uri", "")
        options = params.get("options", {})

        content = self.documents.get(uri, "")

        # Return formatted content (using black-like formatting)
        formatted = self._format_code(content)

        return self._response(msg_id, [{
            "range": {
                "start": {"line": 0, "character": 0},
                "end": {"line": len(content.splitlines()), "character": 0}
            },
            "newText": formatted
        }])

    def _format_code(self, content: str) -> str:
        """Format Python code."""
        try:
            import ast
            import black

            mode = black.Mode()
            formatted = black.format_str(content, mode=mode)
            return formatted
        except:
            return content

    def _hover(self, params: Dict, msg_id: Any) -> str:
        """Handle textDocument/hover with real PyNEAT marker and diagnostic info."""
        doc = params.get("textDocument", {})
        uri = doc.get("uri", "")
        position = params.get("position", {})

        line = position.get("line", 0)
        col = position.get("character", 0)

        # Get document content
        content = self._documents.get(uri, "")
        if not content:
            return self._response(msg_id, None)

        lines = content.split("\n")
        if line >= len(lines):
            return self._response(msg_id, None)

        # Check for PYNAGENT markers at this line
        for marker in self._get_markers(content):
            marker_line = marker.get("line", 0)
            if marker_line == line + 1:  # 1-indexed line
                hover_content = self._build_marker_hover(marker)
                return self._response(msg_id, hover_content)

        # Check for diagnostics at this position
        for diag in self._diagnostics.get(uri, []):
            diag_range = diag.get("range", {})
            start = diag_range.get("start", {})
            if start.get("line") == line:
                hover_content = self._build_diagnostic_hover(diag)
                return self._response(msg_id, hover_content)

        return self._response(msg_id, None)

    def _build_marker_hover(self, marker: Dict) -> Dict:
        """Build hover content for PYNAGENT marker."""
        marker_id = marker.get("id", "")
        issue_type = marker.get("type", "")
        severity = marker.get("severity", "medium")
        hint = marker.get("hint", "")
        why = marker.get("why", "")

        contents = f"**PYNAGENT: {marker_id}**\n\n"
        contents += f"**Type:** `{issue_type}`\n"
        contents += f"**Severity:** {severity}\n\n"
        if hint:
            contents += f"> {hint}\n\n"
        if why:
            contents += f"{why}"

        return {
            "contents": {
                "kind": "markdown",
                "value": contents.strip()
            }
        }

    def _build_diagnostic_hover(self, diag: Dict) -> Dict:
        """Build hover content for diagnostic."""
        code = diag.get("code", "")
        message = diag.get("message", "")
        source = diag.get("source", "PyNEAT")

        contents = f"**{source}: {code}**\n\n{message}"

        return {
            "contents": {
                "kind": "markdown",
                "value": contents
            }
        }

    def _get_markers(self, content: str) -> List[Dict]:
        """Extract PYNAGENT markers from content."""
        markers = []
        pattern = r"#\s*PYNAGENT:\s*(\{[^}]+\})"

        for match in self._marker_regex.finditer(content):
            try:
                marker = json.loads(match.group(1))
                marker["line"] = content[:match.start()].count("\n") + 1
                markers.append(marker)
            except (json.JSONDecodeError, AttributeError):
                continue

        return markers

    def _workspace_symbol(self, params: Dict, msg_id: Any) -> str:
        """Handle workspace/symbol - search for PyNEAT markers and issues."""
        query = (params.get("query", "") or "").lower()

        results = []
        for uri, diags in self._diagnostics.items():
            for diag in diags:
                code = (diag.get("code", "") or "").lower()
                message = (diag.get("message", "") or "").lower()

                if query in code or query in message or query in uri.lower():
                    location = {
                        "uri": uri,
                        "range": diag.get("range", {})
                    }
                    results.append({
                        "name": f"{diag.get('code', 'UNKNOWN')}: {diag.get('message', '')[:50]}",
                        "kind": 1,  # File symbol kind
                        "location": location,
                        "containerName": "PyNEAT"
                    })

        # Limit results to 10
        return self._response(msg_id, results[:10])

    def _response(self, msg_id: Any, result: Any) -> str:
        """Create success response."""
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": result
        }
        return self._send_response(response)

    def _error(self, code: int, message: str, msg_id: Any) -> str:
        """Create error response."""
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": code,
                "message": message
            }
        }
        return self._send_response(response)

    def _send_response(self, response: Dict) -> str:
        """Send response with proper headers."""
        body = json.dumps(response)
        return LSP_HEADER.format(len(body)) + body


def main():
    """Main entry point for LSP server."""
    parser = argparse.ArgumentParser(description="PyNEAT Language Server")
    parser.add_argument("--stdio", action="store_true", help="Use stdio transport")
    parser.add_argument("--tcp", type=int, help="TCP port to listen on")
    parser.add_argument("--socket", type=str, help="Unix socket path")
    args = parser.parse_args()

    server = PyNEATLanguageServer()
    buffer = ""

    if args.stdio or not args.tcp:
        # Stdio transport
        while not server._shutdown:
            try:
                line = sys.stdin.readline()
                if not line:
                    break

                if line.startswith("Content-Length:"):
                    content_length = int(line.split(":")[1].strip())
                    sys.stdin.readline()  # Empty line
                    body = sys.stdin.read(content_length)
                    response = server.handle_message(body)
                    if response:
                        sys.stdout.write(response)
                        sys.stdout.flush()
            except KeyboardInterrupt:
                break
    elif args.tcp:
        # TCP transport
        import socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("127.0.0.1", args.tcp))
        server_socket.listen(1)

        conn, addr = server_socket.accept()
        while not server._shutdown:
            data = conn.recv(4096)
            if not data:
                break

            buffer += data.decode("utf-8")

            while "Content-Length:" in buffer:
                header_end = buffer.find("\r\n\r\n")
                if header_end == -1:
                    break

                header = buffer[:header_end]
                content_length = int([l for l in header.split("\r\n") if l.startswith("Content-Length:")][0].split(":")[1].strip())

                body_start = header_end + 4
                if len(buffer) < body_start + content_length:
                    break

                body = buffer[body_start:body_start + content_length]
                buffer = buffer[body_start + content_length:]

                response = server.handle_message(body)
                if response:
                    conn.sendall(response.encode("utf-8"))


if __name__ == "__main__":
    main()


# Copyright (c) 2026 PyNEAT Authors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# For commercial licensing, contact: n.khanhnam@gmail.com
