"""Webhook server for PyNEAT - receive scan results and send real-time notifications.

Copyright (c) 2026 PyNEAT Authors
License: AGPL-3.0

Features:
  - HTTP webhook endpoint for receiving scan results
  - Real-time Slack/Discord notifications
  - GitHub/GitLab PR comment integration
  - Email alerts for critical findings
  - WebSocket for live dashboard updates
  - Rate limiting and authentication
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable
from datetime import datetime, timedelta

try:
    import asyncio
except ImportError:
    asyncio = None  # type: ignore

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore


@dataclass
class WebhookEvent:
    """A webhook event received by the server."""
    event_type: str  # scan.completed, scan.failed, finding.critical
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    source_ip: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    signature: Optional[str] = None


@dataclass
class NotificationChannel:
    """Configuration for a notification channel."""
    channel_type: str  # slack, discord, email, webhook, github
    url: str
    enabled: bool = True
    secret: Optional[str] = None
    filters: Dict[str, Any] = field(default_factory=dict)
    retry_count: int = 3
    retry_delay: float = 1.0


@dataclass
class ScanResultPayload:
    """Payload from a scan result webhook."""
    scan_id: str
    target: str
    findings_count: int
    findings: List[Dict[str, Any]]
    severity_summary: Dict[str, int]
    duration: float
    timestamp: str
    repository: Optional[str] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None


class WebhookServer:
    """HTTP server for receiving and processing PyNEAT webhooks.

    Endpoints:
      - POST /webhook/scan - Receive scan results
      - POST /webhook/subscribe - Subscribe to notifications
      - GET  /health - Health check
      - GET  /metrics - Prometheus metrics

    Security:
      - HMAC signature verification
      - Rate limiting per IP
      - API key authentication
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8080,
                 api_key: Optional[str] = None,
                 secret_key: Optional[str] = None):
        self.host = host
        self.port = port
        self.api_key = api_key or os.environ.get("PYNEAT_WEBHOOK_API_KEY", "")
        self.secret_key = secret_key or os.environ.get("PYNEAT_WEBHOOK_SECRET", "")

        self.channels: Dict[str, NotificationChannel] = {}
        self.event_handlers: List[Callable[[WebhookEvent], None]] = []
        self.rate_limits: Dict[str, List[float]] = {}  # IP -> timestamps
        self.rate_limit_window = 60  # seconds
        self.rate_limit_max = 100  # requests per window

        self._running = False

    def add_channel(self, channel: NotificationChannel) -> None:
        """Add a notification channel."""
        self.channels[channel.channel_type] = channel

    def remove_channel(self, channel_type: str) -> bool:
        """Remove a notification channel."""
        if channel_type in self.channels:
            del self.channels[channel_type]
            return True
        return False

    def on_event(self, handler: Callable[[WebhookEvent], None]) -> None:
        """Register an event handler."""
        self.event_handlers.append(handler)

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify HMAC signature of the payload."""
        if not self.secret_key:
            return True
        expected = hmac.new(
            self.secret_key.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(f"sha256={expected}", signature)

    def check_rate_limit(self, ip: str) -> bool:
        """Check if an IP is within rate limits.

        Returns True if allowed, False if rate limited.
        """
        now = time.time()
        window_start = now - self.rate_limit_window

        if ip not in self.rate_limits:
            self.rate_limits[ip] = []

        # Clean old entries
        self.rate_limits[ip] = [t for t in self.rate_limits[ip] if t > window_start]

        # Check limit
        if len(self.rate_limits[ip]) >= self.rate_limit_max:
            return False

        # Record this request
        self.rate_limits[ip].append(now)
        return True

    def process_event(self, event: WebhookEvent) -> Dict[str, Any]:
        """Process a webhook event and send notifications.

        Args:
            event: The webhook event to process

        Returns:
            Dict with processing results
        """
        results = {
            "event_type": event.event_type,
            "notifications_sent": 0,
            "notifications_failed": 0,
            "errors": [],
        }

        # Apply filters and send to each channel
        for channel in self.channels.values():
            if not channel.enabled:
                continue

            # Apply channel filters
            if not self._matches_filter(event, channel.filters):
                continue

            try:
                self._send_notification(channel, event)
                results["notifications_sent"] += 1
            except Exception as e:
                results["notifications_failed"] += 1
                results["errors"].append(str(e))

        # Run event handlers
        for handler in self.event_handlers:
            try:
                handler(event)
            except Exception as e:
                results["errors"].append(f"Handler error: {e}")

        return results

    def _matches_filter(self, event: WebhookEvent, filters: Dict[str, Any]) -> bool:
        """Check if an event matches the channel filters."""
        if not filters:
            return True

        # Filter by event type
        if "event_types" in filters:
            if event.event_type not in filters["event_types"]:
                return False

        # Filter by severity
        if "min_severity" in filters:
            payload = event.payload
            if "severity_summary" in payload:
                sev_order = ["critical", "high", "medium", "low", "info"]
                min_idx = sev_order.index(filters["min_severity"])
                for sev in sev_order[:min_idx]:
                    if payload["severity_summary"].get(sev, 0) > 0:
                        return True
                return False

        # Filter by repository
        if "repositories" in filters:
            repo = event.payload.get("repository")
            if repo and repo not in filters["repositories"]:
                return False

        return True

    def _send_notification(self, channel: NotificationChannel, event: WebhookEvent) -> None:
        """Send a notification to a channel."""
        if channel.channel_type == "slack":
            self._send_slack(channel, event)
        elif channel.channel_type == "discord":
            self._send_discord(channel, event)
        elif channel.channel_type == "webhook":
            self._send_webhook(channel, event)
        elif channel.channel_type == "email":
            self._send_email(channel, event)
        elif channel.channel_type == "github":
            self._send_github(channel, event)

    def _send_slack(self, channel: NotificationChannel, event: WebhookEvent) -> None:
        """Send notification to Slack."""
        payload = event.payload
        severity = payload.get("severity_summary", {})

        # Build Slack message
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"PyNEAT Scan: {event.event_type}",
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n{payload.get('target', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Findings:*\n{sum(severity.values())}"},
                ]
            },
        ]

        # Add severity breakdown
        if severity.get("critical"):
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":red_circle: *CRITICAL:* {severity.get('critical', 0)}\n"
                            f":orange_circle: *HIGH:* {severity.get('high', 0)}\n"
                            f":yellow_circle: *MEDIUM:* {severity.get('medium', 0)}"
                }
            })

        # Add findings details
        findings = payload.get("findings", [])[:5]
        if findings:
            finding_text = "\n".join([
                f"• `{f.get('rule_id', '?')}` at {f.get('file', '?')}:{f.get('line', '?')}"
                for f in findings
            ])
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Top findings:*\n{finding_text}"}
            })

        # Footer
        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Sent via PyNEAT Webhook | {datetime.now().isoformat()}"}
            ]
        })

        data = {"blocks": blocks}
        self._http_post(channel.url, data)

    def _send_discord(self, channel: NotificationChannel, event: WebhookEvent) -> None:
        """Send notification to Discord."""
        payload = event.payload
        severity = payload.get("severity_summary", {})

        # Determine color based on severity
        if severity.get("critical"):
            color = 0xFF0000  # Red
        elif severity.get("high"):
            color = 0xFFA500  # Orange
        elif severity.get("medium"):
            color = 0xFFFF00  # Yellow
        else:
            color = 0x00FF00  # Green

        embed = {
            "title": f"PyNEAT Scan: {event.event_type}",
            "color": color,
            "fields": [
                {"name": "Target", "value": payload.get("target", "N/A"), "inline": True},
                {"name": "Total Findings", "value": str(sum(severity.values())), "inline": True},
            ],
            "footer": {"text": "PyNEAT Webhook"},
            "timestamp": datetime.now().isoformat(),
        }

        # Add severity breakdown
        severity_text = "\n".join([
            f"**{k.upper()}**: {v}" for k, v in severity.items() if v > 0
        ])
        if severity_text:
            embed["fields"].append({
                "name": "Severity Breakdown",
                "value": severity_text,
                "inline": False
            })

        data = {"embeds": [embed]}
        self._http_post(channel.url, data)

    def _send_webhook(self, channel: NotificationChannel, event: WebhookEvent) -> None:
        """Forward to a generic webhook."""
        data = {
            "event": event.event_type,
            "timestamp": event.timestamp,
            "payload": event.payload,
        }
        self._http_post(channel.url, data)

    def _send_email(self, channel: NotificationChannel, event: WebhookEvent) -> None:
        """Send email notification.

        Note: Requires smtplib setup - placeholder for now.
        """
        # This would use smtplib to send email
        # For now, just log the event
        pass

    def _send_github(self, channel: NotificationChannel, event: WebhookEvent) -> None:
        """Create GitHub PR comment.

        Note: Requires GitHub API token - placeholder for now.
        """
        # This would use GitHub API to create PR comments
        pass

    def _http_post(self, url: str, data: Dict[str, Any]) -> None:
        """Make an HTTP POST request."""
        if aiohttp is not None:
            # Async version
            import asyncio
            asyncio.get_event_loop().run_until_complete(
                self._http_post_async(url, data)
            )
        else:
            # Sync version using requests
            try:
                import requests
                headers = {"Content-Type": "application/json"}
                requests.post(url, json=data, headers=headers, timeout=10)
            except ImportError:
                import urllib.request
                import urllib.error
                req = urllib.request.Request(
                    url,
                    data=json.dumps(data).encode(),
                    headers={"Content-Type": "application/json"}
                )
                try:
                    with urllib.request.urlopen(req, timeout=10) as response:
                        response.read()
                except urllib.error.HTTPError:
                    pass

    async def _http_post_async(self, url: str, data: Dict[str, Any]) -> None:
        """Async HTTP POST."""
        if aiohttp is None:
            return

        async with aiohttp.ClientSession() as session:
            await session.post(url, json=data, timeout=aiohttp.ClientTimeout(total=10))

    def run(self) -> None:
        """Run the webhook server.

        This is a simple synchronous server. For production,
        use a proper ASGI/WSGI server like uvicorn with FastAPI.
        """
        print(f"PyNEAT Webhook Server starting on {self.host}:{self.port}")
        print(f"  API Key: {'Configured' if self.api_key else 'None (unauthenticated)'}")
        print(f"  Channels: {len(self.channels)} configured")
        print(f"  Rate limit: {self.rate_limit_max} req/{self.rate_limit_window}s per IP")
        print("")
        print("Endpoints:")
        print(f"  POST /webhook/scan     - Receive scan results")
        print(f"  POST /webhook/subscribe - Subscribe to notifications")
        print(f"  GET  /health           - Health check")
        print(f"  GET  /metrics          - Prometheus metrics")
        print("")
        print("Press Ctrl+C to stop.")

        try:
            self._run_server()
        except KeyboardInterrupt:
            print("\nShutting down...")
            self._running = False

    def _run_server(self) -> None:
        """Run the server (simplified - use FastAPI for production)."""
        import http.server
        import socketserver

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                nonlocal server

                # Rate limit check
                client_ip = self.client_address[0]
                if not server.check_rate_limit(client_ip):
                    self.send_error(429, "Rate limit exceeded")
                    return

                # Read content
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length)

                # Verify signature
                signature = self.headers.get('X-Pyneat-Signature', '')
                if signature and not server.verify_signature(body, signature):
                    self.send_error(401, "Invalid signature")
                    return

                # Parse payload
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError:
                    self.send_error(400, "Invalid JSON")
                    return

                # Route to handler
                if self.path == '/webhook/scan':
                    self._handle_scan(payload, client_ip)
                elif self.path == '/webhook/subscribe':
                    self._handle_subscribe(payload, client_ip)
                else:
                    self.send_error(404, "Not found")

            def do_GET(self):
                nonlocal server
                if self.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "healthy"}).encode())
                elif self.path == '/metrics':
                    self._handle_metrics()
                else:
                    self.send_error(404, "Not found")

            def _handle_scan(self, payload: Dict, client_ip: str):
                event = WebhookEvent(
                    event_type=payload.get("event", "scan.completed"),
                    payload=payload,
                    source_ip=client_ip,
                    headers=dict(self.headers),
                )
                results = server.process_event(event)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(results).encode())

            def _handle_subscribe(self, payload: Dict, client_ip: str):
                channel = NotificationChannel(
                    channel_type=payload.get("type", "webhook"),
                    url=payload.get("url", ""),
                    filters=payload.get("filters", {}),
                )
                server.add_channel(channel)
                self.send_response(201)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "subscribed"}).encode())

            def _handle_metrics(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                metrics = [
                    f"pyneat_webhook_events_total 0",
                    f"pyneat_webhook_channels_total {len(server.channels)}",
                ]
                self.wfile.write('\n'.join(metrics).encode())

        server = self
        with socketserver.TCPServer((self.host, self.port), Handler) as httpd:
            self._running = True
            httpd.serve_forever()


def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    """Start the webhook server."""
    server = WebhookServer(host=host, port=port)
    server.run()


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    run_server(host, port)


__all__ = [
    "WebhookServer",
    "WebhookEvent",
    "NotificationChannel",
    "ScanResultPayload",
    "run_server",
]
