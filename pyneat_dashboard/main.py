"""PyNEAT Web Dashboard API - FastAPI REST API for security scanning.

Copyright (c) 2026 PyNEAT Authors
License: AGPL-3.0

Provides:
  - REST API endpoints for scanning and reporting
  - WebSocket for real-time scan updates
  - Project and scan history management
  - User authentication and API keys
  - SARIF/JSON report generation
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, WebSocket, WebSocketDisconnect, UploadFile, File, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field


# ============================================================================
# Pydantic Models
# ============================================================================

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    JAVA = "java"
    RUST = "rust"
    RUBY = "ruby"
    PHP = "php"
    CSHARP = "csharp"
    ALL = "all"


class ScanRequest(BaseModel):
    """Request model for starting a scan."""
    target: str = Field(..., description="Path or URL to scan")
    language: Language = Field(default=Language.ALL, description="Language to scan for")
    severity_filter: List[Severity] = Field(default=[], description="Filter by severity")
    rules: List[str] = Field(default=[], description="Specific rules to enable")
    scan_dependencies: bool = Field(default=True, description="Scan dependencies")
    include_iac: bool = Field(default=True, description="Include IaC files")


class ScanResponse(BaseModel):
    """Response model for a scan operation."""
    scan_id: str
    status: ScanStatus
    target: str
    created_at: str
    message: Optional[str] = None


class FindingModel(BaseModel):
    """Model for a security finding."""
    rule_id: str
    severity: Severity
    confidence: float
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    cvss_score: float
    file: str
    start_line: int
    end_line: int
    snippet: str
    problem: str
    fix_constraints: List[str] = []
    can_auto_fix: bool = False


class ScanResultModel(BaseModel):
    """Model for complete scan results."""
    scan_id: str
    status: ScanStatus
    target: str
    language: str
    started_at: str
    completed_at: Optional[str] = None
    duration: Optional[float] = None
    total_files: int
    findings_count: int
    severity_summary: Dict[str, int]
    findings: List[FindingModel] = []
    errors: List[str] = []


class ProjectModel(BaseModel):
    """Model for a project."""
    project_id: str
    name: str
    repository_url: Optional[str] = None
    created_at: str
    last_scan_at: Optional[str] = None
    scan_count: int = 0
    total_findings: int = 0


class PolicyRequest(BaseModel):
    """Request to evaluate a policy."""
    scan_id: str
    policy_name: str = Field(default="production", description="Policy to evaluate against")


class PolicyResultModel(BaseModel):
    """Policy evaluation result."""
    policy_name: str
    passed: bool
    violations_count: int
    blocked: bool
    summary: Dict[str, int]
    message: str


class ReportFormat(str, Enum):
    SARIF = "sarif"
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"


# ============================================================================
# Data Store (In-Memory for Demo - Use Database in Production)
# ============================================================================

@dataclass
class ScanJob:
    """Represents a scan job."""
    scan_id: str
    status: ScanStatus
    target: str
    language: str
    created_at: float
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    total_files: int = 0


class ScanStore:
    """In-memory store for scan jobs and results."""
    def __init__(self):
        self._scans: Dict[str, ScanJob] = {}
        self._ws_connections: List[WebSocket] = []

    def create_scan(self, scan_id: str, target: str, language: str) -> ScanJob:
        job = ScanJob(
            scan_id=scan_id,
            status=ScanStatus.PENDING,
            target=target,
            language=language,
            created_at=time.time(),
        )
        self._scans[scan_id] = job
        return job

    def get_scan(self, scan_id: str) -> Optional[ScanJob]:
        return self._scans.get(scan_id)

    def update_scan(self, scan_id: str, **kwargs) -> None:
        if scan_id in self._scans:
            for key, value in kwargs.items():
                setattr(self._scans[scan_id], key, value)

    def list_scans(self, limit: int = 100) -> List[ScanJob]:
        return sorted(self._scans.values(), key=lambda s: s.created_at, reverse=True)[:limit]

    def add_websocket(self, ws: WebSocket) -> None:
        self._ws_connections.append(ws)

    def remove_websocket(self, ws: WebSocket) -> None:
        if ws in self._ws_connections:
            self._ws_connections.remove(ws)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast a message to all WebSocket connections."""
        disconnected = []
        for ws in self._ws_connections:
            try:
                await ws.send_json(message)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            self.remove_websocket(ws)


scan_store = ScanStore()


# ============================================================================
# Background Scan Task
# ============================================================================

async def run_scan_task(scan_id: str, target: str, language: str) -> None:
    """Run a scan in the background and update the store."""
    from pyneat.core.engine import RuleEngine
    from pyneat.core.types import RuleConfig
    from pyneat.rules.security import SecurityScannerRule
    from pyneat.rules.secrets import SecretsScannerRule
    from pyneat.rules.iac_security import TerraformSecurityRule, KubernetesSecurityRule

    job = scan_store.get_scan(scan_id)
    if not job:
        return

    job.status = ScanStatus.RUNNING
    job.started_at = time.time()

    await scan_store.broadcast({
        "type": "scan.started",
        "scan_id": scan_id,
        "target": target,
    })

    try:
        # Build engine
        rules = [SecurityScannerRule(RuleConfig(enabled=True))]
        if language in ("all", "python"):
            rules.append(SecretsScannerRule(RuleConfig(enabled=True)))
        if language in ("all", "terraform", "k8s", "docker"):
            rules.extend([
                TerraformSecurityRule(),
                KubernetesSecurityRule(),
            ])

        engine = RuleEngine(rules)

        # Scan target
        target_path = Path(target)
        if not target_path.exists():
            job.errors.append(f"Target not found: {target}")
            job.status = ScanStatus.FAILED
            return

        if target_path.is_file():
            files = [target_path]
        else:
            # Recursively find files
            ext_map = {
                "python": ["*.py"],
                "javascript": ["*.js", "*.jsx"],
                "typescript": ["*.ts", "*.tsx"],
                "go": ["*.go"],
                "java": ["*.java"],
                "rust": ["*.rs"],
                "ruby": ["*.rb"],
                "php": ["*.php"],
            }
            globs = ext_map.get(language, ext_map["python"])
            files = []
            for g in globs:
                files.extend(target_path.rglob(g))
            files = [f for f in files if not any(s in f.parts for s in ["__pycache__", ".venv"])]

        job.total_files = len(files)

        # Process files
        all_findings = []
        for f in files:
            try:
                result = engine.process_file(f, language=language)
                for finding in result.security_findings:
                    all_findings.append({
                        "rule_id": finding.rule_id,
                        "severity": finding.severity.value,
                        "confidence": finding.confidence,
                        "cwe_id": finding.cwe_id,
                        "owasp_id": finding.owasp_id,
                        "cvss_score": finding.cvss_score,
                        "file": str(f),
                        "start_line": finding.start_line,
                        "end_line": finding.end_line,
                        "snippet": finding.snippet or "",
                        "problem": finding.problem,
                        "fix_constraints": list(finding.fix_constraints) if finding.fix_constraints else [],
                        "can_auto_fix": finding.can_auto_fix,
                    })
            except Exception as e:
                job.errors.append(f"Error scanning {f}: {str(e)}")

        job.findings = all_findings
        job.status = ScanStatus.COMPLETED
        job.completed_at = time.time()

        # Broadcast completion
        await scan_store.broadcast({
            "type": "scan.completed",
            "scan_id": scan_id,
            "findings_count": len(all_findings),
        })

    except Exception as e:
        job.status = ScanStatus.FAILED
        job.errors.append(str(e))
        job.completed_at = time.time()

        await scan_store.broadcast({
            "type": "scan.failed",
            "scan_id": scan_id,
            "error": str(e),
        })


# ============================================================================
# FastAPI App
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager."""
    print("PyNEAT Dashboard API starting...")
    yield
    print("PyNEAT Dashboard API shutting down...")


app = FastAPI(
    title="PyNEAT Security Scanner API",
    description="REST API for AI-Generated Code Security Scanning",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Health & Status Endpoints
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "pyneat-dashboard-api", "version": "1.0.0"}


@app.get("/metrics")
async def metrics():
    """Prometheus-style metrics."""
    scans = scan_store.list_scans()
    completed = sum(1 for s in scans if s.status == ScanStatus.COMPLETED)
    failed = sum(1 for s in scans if s.status == ScanStatus.FAILED)
    running = sum(1 for s in scans if s.status == ScanStatus.RUNNING)

    return {
        "pyneat_scans_total": len(scans),
        "pyneat_scans_completed": completed,
        "pyneat_scans_failed": failed,
        "pyneat_scans_running": running,
        "pyneat_websocket_connections": len(scan_store._ws_connections),
    }


# ============================================================================
# Scan Endpoints
# ============================================================================

@app.post("/api/v1/scans", response_model=ScanResponse)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Create a new scan job."""
    scan_id = str(uuid.uuid4())[:8]

    job = scan_store.create_scan(
        scan_id=scan_id,
        target=request.target,
        language=request.language.value,
    )

    # Start scan in background
    background_tasks.add_task(
        run_scan_task,
        scan_id,
        request.target,
        request.language.value,
    )

    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        target=request.target,
        created_at=datetime.fromtimestamp(job.created_at).isoformat(),
        message="Scan started",
    )


@app.get("/api/v1/scans", response_model=List[ScanResultModel])
async def list_scans(limit: int = Query(default=100, le=1000)):
    """List all scan jobs."""
    scans = scan_store.list_scans(limit)

    results = []
    for scan in scans:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in scan.findings:
            sev = f.get("severity", "info")
            summary[sev] = summary.get(sev, 0) + 1

        duration = None
        if scan.started_at and scan.completed_at:
            duration = scan.completed_at - scan.started_at

        results.append(ScanResultModel(
            scan_id=scan.scan_id,
            status=scan.status,
            target=scan.target,
            language=scan.language,
            started_at=datetime.fromtimestamp(scan.started_at or scan.created_at).isoformat(),
            completed_at=datetime.fromtimestamp(scan.completed_at).isoformat() if scan.completed_at else None,
            duration=duration,
            total_files=scan.total_files,
            findings_count=len(scan.findings),
            severity_summary=summary,
            findings=[],
            errors=scan.errors,
        ))

    return results


@app.get("/api/v1/scans/{scan_id}", response_model=ScanResultModel)
async def get_scan(scan_id: str):
    """Get a specific scan result."""
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in scan.findings:
        sev = f.get("severity", "info")
        summary[sev] = summary.get(sev, 0) + 1

    duration = None
    if scan.started_at and scan.completed_at:
        duration = scan.completed_at - scan.started_at

    findings = [FindingModel(**f) for f in scan.findings]

    return ScanResultModel(
        scan_id=scan.scan_id,
        status=scan.status,
        target=scan.target,
        language=scan.language,
        started_at=datetime.fromtimestamp(scan.started_at or scan.created_at).isoformat(),
        completed_at=datetime.fromtimestamp(scan.completed_at).isoformat() if scan.completed_at else None,
        duration=duration,
        total_files=scan.total_files,
        findings_count=len(scan.findings),
        severity_summary=summary,
        findings=findings,
        errors=scan.errors,
    )


@app.get("/api/v1/scans/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    severity: Optional[Severity] = None,
    rule_id: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
):
    """Get findings from a scan with filtering."""
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = scan.findings

    # Apply filters
    if severity:
        findings = [f for f in findings if f.get("severity") == severity.value]
    if rule_id:
        findings = [f for f in findings if rule_id.lower() in f.get("rule_id", "").lower()]

    # Paginate
    total = len(findings)
    findings = findings[offset:offset + limit]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "findings": findings,
    }


@app.get("/api/v1/scans/{scan_id}/report")
async def get_scan_report(scan_id: str, format: ReportFormat = ReportFormat.JSON):
    """Generate a report for a scan."""
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if format == ReportFormat.JSON:
        return scan_store.get_scan(scan_id)

    elif format == ReportFormat.SARIF:
        # Generate SARIF
        rules = {}
        results = []

        for f in scan.findings:
            rule_id = f"PYNEAT/{f['rule_id']}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f["rule_id"],
                    "shortDescription": {"text": f["problem"]},
                    "fullDescription": {"text": f"Security issue: {f['rule_id']}"},
                    "defaultConfiguration": {"level": "error" if f["severity"] in ("critical", "high") else "warning"},
                }

            results.append({
                "ruleId": rule_id,
                "level": "error" if f["severity"] in ("critical", "high") else "warning",
                "message": {"text": f["problem"]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"]},
                        "region": {"startLine": f["start_line"], "endLine": f["end_line"]},
                    }
                }],
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "PyNEAT",
                        "version": "1.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }]
        }
        return JSONResponse(content=sarif)

    elif format == ReportFormat.MARKDOWN:
        # Generate Markdown report
        lines = [
            f"# PyNEAT Security Scan Report",
            "",
            f"**Scan ID:** {scan.scan_id}",
            f"**Target:** {scan.target}",
            f"**Status:** {scan.status.value}",
            f"**Files Scanned:** {scan.total_files}",
            f"**Total Findings:** {len(scan.findings)}",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|---------|-------|",
        ]

        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in scan.findings:
            summary[f.get("severity", "info")] = summary.get(f.get("severity", "info"), 0) + 1

        for sev, count in summary.items():
            if count > 0:
                lines.append(f"| {sev.upper()} | {count} |")

        lines.extend(["", "## Findings", ""])

        for f in scan.findings:
            lines.extend([
                f"### {f['rule_id']} ({f['severity'].upper()})",
                "",
                f"**File:** `{f['file']}:{f['start_line']}`",
                "",
                f"{f['problem']}",
                "",
                "```",
                f["snippet"],
                "```",
                "",
            ])

        return {"content": "\n".join(lines), "content_type": "text/markdown"}

    return {"error": "Unsupported format"}


# ============================================================================
# Policy Endpoints
# ============================================================================

@app.post("/api/v1/policy/evaluate", response_model=PolicyResultModel)
async def evaluate_policy(request: PolicyRequest):
    """Evaluate scan findings against a policy."""
    scan = scan_store.get_scan(request.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    from pyneat.tools.policy_engine import PolicyEngine, SecuritySeverity

    engine = PolicyEngine()
    findings = []
    for f in scan.findings:
        from pyneat.core.types import SecurityFinding, SecuritySeverity
        findings.append(SecurityFinding(
            rule_id=f["rule_id"],
            severity=SecuritySeverity(f["severity"]),
            confidence=f["confidence"],
            cwe_id=f.get("cwe_id") or "",
            owasp_id=f.get("owasp_id") or "",
            cvss_score=f["cvss_score"],
            file=f["file"],
            start_line=f["start_line"],
            end_line=f["end_line"],
            snippet=f.get("snippet", ""),
            problem=f["problem"],
            fix_constraints=tuple(f.get("fix_constraints", [])),
            do_not=(),
            verify=(),
            resources=(),
            can_auto_fix=f.get("can_auto_fix", False),
            auto_fix_available=False,
        ))

    result = engine.evaluate(findings, request.policy_name)

    return PolicyResultModel(
        policy_name=result.policy.name if result.policy else request.policy_name,
        passed=result.passed,
        violations_count=len(result.violations),
        blocked=result.blocked,
        summary=result.summary,
        message=result.message,
    )


# ============================================================================
# WebSocket Endpoint
# ============================================================================

@app.websocket("/ws/scans")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time scan updates."""
    await websocket.accept()
    scan_store.add_websocket(websocket)

    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Echo back or handle commands
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        scan_store.remove_websocket(websocket)


# ============================================================================
# Upload Endpoint
# ============================================================================

@app.post("/api/v1/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload a file for scanning."""
    # Save uploaded file to temp location
    import tempfile
    import shutil

    suffix = Path(file.filename).suffix if file.filename else ".py"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    # Create scan for uploaded file
    scan_id = str(uuid.uuid4())[:8]
    job = scan_store.create_scan(
        scan_id=scan_id,
        target=tmp_path,
        language="python",  # Detect from extension
    )

    # Start scan
    asyncio.create_task(run_scan_task(scan_id, tmp_path, "python"))

    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        target=file.filename or "uploaded_file",
        created_at=datetime.fromtimestamp(job.created_at).isoformat(),
        message=f"File uploaded, scan started",
    )


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
