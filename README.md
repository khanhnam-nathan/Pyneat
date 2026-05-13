# PyNeat: AI-Generated Code Cleaner

**PyNeat 3.1.7** is a code scanning and cleanup tool built specifically for AI-generated code. Unlike generic linters, PyNeat targets the patterns that AI coding assistants systematically produce -- phantom packages, hallucinated parameters, resource leaks, OWASP vulnerabilities, AI-specific security risks -- and cleans them up automatically. Supports 9 languages.

## What It Does

AI assistants are fast — but they generate code with predictable problems:

- **Phantom imports** — generic names like `utils`, `helpers`, `ai` that don't exist
- **Fake parameters** — `param1=x`, `fake=True`, `dummy_arg` that do nothing
- **Resource leaks** — `open()` without `with`, `requests` without timeout
- **Boundary errors** — `list[0]` without empty check, `.split()[0]` without validation
- **Redundant I/O** — same API call 3+ times with identical arguments
- **OWASP Top 10** — command injection, SQL injection, pickle RCE, weak crypto
- **AI-specific risks** — prompt injection, system prompt leakage, hallucinated API calls, tool call collisions
- **Debug artifacts** — `print()`, `pdb`, `console.log` left behind
- **Naming chaos** — mixed camelCase/snake_case in the same file
- **Identity comparisons** — `is 200` instead of `== 200`
- **Type checks** — `type(x) == list` instead of `isinstance(x, list)`

PyNeat detects all of these and auto-fixes what it safely can.

## Multi-Language Support

PyNeat handles 9 languages natively:

| Language | Auto-fix | Security scan |
|----------|---------|---------------|
| Python | ✅ | ✅ |
| JavaScript | ✅ | ✅ |
| TypeScript | ✅ | ✅ |
| Go | ✅ | ✅ |
| Java | ✅ | ✅ |
| Rust | ✅ | ✅ |
| C# | ✅ | ✅ |
| PHP | ✅ | ✅ |
| Ruby | ✅ | ✅ |

For maximum speed on large multi-language codebases, enable the Rust backend.

## Quick Start

```bash
# Install
pip install pyneat

# Scan for issues
pyneat check your_file.py

# Clean AI-generated code patterns
pyneat clean your_file.py --dry-run --diff

# Auto-fix (with backup)
pyneat clean your_file.py --in-place --backup
```

For Python API usage and examples, see [docs/quickstart.md](docs/quickstart.md).

### Running pyneat without installation

If you are working from the source repository (e.g., after `git clone` or `pip install -e .`), you can run pyneat as a Python module without needing to install it:

```bash
# Run CLI commands via module invocation
python -m pyneat check your_file.py
python -m pyneat clean your_file.py --dry-run
```

Both `pyneat check` (after install) and `python -m pyneat check` (from source) are equivalent.

## 3-Tier Package System

PyNeat uses three packages to balance safety vs. aggressiveness:

| Package | Use when |
|---------|----------|
| `safe` (default) | You want zero-risk fixes. Always-on rules that won't break code. |
| `conservative` | You want cleaner code. Adds unused import removal, f-string conversion, debug cleanup. |
| `destructive` | You want a full sweep. Aggressive refactoring — review changes before committing. |

## Safe Package (Default)

Runs automatically, no flags needed:

| Rule | What it fixes |
|------|--------------|
| `IsNotNoneRule` | `x != None` → `x is not None` (PEP8) |
| `RangeLenRule` | `range(len())` anti-pattern |
| `TypingRule` | Missing type annotations |
| `CodeQualityRule` | Magic numbers, empty except blocks |
| `PerformanceRule` | Inefficient loops |
| `SecurityScannerRule` | `os.system`, `pickle`, `secrets`, command injection, weak crypto |

## Conservative Package

```bash
pyneat clean your_file.py --package conservative
```

Adds: unused import removal, `.format()` → f-string, `@dataclass` suggestions, magic number detection, safe debug cleanup (`--safe-debug-clean`).

## Destructive Package

```bash
pyneat clean your_file.py --package destructive
```

Adds: import rewriting/reordering, naming convention enforcement (PascalCase), nested `if` flattening (Arrow Anti-pattern), TODO/FIXME removal, redundant expression simplification, dead code removal, `--aggressive-clean` (strip ALL `print()` calls), `--enable-all` for all rules at once.

## Security Scanning

`SecurityScannerRule` runs in all packages automatically.

### Core Security Rules (SEC-001 to SEC-060)

| Vulnerability | Auto-fix |
|-------------|---------|
| `yaml.load()` without Loader | **→ SafeLoader** |
| Empty `except: pass` | **→ `raise`** |
| Command injection (`os.system`, `subprocess` shell=True) | Warning |
| SQL injection (string concatenation) | Warning |
| `pickle.loads()` (RCE risk) | Warning |
| `eval`/`exec` dynamic execution | Warning |
| Weak crypto (`random` for tokens, `md5`/`sha1`) | Warning |
| Hardcoded secrets (`api_key`, `password`) | Warning |
| Template injection (`render_template_string`) | Warning |
| Path traversal (`open()` with user input) | Warning |
| XXE (unsafe XML parsing) | Warning |
| Debug mode (`DEBUG=True`) | Warning |
| LDAP injection | Warning |
| SSRF / Open redirect | Warning |
| CORS misconfiguration | Warning |

### NEW Security Rules (SEC-061 to SEC-072)

| Rule ID | Vulnerability | Severity | Description |
|---------|-------------|----------|-------------|
| SEC-061 | Missing Subresource Integrity (SRI) | Medium | External `<script>`/`<link>` without `integrity` attribute |
| SEC-062 | Missing Content-Type Validation | High | File upload without Content-Type verification |
| SEC-063 | Missing Rate Limiting | Medium | Sensitive endpoints without rate limiting |
| SEC-064 | Weak JWT Secret Key | Critical | Weak or hardcoded JWT secret |
| SEC-065 | Incomplete Session Destruction | Medium | Logout without full session cleanup |
| SEC-066 | Timing Attack Vulnerability | Medium | `==` used instead of timing-safe comparison |
| SEC-067 | Weak Server-side Validation | High | Only client-side validation, no server check |
| SEC-068 | Client-side Price Calculation | High | Price calculated on client sent to server |
| SEC-069 | Dangerous Dependencies | Medium | Outdated or vulnerable package versions |
| SEC-070 | Missing Docker Vulnerability Scan | Medium | Docker image without vulnerability scanning |
| SEC-071 | Sensitive Data in JWT | High | JWT payload contains sensitive data |
| SEC-072 | Missing CSP Nonce | Medium | Inline `<script>` without CSP nonce |

### Extended Security Rules (SEC-073 to SEC-105+)

33 additional rules organized by OWASP Top 10 2021:

| Category | Rules | Description |
|----------|-------|-------------|
| A01: Broken Access Control | SEC-073 to SEC-075 | IDOR, privilege escalation |
| A02: Cryptographic Failures | SEC-076 to SEC-078 | Weak hash, ECB mode, hardcoded keys |
| A03: Injection | SEC-079 to SEC-082 | LDAP, XPath, SSTI, command injection |
| A05: Security Misconfiguration | SEC-083 to SEC-084 | Debug mode, CORS |
| A07: Authentication Failures | SEC-085 to SEC-086 | Weak password, brute force |
| A08: Software Integrity | SEC-087 to SEC-088 | Insecure deserialization, HTTP without TLS |
| A09: Security Logging | SEC-089 | Sensitive info in logs |
| A10: SSRF | SEC-090 | Server-side request forgery |
| Additional | SEC-091 to SEC-105 | XXE, path traversal, race condition, ReDoS, etc. |

Run `pyneat check your_file.py --severity --cvss` for detailed scan with CVSS scores and CWE/OWASP references.

## AI Security Scanner (NEW)

Detects security risks specific to AI-generated code and AI applications:

| AI Vulnerability | Severity | Rule | Description |
|-----------------|----------|------|-------------|
| Prompt Injection | Critical | AI-010 | "Ignore previous instructions", "forget everything" |
| Context Confusion | Medium | AI-011 | Multi-turn conversation context confusion attacks |
| Proxy Injection | High | AI-012 | Tool call injection in AI agents |
| Missing Confidence Threshold | Medium | AI-020 | LLM output without confidence checking |
| Missing Fact Check | High | AI-021 | No fact verification for AI-generated content |
| Unguarded Sensitive Operation | High | AI-022 | Sensitive operations without guardrails |
| Verbose Error Exposure | Medium | AI-030 | Detailed errors exposing model internals |
| Missing API Rate Limit | Medium | AI-031 | AI API calls without rate limiting |
| Over-detailed System Info | Medium | AI-032 | Excessive system information in responses |
| Adversarial Input | Critical | AI-040 | Homoglyph attacks, injection patterns |
| Unicode Homograph Attack | Medium | AI-041 | Unicode confusable characters in AI inputs |
| System Prompt Leakage | High | AI-050 | Exposed system prompts in responses |
| Tool Call Collision | Medium | AI-051 | Conflicting tool names in AI agents |
| Missing Output Guardrails | High | AI-052 | AI without content filtering guardrails |
| Toxic Output Risk | Medium | AI-053 | Potentially harmful AI-generated content |
| Temperature Misuse | Low | AI-060 | Unsafe temperature parameter settings |
| Context Window Mismanagement | Medium | AI-061 | Context overflow handling issues |
| Hallucinated API Calls | High | AI-070 | Non-existent API endpoints in generated code |

## Rust Backend

For large codebases, the Rust scanner (`pyneat-rs`) delivers 50x-100x speedup:

```bash
pip install pyneat[rust]
pyneat clean your_file.py --rust
```

Uses tree-sitter for AST parsing, pre-compiled regex patterns, and Rayon for parallel processing. No GIL contention for true parallelism.

### Benchmark: PyNEAT vs the Competition

Benchmarked on 200 Python files (~50K LOC) from real vulnerable codebases:

| Tool | Time | Throughput | Security Rules | Languages |
|------|------:|----------:|:------------:|:---------:|
| **PyNEAT Rust** | **10.1 ms** | **20.4K/sec** | **200+** | **9** |
| Ruff | 5.0 ms | 40.0K/sec | 0 | 1 |
| Semgrep | 150 ms | 1.3K/sec | 1000+ | 30+ |
| Bandit | 2000 ms | 100/sec | 70 | 1 |

PyNEAT is **15x faster than Semgrep**, **200x faster than Bandit**, while detecting **53% more critical findings** on real-world vulnerable codebases.

For full benchmarks with detection rates and methodology, see [pyneat-rs/README.md](pyneat-rs/README.md).

### Rust Backend Features

- **LN-AST (Language-Neutral AST)**: Unified AST format for all 9 languages
- **500+ Rules**: 141 core Python/Rust + 230+ language-specific (JS/TS/Go/Java/Rust/C#/PHP/Ruby) + 23 AI security + 100+ enterprise rules
- **Multi-Language**: Native scanners for Python, JavaScript, TypeScript, Go, Java, Rust, C#, PHP, Ruby
- **Auto-fix Engine**: Atomic, conflict-aware code transformations
- **SARIF 2.1.0 Export**: Full compliance with GitHub Security Lab format
- **Python Bindings**: PyO3 integration for seamless Python usage
- **LSP Server**: Real-time IDE diagnostics via Language Server Protocol
- **CI/CD Integrations**: GitHub, GitLab, SonarQube native support

## Installation

```bash
pip install pyneat
```

Or from source:

```bash
git clone https://github.com/khanhnam-nathan/Pyneat.git
cd Pyneat
pip install -e .
```

After installation, the `pyneat` CLI command is available system-wide. Alternatively, you can always run pyneat as a Python module (no install required) from the repository root:

```bash
python -m pyneat check your_file.py
```

## CLI Reference

PyNeat exposes 11 commands:

| Command | Description |
|---------|-------------|
| `pyneat clean` | Clean a single file |
| `pyneat clean-dir` | Clean all files in a directory |
| `pyneat check` | Security scan (no auto-fix) |
| `pyneat rules` | List all available rules |
| `pyneat explain` | Detailed explanation of a rule (CWE, OWASP, fix steps) |
| `pyneat ignore` | Ignore a rule (per-file or globally) |
| `pyneat report` | Export security report (JSON/SARIF/HTML) |
| `pyneat security-db` | Manage CVE and GitHub Advisory databases |
| `pyneat audit-deps` | Audit dependencies for known vulnerabilities (OSV) |
| `pyneat sbom` | Generate Software Bill of Materials (CycloneDX/SPDX) |
| `pyneat mcp` | Start MCP server for Cursor/IDE integration |

Additional flags:

| Flag | Description |
|------|-------------|
| `--enable-all` | Enable all rules at once (destructive package) |
| `--export-manifest` | Auto-export `.pyneat.manifest.yaml` on exit |
| `--annotate` | Inject PYNAGENT YAML comments into source code |
| `--dry-run` | Preview changes without writing |
| `--diff` | Show diff before applying |
| `--backup` | Backup file before modifying |
| `--in-place` | Modify file directly |
| `--fail-on` | Exit with error on specific severity threshold |
| `--baseline` | Ignore known issues from baseline file |
| `--parallel` | Number of parallel threads |
| `--rust/--no-rust` | Force Rust/Python engine (default: Rust primary, Python fallback) |
| `--lang` | Target language for multi-language scanning (JS, TS, Go, Java...) |
| `--exclude` | Exclude files matching pattern (can be used multiple times) |
| `--rule` | Only run specific rules (can be used multiple times) |
| `--lock-files` | Discover and list lock files in the target directory |
| `--check-cve` | Include CVE scan in dependency audit |
| `--check-license` | Check license compliance of dependencies |

### Clean a single file

```bash
# Safe package (default) — zero risk
pyneat clean your_file.py

# Preview without writing
pyneat clean your_file.py --dry-run --diff

# In-place with backup
pyneat clean your_file.py --in-place --backup

# Conservative — cleaner code
pyneat clean your_file.py --package conservative

# Destructive — full sweep
pyneat clean your_file.py --package destructive
```

### Clean a directory

```bash
pyneat clean-dir ./src --dry-run --diff
pyneat clean-dir ./src --pattern "*.py" --in-place --backup --parallel
```

### Security scan

```bash
pyneat check your_file.py --severity --cvss
pyneat check ./src --fail-on critical --format sarif --output report.sarif
```

### Explain a rule

```bash
pyneat explain SEC-001
```

Shows: problem description, fix constraints, common mistakes, verification steps, documentation links.

### Ignore a rule

```bash
# Ignore one instance at specific file + line
pyneat ignore SEC-003 --file app.py --line 42 --reason "already sanitized"

# Ignore globally for entire project
pyneat ignore SEC-003 --global --reason "not applicable to our codebase"
```

### Export report

```bash
pyneat report ./src -f sarif -o security.sarif      # GitHub Code Scanning
pyneat report ./src -f json -o report.json          # Custom integration
pyneat report ./src -f html -o report.html          # Human-readable
pyneat report ./src -f yaml -o report.yaml          # PyNEAT manifest (full AgentMarker data)
pyneat report ./src -f junit -o junit.xml           # JUnit XML
pyneat report ./src -f gitlab -o gitlab.json        # GitLab SAST
pyneat report ./src -f sonarqube -o sq.json          # SonarQube Generic Issue
pyneat report ./src -f markdown -o report.md        # Markdown summary

# Use Rust scanner for speed (default: auto-detect)
pyneat report ./src -f sarif -o security.sarif --rust
```

### Manage security databases

```bash
pyneat security-db --status   # Show CVE/GHSA database status
pyneat security-db --update   # Update to latest CVE + GitHub Advisory
pyneat security-db --force     # Force update (ignore cache age)
```

### Interactive Feature Menu

After every `check`, `clean`, `rules`, or `report`, PyNeat shows a smart feature menu:

```
┌─────────────────────────────────────────────────────────────┐
│                  EXPLORE MORE FEATURES                     │
└─────────────────────────────────────────────────────────────┘

[A] 🔒 Security Check
    Quét lỗ hổng: SQL injection, path traversal, hardcoded secrets...
    → pyneat check file.py

[B] 🧹 Clean Code
    Thêm type hints, xóa unused imports, số magic, debug prints...
    → pyneat clean file.py

[C] 📖 Explain Rule
    Nguyên nhân, cách fix, CWE/OWASP, verification steps...
    → pyneat explain SEC-001

[D] 📊 Export Report (JSON/SARIF)
    Tích hợp CI/CD: GitHub Code Scanning, GitLab SAST...
    → pyneat report . -f sarif -o security.sarif

[q] Exit - return to terminal
[Enter] Skip this menu
```

## Python API

```python
from pyneat import clean_code, clean_file, analyze_code
from pyneat import RuleEngine, CodeFile, RuleConfig

# Clean code string
result = clean_code("x == None")  # "x is not None"

# Clean a file
from pathlib import Path
result = clean_file(Path("app.py"), in_place=True)
print(f"Made {len(result.changes_made)} changes")

# Analyze without fixing
report = analyze_code("x == None; print('debug')")
for issue in report['issues']:
    print(f"  - {issue}")
```

### Python API — Custom engine

```python
from pyneat import RuleEngine, CodeFile
from pyneat.rules import IsNotNoneRule, DebugCleaner

engine = RuleEngine([
    IsNotNoneRule(),
    DebugCleaner(mode="safe"),
])
result = engine.process_code_file(CodeFile(path=Path("demo.py"), content=source))
```

## Configuration

Add to `pyproject.toml`:

```toml
[tool.pyneat]
package = "safe"                  # safe, conservative, destructive

# Conservative
enable_unused_imports = true
enable_fstring = false
enable_dataclass = false
enable_magic_numbers = false
debug_clean_mode = "off"          # off, safe, aggressive

# Destructive (caution!)
enable_import_cleaning = false
enable_naming = false
enable_refactoring = false
enable_comment_clean = false
enable_redundant = false
enable_dead_code = false
enable_match_case = false

# CI/CD
export_manifest = false
```

## Rust/PyO3 API (High-Performance)

For maximum performance, use the Rust-accelerated scanner directly:

```python
import pyneat  # replaces pyneat_rs from v3.1.2+

# Security scan (Python)
issues = pyneat.scan_security(code)

# Security scan (any language: js, ts, go, java, rs, cs, php, rb)
js_issues = pyneat.scan_multilang(js_code, "javascript")
ts_issues = pyneat.scan_multilang(ts_code, "typescript")

# AI security scan
ai_issues = pyneat.scan_ai_security(ai_code, "python")

# Get rule catalog
rules = pyneat.get_rules()       # Core security rules (~141)
ai_rules = pyneat.get_ai_rules() # AI security rules (23)

# Detect language from file extension
lang = pyneat.detect_language("file.js")   # → "javascript"
lang = pyneat.detect_language("file.ts")    # → "typescript"

# Auto-fix
fixed_code = pyneat.apply_auto_fix(code, json.dumps(finding))

# Batch fixes with conflict resolution
result = pyneat.apply_fixes_batch(code, json.dumps(findings))
```

## Pre-commit Integration

```yaml
repos:
  - repo: local
    hooks:
      - id: pyneat-clean
        name: PyNeat AI Code Cleaner
        entry: pyneat clean --package conservative --in-place
        language: system
        types: [python]
        pass_filenames: true
        args: ['--dry-run']
```

```bash
# Linux/macOS
bash scripts/setup-pre-commit.sh

# Windows
scripts\setup-pre-commit.bat
```

## GitHub Actions

```yaml
name: PyNeat Code Quality
on: [push, pull_request]
jobs:
  pyneat:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - name: Install PyNeat
        run: pip install pyneat
      - name: Run PyNeat
        run: pyneat clean-dir . --dry-run
```

Full template at [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

### Manifest Export — CI/CD Integration
- `ManifestExporter` writes `.pyneat.manifest.json` with all markers
- `export_to_sarif()` — SARIF 2.1.0 format (GitHub Security, Azure DevOps)
- `export_to_codeclimate()` — Code Climate format
- `export_to_markdown()` — Human-readable report

### MarkerCleanup — Stale Marker Removal
- `MarkerCleanup` class removes markers after issues are fixed
- `remove_stale_markers()` — only removes markers not in remaining_issues
- `remove_all_markers()` — strips all PYNAGENT comments

## AgentMarker System

Every finding in PyNEAT is represented as an **AgentMarker** — a structured, self-contained object designed for agent-to-agent handoff. Unlike raw findings, AgentMarkers carry full context that lets an AI agent understand, fix, and track issues without external lookup.

### AgentMarker Fields

```python
@dataclass(frozen=True)
class AgentMarker:
    marker_id: str       # Unique ID, e.g. "PYN-SEC-0001"
    issue_type: str     # e.g. "sql_injection", "unused_import"
    rule_id: str        # e.g. "SecurityScannerRule", "DeadCodeRule"
    severity: str       # "critical", "high", "medium", "low", "info"
    line: int           # 1-indexed start line
    end_line: int       # 1-indexed end line
    hint: str           # Suggested fix
    why: str            # Why this is a problem
    impact: str         # Consequences if exploited
    confidence: float   # 0.0-1.0 detection confidence
    can_auto_fix: bool  # Whether auto-fix is conceptually possible
    fix_diff: str       # Unified diff for the fix
    snippet: str        # Code snippet (max 200 chars)
    cwe_id: str         # CWE-89, CWE-79...
    cvss_score: float   # e.g. 9.8
    cvss_vector: str    # CVSS:3.1/AV:N/AC:L/...
    owasp_id: str       # OWASP-A03
    related_markers: Tuple[str]  # Related marker IDs
```

### Manifest Export

Export full scan results as `.pyneat.manifest.yaml`:

```bash
pyneat clean your_file.py --export-manifest
```

The manifest contains:
- All AgentMarkers with full metadata
- Severity breakdown (critical/high/medium/low/info counts)
- Rules that were enabled
- Tool version and scan timestamp

### Manifest Diff — Track Progress

Compare two manifests to track code quality progress across commits:

```python
from pyneat.core.manifest_schema import diff_manifests, format_diff

old_manifest = load_manifest_or_fail("baseline.pyneat.manifest.yaml")
new_manifest = load_manifest_or_fail("current.pyneat.manifest.yaml")
diff = diff_manifests(old_manifest, new_manifest)
print(format_diff(diff))
```

## SBOM — Software Bill of Materials

Generate a complete inventory of your dependencies:

```bash
# CycloneDX JSON (default)
pyneat sbom --format cyclonedx-json --output sbom.json

# SPDX
pyneat sbom --format spdx-json --output sbom.json

# Include known vulnerabilities
pyneat sbom --format cyclonedx-json --output sbom.json --include-vulns
```

SBOM formats supported: **CycloneDX JSON**, **SPDX JSON**. Integrates with OSV database for vulnerability enrichment.

## Dependency Audit

Scan dependencies against the OSV vulnerability database:

```bash
# Scan installed packages
pyneat audit-deps

# Scan requirements.txt
pyneat audit-deps --path requirements.txt

# Export as SARIF for GitHub
pyneat audit-deps --format sarif --output vulns.sarif

# Export as SBOM with vulnerability data
pyneat audit-deps --format sbom --output sbom.json

# Check license compliance
pyneat audit-deps --check-license
```

## MCP Server — IDE Integration

PyNEAT includes a **Model Context Protocol (MCP)** server, enabling Cursor and other MCP-compatible editors to invoke PyNEAT as a native tool. This brings security scanning directly into your AI coding workflow without leaving the editor.

### Architecture

The MCP server runs as a **STDIO JSON-RPC 2.0** service — no network sockets, no HTTP, just stdin/stdout. This makes it safe, fast, and compatible with any MCP client.

```
Cursor (MCP Client)
    │
    ├─ JSON-RPC 2.0 over STDIO
    │
    ▼
PyNEAT MCP Server (pyneat.tools.mcp_server)
    │
    ├─ pyneat_scan        → Scan code string for issues
    ├─ pyneat_scan_file   → Scan file on disk
    ├─ pyneat_explain     → Get rule metadata
    ├─ pyneat_auto_fix    → Apply auto-fix
    ├─ pyneat_list_rules  → List available rules
    └─ pyneat_audit_deps  → Audit dependencies
```

### Setup

**1. Configure Cursor MCP**

Add to your Cursor settings (`settings.json`):

```json
{
  "mcpServers": {
    "pyneat": {
      "command": "python",
      "args": ["-m", "pyneat.tools.mcp_server"]
    }
  }
}
```

Or use the CLI shortcut:

```bash
# Just run this once to verify MCP is working
pyneat mcp --verbose
```

**2. Available MCP Tools**

| Tool | Description | Input |
|------|-------------|-------|
| `pyneat_scan` | Scan code string | `code`, `language` |
| `pyneat_scan_file` | Scan file on disk | `file_path`, `language` |
| `pyneat_explain` | Get rule metadata | `rule_id`, `issue_type` |
| `pyneat_auto_fix` | Apply auto-fix | `marker_id`, `code`, `language` |
| `pyneat_list_rules` | List all rules | `category`, `severity` |
| `pyneat_audit_deps` | Audit dependencies | `path`, `check_vulns` |

### Usage Examples

After setup, use PyNEAT tools directly in Cursor:

```
# Scan code for security issues
Tool: pyneat_scan
code: eval(user_input)
language: python

# Scan a file
Tool: pyneat_scan_file
file_path: ./src/auth.py

# Get rule explanation
Tool: pyneat_explain
rule_id: SEC-001

# Auto-fix a finding
Tool: pyneat_auto_fix
marker_id: PYN-SEC-0001
code: os.system(user_input)
language: python

# List security rules
Tool: pyneat_list_rules
category: security
severity: high

# Audit dependencies
Tool: pyneat_audit_deps
path: requirements.txt
check_vulns: true
```

### Response Format

Every tool returns structured **AgentMarkers**:

```json
{
  "marker_id": "PYN-SEC-0001",
  "issue_type": "sql_injection",
  "rule_id": "SecurityScannerRule",
  "severity": "critical",
  "line": 42,
  "end_line": 42,
  "hint": "Use parameterized queries instead of string concatenation",
  "why": "User input is directly embedded in SQL query",
  "impact": "Attacker can read/modify/delete database records",
  "confidence": 0.95,
  "can_auto_fix": false,
  "cwe_id": "CWE-89",
  "cvss_score": 9.8,
  "owasp_id": "OWASP-A03"
}
```

This structure gives AI agents everything they need to understand and fix the issue — without any external lookup.

### Python API — MCP Tools

You can also use the MCP tool functions directly from Python:

```python
from pyneat.tools.mcp_server import (
    scan_code, scan_file, explain_rule,
    auto_fix_code, list_rules, audit_deps
)

# Scan code
results = scan_code("eval(user_input)", language="python")
for marker in results:
    print(f"{marker.marker_id}: {marker.issue_type}")

# Audit dependencies
vulns = audit_deps("requirements.txt", check_vulns=True)
print(f"Found {len(vulns)} vulnerabilities")
```

## VSCode Extension

PyNeat is available as a VSCode/Cursor extension:

- **Real-time diagnostics** for Python, JavaScript, TypeScript
- **Quick Fix** — auto-fix with one click
- **Hover info** — severity, CWE, fix constraints, verification steps
- **Context menu** — Apply Fix, Send to AI Agent, Ignore, Add Comment
- **Save-triggered scan** — runs automatically when you save

Install from `.vsix` or search the marketplace (coming soon).

## Examples

Check out the [examples/](examples/) directory for ready-to-use scripts:

| Example | Description |
|---------|-------------|
| [basic_usage.py](examples/basic_usage.py) | Scan and clean a single file |
| [security_scan.py](examples/security_scan.py) | Security scanning with SARIF export |
| [batch_processing.py](examples/batch_processing.py) | Process entire projects |
| [custom_rule.py](examples/custom_rule.py) | Create and use custom rules |
| [pre_commit_integration.py](examples/pre_commit_integration.py) | Integrate with pre-commit hooks |

Run an example:
```bash
python examples/basic_usage.py
```

## Documentation

| Document | Description |
|----------|-------------|
| [docs/quickstart.md](docs/quickstart.md) | 5-minute getting started guide |
| [docs/faq.md](docs/faq.md) | Frequently asked questions |
| [docs/architecture.md](docs/architecture.md) | Technical architecture |
| [docs/writing-rules.md](docs/writing-rules.md) | Creating custom rules |
| [docs/github-actions-guide.md](docs/github-actions-guide.md) | CI/CD integration guide |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community code of conduct |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Build distribution
python -m build
```

## Architecture: 7-Layer Protection System

| Layer | Component | Description |
|-------|-----------|-------------|
| 1 | **AST Guard** | Validates code structure before processing |
| 2 | **Semantic Guard** | Preserves code semantics during transformations |
| 3 | **Type Shield** | Prevents type-related regressions |
| 4 | **Atomic Operations** | Ensures atomic transformations |
| 5 | **Scope Guard** | Isolates changes within safe boundaries |
| 6 | **Type Checking** | Validates with mypy/pyright |
| 7 | **Fuzz Testing** | Stress tests with malformed inputs |

## Editions & Commercial Support

PyNeat uses a dual-licensing / freemium model.

### PyNeat Community (current, free)
- **License:** GNU AGPLv3
- **Engine:** Pure Python + Rust hybrid (`pyneat-rs`)
- **Best for:** Individual developers, students, small projects
- **Rust coverage:** ~30% of rules (security + quality)

### PyNeat Standard (on request)
- **Engine:** Full Rust (`pyneat-rs`) for extreme performance
- **Features:** Multi-threading, 50x-100x faster, deep CI/CD integration
- **Best for:** Mid-sized teams, 1,000+ files

### PyNeat Enterprise (on request)
- **Features:** Everything in Standard + Custom Ruleset API, Audit Reports, Dedicated SLA
- **Best for:** Large enterprises

**Commercial License Exemption:** If you cannot comply with AGPLv3 (e.g., proprietary SaaS, closed-source embedding), contact the author for a commercial license.

Contact: `khanhnam.copywriting@gmail.com`

## License

PyNeat is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

PyNeat is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

AGPLv3 with Commercial Exception: Commercial use of this software
(e.g., bundling in paid products, SaaS services) is permitted,
provided that you comply with the open source obligations under AGPLv3 §11.
Contact the author for alternative licensing arrangements.
