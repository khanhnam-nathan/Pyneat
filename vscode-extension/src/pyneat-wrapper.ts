/**
 * PyNeat - AI Code Cleaner
 * 
 * Copyright (C) 2026 PyNEAT Authors
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * PyNEAT CLI Wrapper
 * Handles communication between VS Code extension and PyNEAT Python CLI
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { spawn, ChildProcess } from 'child_process';

export interface PyneatFinding {
  rule_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  cwe_id: string;
  owasp_id: string;
  cvss_score: number;
  cvss_vector: string;
  file: string;
  start_line: number;
  end_line: number;
  snippet: string;
  problem: string;
  fix_constraints: string[];
  do_not: string[];
  verify: string[];
  resources: string[];
  can_auto_fix: boolean;
  auto_fix_available: boolean;
  auto_fix_before: string | null;
  auto_fix_after: string | null;
}

export interface PyneatScanResult {
  scan_version: string;
  timestamp: string;
  target: string;
  total_files: number;
  scan_duration_seconds: number;
  summary: Record<string, number>;
  findings: PyneatFinding[];
  dependency_findings?: PyneatDependencyFinding[];
}

export interface PyneatDependencyFinding {
  rule_id: string;
  severity: string;
  package: string;
  version: string;
  ecosystem: string;
  cve_id: string | null;
  ghsa_id: string | null;
  description: string;
  fixed_version: string | null;
  source: string;
  recommendation: string;
}

export interface PyneatIgnoreEntry {
  rule_id: string;
  file: string;
  line: number | null;
  reason: string;
}

export class PyneatWrapper {
  private pythonPath: string;
  private config: vscode.WorkspaceConfiguration;
  private runningProcesses: Map<string, ChildProcess> = new Map();

  constructor(_context: vscode.ExtensionContext) {
    const resourceUri = vscode.workspace.workspaceFolders?.[0]?.uri ?? null;
    this.config = vscode.workspace.getConfiguration('pyneat', resourceUri);
    this.pythonPath = this.config.get('pythonPath', 'python') as string;
  }

  /**
   * Run PyNEAT check and return parsed results (multi-language)
   */
  async checkFile(filePath: string): Promise<PyneatScanResult | null> {
    const ext = filePath.split('.').pop()?.toLowerCase();
    let args: string[];

    if (ext === 'py') {
      // Try native Rust backend first if enabled
      const useRust = this.config.get('enableRustBackend', true) as boolean;
      if (useRust && await this.isPyneatRsAvailable()) {
        args = [await this.getPyneatRsPath(), 'check', '--format', 'sarif', filePath];
        return this.runPyneatRs(args);
      }
      args = ['-m', 'pyneat.cli', 'check', filePath, '--format', 'json', '--output', '-'];
    } else {
      // Multi-language scanning via pyneat-rs native binary
      const pyneatRsPath = await this.getPyneatRsPath();
      if (pyneatRsPath) {
        args = [pyneatRsPath, 'scan', '--format', 'sarif', filePath];
        return this.runPyneatRs(args);
      }
      // Fallback to Python CLI
      args = ['-m', 'pyneat.cli', 'check', filePath, '--format', 'json', '--output', '-'];
    }

    const result = await this.runPyneat(args);
    if (!result) { return null; }

    try {
      return JSON.parse(result) as PyneatScanResult;
    } catch {
      vscode.window.showErrorMessage('PyNEAT: Failed to parse scan results');
      return null;
    }
  }

  /**
   * Run PyNEAT with SARIF format output
   */
  async checkFileSarif(filePath: string): Promise<string | null> {
    const ext = filePath.split('.').pop()?.toLowerCase();
    const pyneatRsPath = await this.getPyneatRsPath();

    let args: string[];
    if (ext === 'py' && pyneatRsPath) {
      args = [pyneatRsPath, 'check', '--format', 'sarif', filePath];
    } else if (pyneatRsPath) {
      args = [pyneatRsPath, 'scan', '--format', 'sarif', filePath];
    } else {
      args = ['-m', 'pyneat.cli', 'check', filePath, '--format', 'sarif', '--output', '-'];
    }

    return this.runPyneat(args);
  }

  /**
   * Run PyNEAT workspace scan with SARIF output
   */
  async checkWorkspaceSarif(dirPath: string): Promise<string | null> {
    const pyneatRsPath = await this.getPyneatRsPath();

    let args: string[];
    if (pyneatRsPath) {
      args = [pyneatRsPath, 'scan', '--format', 'sarif', dirPath];
    } else {
      args = ['-m', 'pyneat.cli', 'check', dirPath, '--format', 'sarif', '--output', '-'];
    }

    return this.runPyneat(args);
  }

  /**
   * Run native Rust backend
   */
  private async runPyneatRs(args: string[]): Promise<PyneatScanResult | null> {
    const result = await this.runPyneat(args);
    if (!result) { return null; }

    try {
      const sarif = JSON.parse(result);
      // Convert SARIF to PyneatScanResult format
      return this.convertSarifToResult(sarif);
    } catch {
      return null;
    }
  }

  /**
   * Convert SARIF format to PyneatScanResult
   */
  private convertSarifToResult(sarif: any): PyneatScanResult {
    const findings: PyneatFinding[] = [];
    const run = sarif.runs?.[0];
    const results = run?.results || [];

    for (const r of results) {
      const loc = r.locations?.[0];
      const physLoc = loc?.physicalLocation;
      const region = physLoc?.region;
      const uri = physLoc?.artifactLocation?.uri || '';
      const fileName = uri.split(/[/\\]/).pop() || uri;

      findings.push({
        rule_id: r.ruleId?.split('/').pop() || 'UNKNOWN',
        severity: this.sarifLevelToSeverity(r.level),
        confidence: 1.0,
        cwe_id: r.properties?.cwe_id || '',
        owasp_id: '',
        cvss_score: parseFloat(r.properties?.cvss || '5.0'),
        cvss_vector: '',
        file: uri,
        start_line: region?.startLine || 1,
        end_line: region?.endLine || region?.startLine || 1,
        snippet: region?.snippet?.text || '',
        problem: r.message?.text || 'Security issue found',
        fix_constraints: r.properties?.fix_hint ? [r.properties.fix_hint] : [],
        do_not: [],
        verify: [],
        resources: [],
        can_auto_fix: false,
        auto_fix_available: r.properties?.can_auto_fix || false,
        auto_fix_before: null,
        auto_fix_after: null,
      });
    }

    return {
      scan_version: '2.4.5',
      timestamp: new Date().toISOString(),
      target: '',
      total_files: 1,
      scan_duration_seconds: 0,
      summary: findings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {} as Record<string, number>),
      findings,
    };
  }

  /**
   * Map SARIF level to PyNEAT severity
   */
  private sarifLevelToSeverity(level: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    switch (level) {
      case 'error': return 'high';
      case 'warning': return 'medium';
      case 'note': return 'low';
      default: return 'info';
    }
  }

  /**
   * Check if native Rust backend is available
   */
  async isPyneatRsAvailable(): Promise<boolean> {
    const paths = [
      './pyneat-rs/target/release/pyneat',
      './target/release/pyneat',
      'pyneat-rs',
      'pyneat',
    ];
    for (const p of paths) {
      try {
        const result = await this.runPyneat([p, '--version']);
        if (result) { return true; }
      } catch { /* ignore */ }
    }
    return false;
  }

  /**
   * Get path to native Rust binary
   */
  async getPyneatRsPath(): Promise<string | null> {
    const paths = [
      vscode.workspace.getConfiguration('pyneat').get('pyneatRsPath', '') as string,
      './target/release/pyneat.exe',
      './target/release/pyneat',
      './pyneat-rs/target/release/pyneat.exe',
      './pyneat-rs/target/release/pyneat',
    ];
    return paths.find(p => p && fs.existsSync(p)) || null;
  }

  /**
   * Run PyNEAT check on workspace
   */
  async checkWorkspace(dirPath: string): Promise<PyneatScanResult | null> {
    const args = [
      '-m', 'pyneat.cli',
      'check', dirPath,
      '--format', 'json',
      '--output', '-'
    ];

    const result = await this.runPyneat(args);
    if (!result) { return null; }

    try {
      return JSON.parse(result) as PyneatScanResult;
    } catch {
      vscode.window.showErrorMessage('PyNEAT: Failed to parse scan results');
      return null;
    }
  }

  /**
   * Get a quick scan with dry-run (faster)
   */
  async quickScan(filePath: string): Promise<PyneatFinding[]> {
    const args = [
      '-m', 'pyneat.cli',
      'clean', filePath,
      '--dry-run',
      '--format', 'json'
    ];

    const result = await this.runPyneat(args);
    if (!result) {
      return [];
    }

    try {
      const parsed = JSON.parse(result);
      return parsed.findings || [];
    } catch {
      return [];
    }
  }

  /**
   * Apply auto-fix to file
   */
  async applyFix(filePath: string): Promise<boolean> {
    const args = [
      '-m', 'pyneat.cli',
      'check', filePath,
      '--apply',
      '--yes'
    ];

    const result = await this.runPyneat(args, 60000);
    return result !== null;
  }

  /**
   * Add context comment to file
   */
  async addContext(filePath: string, finding: PyneatFinding): Promise<boolean> {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    if (finding.start_line < 1 || finding.start_line > lines.length) {
      return false;
    }

    const comment = this.buildContextComment(finding);
    lines.splice(finding.start_line - 1, 0, comment);

    try {
      fs.writeFileSync(filePath, lines.join('\n'), 'utf-8');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Build context comment for a finding
   */
  buildContextComment(finding: PyneatFinding): string {
    const fix = finding.fix_constraints[0] || 'See documentation';
    return `# [SEC-${finding.rule_id}] SECURITY WARNING
# Severity: ${finding.severity.toUpperCase()}
# Reason: ${finding.problem}
# Fix: ${fix}`;
  }

  /**
   * Check if PyNEAT is available
   */
  async isAvailable(): Promise<boolean> {
    try {
      const result = await this.runPyneat(['--version']);
      return result !== null;
    } catch {
      return false;
    }
  }

  /**
   * Get PyNEAT version
   */
  async getVersion(): Promise<string | null> {
    const result = await this.runPyneat(['--version']);
    return result?.trim() || null;
  }

  /**
   * Ignore an issue at specific location
   */
  async ignoreIssue(finding: PyneatFinding, reason: string): Promise<boolean> {
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!workspaceRoot) {
      vscode.window.showWarningMessage('No workspace folder open');
      return false;
    }

    const ignorePath = path.join(workspaceRoot, this.config.get('workspaceIgnore', '.pyneatignore'));

    const entry = `SEC-${finding.rule_id} ${finding.file}:${finding.start_line} # ${reason}\n`;

    try {
      if (fs.existsSync(ignorePath)) {
        const existing = fs.readFileSync(ignorePath, 'utf-8');
        fs.writeFileSync(ignorePath, existing + entry, 'utf-8');
      } else {
        fs.writeFileSync(ignorePath, entry, 'utf-8');
      }
      return true;
    } catch {
      vscode.window.showErrorMessage('PyNEAT: Failed to write ignore file');
      return false;
    }
  }

  /**
   * Format finding as AI agent context
   */
  formatAIGentContext(finding: PyneatFinding): string {
    const context = `## PyNEAT Security Finding

**File:** \`${finding.file}\`
**Line:** ${finding.start_line}
**Rule:** SEC-${finding.rule_id}
**Severity:** ${finding.severity.toUpperCase()}
**CWE:** ${finding.cwe_id || 'N/A'}
**OWASP:** ${finding.owasp_id || 'N/A'}

**Code Snippet:**
\`\`\`
${finding.snippet}
\`\`\`

**Problem:** ${finding.problem}

**Fix Constraints:**
${finding.fix_constraints.map((c, i) => `${i + 1}. ${c}`).join('\n')}

**DO NOT:**
${finding.do_not.map(d => `- ${d}`).join('\n')}

**How to Verify:**
${finding.verify.map(v => `- ${v}`).join('\n')}

**Resources:**
${finding.resources.map(r => `- ${r}`).join('\n')}
`;

    return context;
  }

  /**
   * Clean up running processes
   */
  dispose(): void {
    for (const [key, proc] of this.runningProcesses) {
      try {
        proc.kill();
      } catch {
        // Process already terminated
      }
      this.runningProcesses.delete(key);
    }
  }

  /**
   * Run PyNEAT CLI command
   */
  private async runPyneat(args: string[], timeout: number = 30000): Promise<string | null> {
    return new Promise((resolve) => {
      const proc = spawn(this.pythonPath, args, {
        cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
        env: { ...process.env, PYTHONIOENCODING: 'utf-8' }
      });

      const processId = `${Date.now()}-${Math.random()}`;
      this.runningProcesses.set(processId, proc);

      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      const timer = setTimeout(() => {
        proc.kill();
        vscode.window.showWarningMessage('PyNEAT: Scan timed out');
        resolve(null);
      }, timeout);

      proc.on('close', (code) => {
        clearTimeout(timer);
        this.runningProcesses.delete(processId);

        if (code === 0 || stdout) {
          resolve(stdout || stderr);
        } else {
          if (stderr) {
            vscode.window.showWarningMessage(`PyNEAT: ${stderr.slice(0, 200)}`);
          }
          resolve(null);
        }
      });

      proc.on('error', (err) => {
        clearTimeout(timer);
        this.runningProcesses.delete(processId);
        vscode.window.showErrorMessage(`PyNEAT: Failed to run - ${err.message}`);
        resolve(null);
      });
    });
  }
}

/**
 * Get instance of PyneatWrapper (singleton)
 */
let wrapperInstance: PyneatWrapper | null = null;

export function getPyneatWrapper(context: vscode.ExtensionContext): PyneatWrapper {
  if (!wrapperInstance) {
    wrapperInstance = new PyneatWrapper(context);
  }
  return wrapperInstance;
}