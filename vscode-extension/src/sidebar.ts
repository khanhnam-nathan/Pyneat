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
 * PyNEAT Sidebar - Tree View for scan results
 */

import * as vscode from 'vscode';
import { PyneatWrapper } from './pyneat-wrapper';

export interface PyneatTreeItem {
  label: string;
  children?: PyneatTreeItem[];
  finding?: any;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  icon?: string;
  command?: vscode.Command;
}

export class PyneatSidebarProvider implements vscode.TreeDataProvider<PyneatTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<PyneatTreeItem | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private findings: Map<string, any[]> = new Map();
  private pyneat: PyneatWrapper;

  constructor(pyneat: PyneatWrapper) {
    this.pyneat = pyneat;
  }

  refresh(findings: Map<string, any[]>): void {
    this.findings = findings;
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: PyneatTreeItem): vscode.TreeItem {
    const item = new vscode.TreeItem(element.label);
    item.collapsibleState = element.children
      ? vscode.TreeItemCollapsibleState.Expanded
      : vscode.TreeItemCollapsibleState.None;

    // Set icon based on severity
    if (element.severity) {
      item.iconPath = this.getSeverityIcon(element.severity);
    } else if (element.icon) {
      item.iconPath = new vscode.ThemeIcon(element.icon);
    }

    if (element.command) {
      item.command = element.command;
    }

    // Set description for findings
    if (element.finding) {
      item.description = element.finding.severity?.toUpperCase();
      item.tooltip = this.buildTooltip(element.finding);
    }

    return item;
  }

  getChildren(element?: PyneatTreeItem): PyneatTreeItem[] {
    if (!element) {
      // Root level: group by file
      const files: PyneatTreeItem[] = [];
      for (const [filePath, fileFindings] of this.findings) {
        const fileName = filePath.split(/[/\\]/).pop() || filePath;
        const grouped = this.groupBySeverity(fileFindings);
        files.push({
          label: `${fileName} (${fileFindings.length})`,
          icon: 'file',
          children: grouped,
        });
      }
      return files.length > 0 ? files : [{
        label: 'No issues found',
        icon: 'check',
      }];
    }

    if (element.children) {
      return element.children;
    }

    return [];
  }

  private groupBySeverity(findings: any[]): PyneatTreeItem[] {
    const groups: Record<string, any[]> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: [],
    };

    for (const f of findings) {
      const sev = (f.severity || 'info').toLowerCase();
      if (groups[sev]) {
        groups[sev].push(f);
      } else {
        groups.info.push(f);
      }
    }

    const items: PyneatTreeItem[] = [];

    if (groups.critical.length) {
      items.push({
        label: `Critical (${groups.critical.length})`,
        severity: 'critical',
        icon: 'error',
        children: groups.critical.map(f => ({
          label: `[${f.rule_id}] ${f.problem || f.message || 'Unknown issue'}`,
          severity: 'critical',
          finding: f,
          command: {
            command: 'pyneat.goToFinding',
            title: 'Go to Finding',
            arguments: [f],
          },
        })),
      });
    }

    if (groups.high.length) {
      items.push({
        label: `High (${groups.high.length})`,
        severity: 'high',
        icon: 'warning',
        children: groups.high.map(f => ({
          label: `[${f.rule_id}] ${f.problem || f.message || 'Unknown issue'}`,
          severity: 'high',
          finding: f,
          command: {
            command: 'pyneat.goToFinding',
            title: 'Go to Finding',
            arguments: [f],
          },
        })),
      });
    }

    if (groups.medium.length) {
      items.push({
        label: `Medium (${groups.medium.length})`,
        severity: 'medium',
        icon: 'warning',
        children: groups.medium.map(f => ({
          label: `[${f.rule_id}] ${f.problem || f.message || 'Unknown issue'}`,
          severity: 'medium',
          finding: f,
          command: {
            command: 'pyneat.goToFinding',
            title: 'Go to Finding',
            arguments: [f],
          },
        })),
      });
    }

    if (groups.low.length) {
      items.push({
        label: `Low (${groups.low.length})`,
        severity: 'low',
        icon: 'info',
        children: groups.low.map(f => ({
          label: `[${f.rule_id}] ${f.problem || f.message || 'Unknown issue'}`,
          severity: 'low',
          finding: f,
        })),
      });
    }

    if (groups.info.length) {
      items.push({
        label: `Info (${groups.info.length})`,
        severity: 'info',
        icon: 'info',
        children: groups.info.map(f => ({
          label: `[${f.rule_id}] ${f.problem || f.message || 'Unknown issue'}`,
          severity: 'info',
          finding: f,
        })),
      });
    }

    return items;
  }

  private getSeverityIcon(severity: string): vscode.ThemeIcon {
    switch (severity) {
      case 'critical':
        return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
      case 'high':
        return new vscode.ThemeIcon('warning', new vscode.ThemeColor('errorForeground'));
      case 'medium':
        return new vscode.ThemeIcon('warning');
      case 'low':
        return new vscode.ThemeIcon('info');
      default:
        return new vscode.ThemeIcon('info');
    }
  }

  private buildTooltip(finding: any): string {
    const lines: string[] = [];
    lines.push(`[${finding.rule_id || 'UNKNOWN'}] ${finding.severity?.toUpperCase() || 'INFO'}`);
    lines.push('');
    lines.push(finding.problem || finding.message || 'No description');
    lines.push('');
    if (finding.cwe_id) {
      lines.push(`CWE: ${finding.cwe_id}`);
    }
    if (finding.fix_hint || finding.fix_constraints?.[0]) {
      lines.push(`Fix: ${finding.fix_hint || finding.fix_constraints[0]}`);
    }
    if (finding.line || finding.start_line) {
      lines.push(`Line: ${finding.line || finding.start_line}`);
    }
    return lines.join('\n');
  }
}

/**
 * Sidebar Webview Provider
 */
export class PyneatSidebarWebviewProvider {
  private webviewPanel: vscode.WebviewPanel | undefined;
  private findings: Map<string, any[]> = new Map();

  constructor(
    private context: vscode.ExtensionContext,
    private pyneat: PyneatWrapper,
  ) {}

  createOrShow(): void {
    if (this.webviewPanel) {
      this.webviewPanel.webview.html = this.getHtml();
      this.webviewPanel.reveal(vscode.ViewColumn.Three);
      return;
    }

    this.webviewPanel = vscode.window.createWebviewPanel(
      'pyneat.sidebar',
      'PyNEAT Security',
      vscode.ViewColumn.Three,
      {
        retainContextWhenHidden: true,
        enableFindWidget: true,
      }
    );

    this.webviewPanel.webview.html = this.getHtml();

    this.webviewPanel.onDidDispose(() => {
      this.webviewPanel = undefined;
    });
  }

  updateFindings(findings: Map<string, any[]>): void {
    this.findings = findings;
    if (this.webviewPanel) {
      this.webviewPanel.webview.html = this.getHtml();
    }
  }

  private getHtml(): string {
    const total = Array.from(this.findings.values()).reduce((sum, arr) => sum + arr.length, 0);
    const critical = this.countSeverity('critical');
    const high = this.countSeverity('high');
    const medium = this.countSeverity('medium');
    const low = this.countSeverity('low');

    const findingsHtml = this.renderFindings();

    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #1e1e1e; color: #d4d4d4; padding: 16px; }
    .header { margin-bottom: 16px; }
    .title { font-size: 16px; font-weight: 600; color: #569cd6; margin-bottom: 8px; }
    .summary { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
    .badge {
      padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: 500;
    }
    .badge.critical { background: #f14c4c33; color: #f14c4c; }
    .badge.high { background: #ce917833; color: #ce9178; }
    .badge.medium { background: #dcdcaa33; color: #dcdcaa; }
    .badge.low { background: #6a995533; color: #6a9955; }
    .badge.info { background: #80808033; color: #808080; }
    .badge.total { background: #569cd633; color: #569cd6; }

    .scan-btn {
      width: 100%; padding: 8px; background: #0e639c; color: white;
      border: none; border-radius: 4px; cursor: pointer; font-size: 13px;
      margin-bottom: 16px;
    }
    .scan-btn:hover { background: #1177bb; }

    .config-section { margin-bottom: 16px; padding: 12px; background: #2d2d2d; border-radius: 6px; }
    .config-title { font-size: 13px; font-weight: 600; margin-bottom: 8px; color: #9cdcfe; }
    .config-row { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-size: 12px; }
    .config-row label { flex: 1; }
    .config-row select, .config-row input { flex: 1; padding: 4px; background: #3c3c3c; color: #d4d4d4; border: 1px solid #555; border-radius: 4px; }

    .findings-list { max-height: 60vh; overflow-y: auto; }
    .finding-item {
      padding: 10px 12px; background: #2d2d2d; border-radius: 4px;
      margin-bottom: 6px; cursor: pointer; border-left: 3px solid #569cd6;
    }
    .finding-item:hover { background: #3c3c3c; }
    .finding-item.critical { border-left-color: #f14c4c; }
    .finding-item.high { border-left-color: #ce9178; }
    .finding-item.medium { border-left-color: #dcdcaa; }
    .finding-item.low { border-left-color: #6a9955; }

    .finding-rule { font-size: 11px; color: #569cd6; font-family: monospace; margin-bottom: 4px; }
    .finding-problem { font-size: 13px; color: #d4d4d4; margin-bottom: 6px; }
    .finding-meta { font-size: 11px; color: #808080; display: flex; gap: 12px; }
    .finding-meta span { display: flex; align-items: center; gap: 4px; }

    .empty-state { text-align: center; padding: 40px 20px; color: #6a9955; }
    .empty-state .icon { font-size: 48px; margin-bottom: 12px; }
    .empty-state .text { font-size: 14px; }

    .tabs { display: flex; border-bottom: 1px solid #3c3c3c; margin-bottom: 12px; }
    .tab { padding: 8px 16px; cursor: pointer; font-size: 13px; border-bottom: 2px solid transparent; }
    .tab.active { color: #569cd6; border-bottom-color: #569cd6; }
    .tab:hover { color: #9cdcfe; }
  </style>
</head>
<body>
  <div class="header">
    <div class="title">PyNEAT Security Scanner</div>
    <div class="summary">
      <span class="badge total">Total: ${total}</span>
      <span class="badge critical">${critical} Critical</span>
      <span class="badge high">${high} High</span>
      <span class="badge medium">${medium} Medium</span>
      <span class="badge low">${low} Low</span>
    </div>
    <button class="scan-btn" onclick="runScan()">Run Full Scan</button>
  </div>

  <div class="config-section">
    <div class="config-title">Configuration</div>
    <div class="config-row">
      <label>Severity:</label>
      <select id="severity-filter">
        <option value="info">All (info+)</option>
        <option value="low">Low+</option>
        <option value="medium">Medium+</option>
        <option value="high">High+</option>
        <option value="critical">Critical only</option>
      </select>
    </div>
    <div class="config-row">
      <label>Format:</label>
      <select id="format-select">
        <option value="text">Text</option>
        <option value="sarif">SARIF (CI/CD)</option>
        <option value="json">JSON</option>
        <option value="codeclimate">CodeClimate</option>
      </select>
    </div>
    <div class="config-row">
      <label>Auto-fix:</label>
      <input type="checkbox" id="auto-fix" />
    </div>
  </div>

  <div class="tabs">
    <div class="tab active" data-tab="findings">Findings</div>
    <div class="tab" data-tab="rules">Rules</div>
    <div class="tab" data-tab="ai">AI Security</div>
  </div>

  <div class="findings-list">
    ${findingsHtml}
  </div>

  <script>
    const vscode = acquireVsCodeApi();

    function runScan() {
      vscode.postMessage({ command: 'runScan' });
    }

    document.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        vscode.postMessage({ command: 'switchTab', tab: tab.dataset.tab });
      });
    });

    document.querySelectorAll('.finding-item').forEach(item => {
      item.addEventListener('click', () => {
        const finding = ${JSON.stringify(Array.from(this.findings.values()).flat())};
        const idx = parseInt(item.dataset.idx);
        vscode.postMessage({ command: 'goToFinding', finding: finding[idx] });
      });
    });
  </script>
</body>
</html>`;
  }

  private countSeverity(severity: string): number {
    let count = 0;
    for (const findings of this.findings.values()) {
      for (const f of findings) {
        if ((f.severity || 'info').toLowerCase() === severity) {
          count++;
        }
      }
    }
    return count;
  }

  private renderFindings(): string {
    const allFindings: any[] = Array.from(this.findings.values()).flat();

    if (allFindings.length === 0) {
      return `
        <div class="empty-state">
          <div class="icon">&#10003;</div>
          <div class="text">No security issues found</div>
        </div>`;
    }

    return allFindings.map((f, idx) => `
      <div class="finding-item ${f.severity || 'info'}" data-idx="${idx}">
        <div class="finding-rule">${f.rule_id || 'UNKNOWN'}</div>
        <div class="finding-problem">${f.problem || f.message || 'Unknown issue'}</div>
        <div class="finding-meta">
          <span class="badge ${f.severity || 'info'}">${(f.severity || 'info').toUpperCase()}</span>
          ${f.cwe_id ? `<span>CWE: ${f.cwe_id}</span>` : ''}
          ${f.line || f.start_line ? `<span>Line ${f.line || f.start_line}</span>` : ''}
        </div>
      </div>
    `).join('');
  }
}
