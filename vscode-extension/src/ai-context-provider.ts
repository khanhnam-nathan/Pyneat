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
 * AI Context Provider
 * Formats PyNEAT findings as AI agent context and manages AI integration
 */

import * as vscode from 'vscode';
import { PyneatWrapper } from './pyneat-wrapper';

export class AIContextProvider {
  constructor(_context: vscode.ExtensionContext, _pyneat: PyneatWrapper) {
    // Commands are registered in InlineFixProvider
  }

  /**
   * Generate full scan context for all files in workspace
   */
  async generateWorkspaceContext(): Promise<string> {
    const findings: Array<{
      file: string;
      line: number;
      rule: string;
      severity: string;
      problem: string;
    }> = [];

    for (const doc of vscode.workspace.textDocuments) {
      if (!['python', 'javascript', 'typescript'].includes(doc.languageId)) {
        continue;
      }

      const diagnostics = vscode.languages.getDiagnostics(doc.uri);
      for (const diag of diagnostics) {
        if (diag.source === 'PyNEAT') {
          findings.push({
            file: doc.fileName,
            line: diag.range.start.line + 1,
            rule: diag.code as string || 'unknown',
            severity: diag.severity === vscode.DiagnosticSeverity.Error ? 'high' :
                      diag.severity === vscode.DiagnosticSeverity.Warning ? 'medium' : 'low',
            problem: diag.message.split('\n')[0],
          });
        }
      }
    }

    const context = `## PyNEAT Workspace Security Report

**Total Issues Found:** ${findings.length}

**Files with Issues:**
${findings.length > 0 ? findings
  .map((f) => `- \`${f.file}\` (line ${f.line}): [${f.rule}] ${f.problem}`)
  .join('\n') : 'No issues found'}

**Summary by Severity:**
${this.summarizeBySeverity(findings)}

**Recommendation:**
Fix HIGH and CRITICAL issues first. Use 'pyneat applyFix' command or the AI agent context feature.
`;

    return context;
  }

  /**
   * Summarize findings by severity
   */
  private summarizeBySeverity(findings: Array<{ severity: string }>): string {
    const counts: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    }

    return Object.entries(counts)
      .filter(([, count]) => count > 0)
      .map(([sev, count]) => `- ${sev.toUpperCase()}: ${count}`)
      .join('\n');
  }

  /**
   * Dispose
   */
  dispose(): void {
    // Nothing to dispose
  }
}
