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
 * Inline Fix Provider
 * Provides code actions and quick fixes for PyNEAT findings
 */

import * as vscode from 'vscode';
import { PyneatFinding, PyneatWrapper } from './pyneat-wrapper';
import { DiagnosticProvider } from './diagnostic-provider';

export class InlineFixProvider implements vscode.CodeActionProvider {
  private context: vscode.ExtensionContext;
  private pyneat: PyneatWrapper;
  private diagnosticProvider: DiagnosticProvider | undefined;
  private findingMap: Map<string, PyneatFinding> = new Map();

  constructor(
    context: vscode.ExtensionContext,
    pyneat: PyneatWrapper,
    diagnosticProvider?: DiagnosticProvider
  ) {
    this.context = context;
    this.pyneat = pyneat;
    this.diagnosticProvider = diagnosticProvider;
    this.registerCommands();
  }

  /**
   * Register command handlers
   */
  private registerCommands(): void {
    const applyFixCmd = vscode.commands.registerCommand('pyneat.applyFix', async (uri?: vscode.Uri) => {
      await this.applyFix(uri);
    });

    const sendContextCmd = vscode.commands.registerCommand('pyneat.sendContext', async (uri?: vscode.Uri) => {
      await this.sendToAIAgent(uri);
    });

    const ignoreIssueCmd = vscode.commands.registerCommand('pyneat.ignoreIssue', async (uri?: vscode.Uri) => {
      await this.ignoreIssue(uri);
    });

    const addContextCmd = vscode.commands.registerCommand('pyneat.addContext', async (uri?: vscode.Uri) => {
      await this.addContextComment(uri);
    });

    this.context.subscriptions.push(applyFixCmd, sendContextCmd, ignoreIssueCmd, addContextCmd);
  }

  /**
   * Provide code actions (lightbulb suggestions)
   */
  public provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.ProviderResult<vscode.CodeAction[]> {
    const actions: vscode.CodeAction[] = [];

    // Check if there are any diagnostics at this location
    const diagnostics = context.diagnostics.filter(
      (d) => d.source === 'PyNEAT' && d.range.intersection(range)
    );

    if (diagnostics.length === 0) {
      return actions;
    }

    const finding = this.findingsFromDiagnostics(diagnostics, document);
    if (!finding) {
      return actions;
    }

    // Action 1: Apply Auto-fix
    if (finding.auto_fix_available) {
      const applyFix = new vscode.CodeAction('PyNEAT: Apply Fix', vscode.CodeActionKind.QuickFix);
      applyFix.command = {
        command: 'pyneat.applyFix',
        title: 'Apply Fix',
        arguments: [document.uri],
      };
      applyFix.diagnostics = diagnostics;
      applyFix.kind = vscode.CodeActionKind.QuickFix;
      actions.push(applyFix);
    }

    // Action 2: Send to AI Agent
    const sendContext = new vscode.CodeAction('PyNEAT: Send to AI Agent', vscode.CodeActionKind.Refactor);
    sendContext.command = {
      command: 'pyneat.sendContext',
      title: 'Send to AI Agent',
      arguments: [document.uri],
    };
    sendContext.diagnostics = diagnostics;
    sendContext.kind = vscode.CodeActionKind.Refactor;
    actions.push(sendContext);

    // Action 3: Add Context Comment
    const addContext = new vscode.CodeAction('PyNEAT: Add Context Comment', vscode.CodeActionKind.Refactor);
    addContext.command = {
      command: 'pyneat.addContext',
      title: 'Add Context Comment',
      arguments: [document.uri],
    };
    addContext.diagnostics = diagnostics;
    addContext.kind = vscode.CodeActionKind.Refactor;
    actions.push(addContext);

    // Action 4: Ignore This Issue
    const ignore = new vscode.CodeAction('PyNEAT: Ignore This Issue', vscode.CodeActionKind.QuickFix);
    ignore.command = {
      command: 'pyneat.ignoreIssue',
      title: 'Ignore This Issue',
      arguments: [document.uri],
    };
    ignore.diagnostics = diagnostics;
    ignore.kind = vscode.CodeActionKind.QuickFix;
    actions.push(ignore);

    return actions;
  }

  /**
   * Extract finding from diagnostics
   */
  private findingsFromDiagnostics(diagnostics: vscode.Diagnostic[], document?: vscode.TextDocument): PyneatFinding | null {
    if (diagnostics.length === 0) {
      return null;
    }

    const diag = diagnostics[0];
    const uriKey = document?.uri.toString() || diag.range.start.line.toString();
    const stored = this.findingMap.get(uriKey);
    if (stored) {
      return stored;
    }

    if (this.diagnosticProvider && document) {
      const findings = this.diagnosticProvider.getFindings(document.uri);
      return findings[0] || null;
    }

    return null;
  }

  /**
   * Store finding for later retrieval
   */
  public storeFinding(uri: vscode.Uri, finding: PyneatFinding): void {
    this.findingMap.set(uri.toString(), finding);
  }

  /**
   * Get finding for URI
   */
  public getFinding(uri: vscode.Uri): PyneatFinding | undefined {
    return this.findingMap.get(uri.toString());
  }

  /**
   * Clear finding for URI
   */
  public clearFinding(uri: vscode.Uri): void {
    this.findingMap.delete(uri.toString());
  }

  /**
   * Apply fix to file
   */
  private async applyFix(uri?: vscode.Uri): Promise<void> {
    const targetUri = uri || vscode.window.activeTextEditor?.document.uri;
    if (!targetUri) {
      vscode.window.showWarningMessage('No file to fix');
      return;
    }

    const result = await vscode.window.showInformationMessage(
      'Apply PyNEAT auto-fix to this file?',
      { modal: true },
      'Yes',
      'No'
    );

    if (result !== 'Yes') {
      return;
    }

    const success = await this.pyneat.applyFix(targetUri.fsPath);
    if (success) {
      vscode.window.showInformationMessage('PyNEAT: Fix applied successfully');
      await vscode.commands.executeCommand('pyneat.checkFile', targetUri);
    } else {
      vscode.window.showErrorMessage('PyNEAT: Failed to apply fix');
    }
  }

  /**
   * Send finding context to AI agent
   */
  private async sendToAIAgent(uri?: vscode.Uri): Promise<void> {
    const targetUri = uri || vscode.window.activeTextEditor?.document.uri;
    if (!targetUri) {
      vscode.window.showWarningMessage('No file selected');
      return;
    }

    const finding = this.getFinding(targetUri);
    if (!finding) {
      vscode.window.showWarningMessage('No PyNEAT finding for this file');
      return;
    }

    const context = this.pyneat.formatAIGentContext(finding);

    // Copy to clipboard
    await vscode.env.clipboard.writeText(context);

    // Show notification
    vscode.window.showInformationMessage(
      'PyNEAT context copied to clipboard. Paste in Cursor/Cline for AI agent.',
      'Open Cursor'
    ).then((action) => {
      if (action === 'Open Cursor') {
        vscode.env.openExternal(vscode.Uri.parse('https://cursor.com'));
      }
    });
  }

  /**
   * Ignore this issue
   */
  private async ignoreIssue(uri?: vscode.Uri): Promise<void> {
    const targetUri = uri || vscode.window.activeTextEditor?.document.uri;
    if (!targetUri) {
      vscode.window.showWarningMessage('No file selected');
      return;
    }

    const finding = this.getFinding(targetUri);
    if (!finding) {
      vscode.window.showWarningMessage('No PyNEAT finding for this file');
      return;
    }

    const reason = await vscode.window.showInputBox({
      prompt: 'Reason for ignoring this issue (required)',
      placeHolder: 'e.g., already sanitized, intentional, false positive',
      validateInput: (value) => {
        return value.trim().length === 0 ? 'Reason is required' : null;
      },
    });

    if (!reason) {
      return;
    }

    const success = await this.pyneat.ignoreIssue(finding, reason);
    if (success) {
      vscode.window.showInformationMessage('PyNEAT: Issue ignored. Added to .pyneatignore');
      await vscode.commands.executeCommand('pyneat.checkFile', targetUri);
    }
  }

  /**
   * Add context comment
   */
  private async addContextComment(uri?: vscode.Uri): Promise<void> {
    const targetUri = uri || vscode.window.activeTextEditor?.document.uri;
    if (!targetUri) {
      vscode.window.showWarningMessage('No file selected');
      return;
    }

    const finding = this.getFinding(targetUri);
    if (!finding) {
      vscode.window.showWarningMessage('No PyNEAT finding for this file');
      return;
    }

    const success = await this.pyneat.addContext(targetUri.fsPath, finding);
    if (success) {
      vscode.window.showInformationMessage('PyNEAT: Context comment added');
      await vscode.commands.executeCommand('pyneat.checkFile', targetUri);
    } else {
      vscode.window.showErrorMessage('PyNEAT: Failed to add context comment');
    }
  }

  /**
   * Provide hover information
   */
  public provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
    _token: vscode.CancellationToken
  ): vscode.ProviderResult<vscode.Hover> {
    const config = vscode.workspace.getConfiguration('pyneat', document.uri);
    if (!config.get('showHoverInfo', true)) {
      return null;
    }

    const diagnostics = vscode.languages.getDiagnostics(document.uri);
    const matching = diagnostics.find(
      (d) =>
        d.source === 'PyNEAT' &&
        d.range.contains(position)
    );

    if (!matching) {
      return null;
    }

    const content = new vscode.MarkdownString();
    content.appendMarkdown(matching.message);

    return new vscode.Hover(content, matching.range);
  }

  /**
   * Dispose
   */
  dispose(): void {
    this.findingMap.clear();
  }
}

/**
 * Code action provider metadata
 */
export const inlineFixProviderMetadata: vscode.CodeActionProviderMetadata = {
  providedCodeActionKinds: [
    vscode.CodeActionKind.QuickFix,
    vscode.CodeActionKind.Refactor,
  ],
};