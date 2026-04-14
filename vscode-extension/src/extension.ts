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
 * PyNEAT Extension for VS Code
 * Main entry point - activates and deactivates the extension
 */

import * as vscode from 'vscode';
import { getPyneatWrapper, PyneatWrapper } from './pyneat-wrapper';
import { DiagnosticProvider } from './diagnostic-provider';
import { InlineFixProvider, inlineFixProviderMetadata } from './inline-fix-provider';
import { AIContextProvider } from './ai-context-provider';

let diagnosticProvider: DiagnosticProvider | undefined;
let inlineFixProvider: InlineFixProvider | undefined;
let aiContextProvider: AIContextProvider | undefined;
let pyneatWrapper: PyneatWrapper | undefined;
let statusBarItem: vscode.StatusBarItem | undefined;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  // Show activation message
  vscode.window.showInformationMessage('PyNEAT Security Scanner is starting...');

  // Initialize wrapper
  pyneatWrapper = getPyneatWrapper(context);

  // Check PyNEAT availability
  const isAvailable = await pyneatWrapper.isAvailable();
  if (!isAvailable) {
    const install = await vscode.window.showWarningMessage(
      'PyNEAT is not installed or not found in PATH.\n' +
      'Install it with: pip install pyneat-cli',
      'Open Settings',
      'Dismiss'
    );

    if (install === 'Open Settings') {
      vscode.commands.executeCommand('workbench.action.openSettings', 'pyneat.pythonPath');
    }
    return;
  }

  // Get PyNEAT version
  const version = await pyneatWrapper.getVersion();
  vscode.window.showInformationMessage(`PyNEAT v${version || 'unknown'} activated.`);

  // Initialize diagnostic provider
  diagnosticProvider = new DiagnosticProvider(context, pyneatWrapper);

  // Initialize inline fix provider
  inlineFixProvider = new InlineFixProvider(context, pyneatWrapper, diagnosticProvider);

  // Initialize AI context provider
  aiContextProvider = new AIContextProvider(context, pyneatWrapper);

  // Register code action provider
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      [
        { scheme: 'file', language: 'python' },
        { scheme: 'file', language: 'javascript' },
        { scheme: 'file', language: 'typescript' },
      ],
      inlineFixProvider,
      inlineFixProviderMetadata
    )
  );

  // Register hover provider
  context.subscriptions.push(
    vscode.languages.registerHoverProvider(
      [
        { scheme: 'file', language: 'python' },
        { scheme: 'file', language: 'javascript' },
        { scheme: 'file', language: 'typescript' },
      ],
      {
        provideHover: inlineFixProvider.provideHover.bind(inlineFixProvider),
      }
    )
  );

  // Register check file command
  const checkFileCmd = vscode.commands.registerCommand('pyneat.checkFile', async (uri?: vscode.Uri) => {
    const targetUri = uri || vscode.window.activeTextEditor?.document.uri;
    if (!targetUri) {
      vscode.window.showWarningMessage('No file to check');
      return;
    }

    if (diagnosticProvider) {
      const doc = await vscode.workspace.openTextDocument(targetUri);
      await diagnosticProvider.scanDocument(doc);
    }
  });

  // Register check workspace command
  const checkWorkspaceCmd = vscode.commands.registerCommand('pyneat.checkWorkspace', async () => {
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!workspaceRoot) {
      vscode.window.showWarningMessage('No workspace folder open');
      return;
    }

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'PyNEAT Scanning',
        cancellable: true,
      },
      async (progress) => {
        progress.report({ message: 'Scanning workspace...' });

        if (diagnosticProvider) {
          await diagnosticProvider.scanAllOpen();
        }

        progress.report({ message: 'Scan complete' });
      }
    );

    vscode.window.showInformationMessage('PyNEAT: Workspace scan complete');
  });

  context.subscriptions.push(checkFileCmd, checkWorkspaceCmd);

  // Scan open documents on activation
  await diagnosticProvider.scanAllOpen();

  // Register configuration change handler
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration('pyneat')) {
        // Re-initialize with new settings
        if (diagnosticProvider) {
          diagnosticProvider.clearAll();
          diagnosticProvider.scanAllOpen();
        }
      }
    })
  );
}

/**
 * Deactivate extension
 */
export function deactivate(): void {
  if (diagnosticProvider) {
    diagnosticProvider.dispose();
    diagnosticProvider = undefined;
  }

  if (inlineFixProvider) {
    inlineFixProvider.dispose();
    inlineFixProvider = undefined;
  }

  if (aiContextProvider) {
    aiContextProvider.dispose();
    aiContextProvider = undefined;
  }

  if (pyneatWrapper) {
    pyneatWrapper.dispose();
    pyneatWrapper = undefined;
  }

  if (statusBarItem) {
    statusBarItem.dispose();
    statusBarItem = undefined;
  }
}