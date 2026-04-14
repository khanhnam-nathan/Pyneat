"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
/**
 * PyNEAT Extension for VS Code
 * Main entry point - activates and deactivates the extension
 */
const vscode = __importStar(require("vscode"));
const pyneat_wrapper_1 = require("./pyneat-wrapper");
const diagnostic_provider_1 = require("./diagnostic-provider");
const inline_fix_provider_1 = require("./inline-fix-provider");
const ai_context_provider_1 = require("./ai-context-provider");
let diagnosticProvider;
let inlineFixProvider;
let aiContextProvider;
let pyneatWrapper;
let statusBarItem;
async function activate(context) {
    // Show activation message
    vscode.window.showInformationMessage('PyNEAT Security Scanner is starting...');
    // Initialize wrapper
    pyneatWrapper = (0, pyneat_wrapper_1.getPyneatWrapper)(context);
    // Check PyNEAT availability
    const isAvailable = await pyneatWrapper.isAvailable();
    if (!isAvailable) {
        const install = await vscode.window.showWarningMessage('PyNEAT is not installed or not found in PATH.\n' +
            'Install it with: pip install pyneat-cli', 'Open Settings', 'Dismiss');
        if (install === 'Open Settings') {
            vscode.commands.executeCommand('workbench.action.openSettings', 'pyneat.pythonPath');
        }
        return;
    }
    // Get PyNEAT version
    const version = await pyneatWrapper.getVersion();
    vscode.window.showInformationMessage(`PyNEAT v${version || 'unknown'} activated.`);
    // Initialize diagnostic provider
    diagnosticProvider = new diagnostic_provider_1.DiagnosticProvider(context, pyneatWrapper);
    // Initialize inline fix provider
    inlineFixProvider = new inline_fix_provider_1.InlineFixProvider(context, pyneatWrapper, diagnosticProvider);
    // Initialize AI context provider
    aiContextProvider = new ai_context_provider_1.AIContextProvider(context, pyneatWrapper);
    // Register code action provider
    context.subscriptions.push(vscode.languages.registerCodeActionsProvider([
        { scheme: 'file', language: 'python' },
        { scheme: 'file', language: 'javascript' },
        { scheme: 'file', language: 'typescript' },
    ], inlineFixProvider, inline_fix_provider_1.inlineFixProviderMetadata));
    // Register hover provider
    context.subscriptions.push(vscode.languages.registerHoverProvider([
        { scheme: 'file', language: 'python' },
        { scheme: 'file', language: 'javascript' },
        { scheme: 'file', language: 'typescript' },
    ], {
        provideHover: inlineFixProvider.provideHover.bind(inlineFixProvider),
    }));
    // Register check file command
    const checkFileCmd = vscode.commands.registerCommand('pyneat.checkFile', async (uri) => {
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
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'PyNEAT Scanning',
            cancellable: true,
        }, async (progress) => {
            progress.report({ message: 'Scanning workspace...' });
            if (diagnosticProvider) {
                await diagnosticProvider.scanAllOpen();
            }
            progress.report({ message: 'Scan complete' });
        });
        vscode.window.showInformationMessage('PyNEAT: Workspace scan complete');
    });
    context.subscriptions.push(checkFileCmd, checkWorkspaceCmd);
    // Scan open documents on activation
    await diagnosticProvider.scanAllOpen();
    // Register configuration change handler
    context.subscriptions.push(vscode.workspace.onDidChangeConfiguration((event) => {
        if (event.affectsConfiguration('pyneat')) {
            // Re-initialize with new settings
            if (diagnosticProvider) {
                diagnosticProvider.clearAll();
                diagnosticProvider.scanAllOpen();
            }
        }
    }));
}
/**
 * Deactivate extension
 */
function deactivate() {
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
//# sourceMappingURL=extension.js.map