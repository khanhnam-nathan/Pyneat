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
exports.inlineFixProviderMetadata = exports.InlineFixProvider = void 0;
/**
 * Inline Fix Provider
 * Provides code actions and quick fixes for PyNEAT findings
 */
const vscode = __importStar(require("vscode"));
class InlineFixProvider {
    context;
    pyneat;
    diagnosticProvider;
    findingMap = new Map();
    constructor(context, pyneat, diagnosticProvider) {
        this.context = context;
        this.pyneat = pyneat;
        this.diagnosticProvider = diagnosticProvider;
        this.registerCommands();
    }
    /**
     * Register command handlers
     */
    registerCommands() {
        const applyFixCmd = vscode.commands.registerCommand('pyneat.applyFix', async (uri) => {
            await this.applyFix(uri);
        });
        const sendContextCmd = vscode.commands.registerCommand('pyneat.sendContext', async (uri) => {
            await this.sendToAIAgent(uri);
        });
        const ignoreIssueCmd = vscode.commands.registerCommand('pyneat.ignoreIssue', async (uri) => {
            await this.ignoreIssue(uri);
        });
        const addContextCmd = vscode.commands.registerCommand('pyneat.addContext', async (uri) => {
            await this.addContextComment(uri);
        });
        this.context.subscriptions.push(applyFixCmd, sendContextCmd, ignoreIssueCmd, addContextCmd);
    }
    /**
     * Provide code actions (lightbulb suggestions)
     */
    provideCodeActions(document, range, context) {
        const actions = [];
        // Check if there are any diagnostics at this location
        const diagnostics = context.diagnostics.filter((d) => d.source === 'PyNEAT' && d.range.intersection(range));
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
    findingsFromDiagnostics(diagnostics, document) {
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
    storeFinding(uri, finding) {
        this.findingMap.set(uri.toString(), finding);
    }
    /**
     * Get finding for URI
     */
    getFinding(uri) {
        return this.findingMap.get(uri.toString());
    }
    /**
     * Clear finding for URI
     */
    clearFinding(uri) {
        this.findingMap.delete(uri.toString());
    }
    /**
     * Apply fix to file
     */
    async applyFix(uri) {
        const targetUri = uri || vscode.window.activeTextEditor?.document.uri;
        if (!targetUri) {
            vscode.window.showWarningMessage('No file to fix');
            return;
        }
        const result = await vscode.window.showInformationMessage('Apply PyNEAT auto-fix to this file?', { modal: true }, 'Yes', 'No');
        if (result !== 'Yes') {
            return;
        }
        const success = await this.pyneat.applyFix(targetUri.fsPath);
        if (success) {
            vscode.window.showInformationMessage('PyNEAT: Fix applied successfully');
            await vscode.commands.executeCommand('pyneat.checkFile', targetUri);
        }
        else {
            vscode.window.showErrorMessage('PyNEAT: Failed to apply fix');
        }
    }
    /**
     * Send finding context to AI agent
     */
    async sendToAIAgent(uri) {
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
        vscode.window.showInformationMessage('PyNEAT context copied to clipboard. Paste in Cursor/Cline for AI agent.', 'Open Cursor').then((action) => {
            if (action === 'Open Cursor') {
                vscode.env.openExternal(vscode.Uri.parse('https://cursor.com'));
            }
        });
    }
    /**
     * Ignore this issue
     */
    async ignoreIssue(uri) {
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
    async addContextComment(uri) {
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
        }
        else {
            vscode.window.showErrorMessage('PyNEAT: Failed to add context comment');
        }
    }
    /**
     * Provide hover information
     */
    provideHover(document, position, _token) {
        const config = vscode.workspace.getConfiguration('pyneat', document.uri);
        if (!config.get('showHoverInfo', true)) {
            return null;
        }
        const diagnostics = vscode.languages.getDiagnostics(document.uri);
        const matching = diagnostics.find((d) => d.source === 'PyNEAT' &&
            d.range.contains(position));
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
    dispose() {
        this.findingMap.clear();
    }
}
exports.InlineFixProvider = InlineFixProvider;
/**
 * Code action provider metadata
 */
exports.inlineFixProviderMetadata = {
    providedCodeActionKinds: [
        vscode.CodeActionKind.QuickFix,
        vscode.CodeActionKind.Refactor,
    ],
};
//# sourceMappingURL=inline-fix-provider.js.map