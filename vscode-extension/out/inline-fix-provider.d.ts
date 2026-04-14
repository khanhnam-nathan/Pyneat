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
export declare class InlineFixProvider implements vscode.CodeActionProvider {
    private context;
    private pyneat;
    private diagnosticProvider;
    private findingMap;
    constructor(context: vscode.ExtensionContext, pyneat: PyneatWrapper, diagnosticProvider?: DiagnosticProvider);
    /**
     * Register command handlers
     */
    private registerCommands;
    /**
     * Provide code actions (lightbulb suggestions)
     */
    provideCodeActions(document: vscode.TextDocument, range: vscode.Range, context: vscode.CodeActionContext): vscode.ProviderResult<vscode.CodeAction[]>;
    /**
     * Extract finding from diagnostics
     */
    private findingsFromDiagnostics;
    /**
     * Store finding for later retrieval
     */
    storeFinding(uri: vscode.Uri, finding: PyneatFinding): void;
    /**
     * Get finding for URI
     */
    getFinding(uri: vscode.Uri): PyneatFinding | undefined;
    /**
     * Clear finding for URI
     */
    clearFinding(uri: vscode.Uri): void;
    /**
     * Apply fix to file
     */
    private applyFix;
    /**
     * Send finding context to AI agent
     */
    private sendToAIAgent;
    /**
     * Ignore this issue
     */
    private ignoreIssue;
    /**
     * Add context comment
     */
    private addContextComment;
    /**
     * Provide hover information
     */
    provideHover(document: vscode.TextDocument, position: vscode.Position, _token: vscode.CancellationToken): vscode.ProviderResult<vscode.Hover>;
    /**
     * Dispose
     */
    dispose(): void;
}
/**
 * Code action provider metadata
 */
export declare const inlineFixProviderMetadata: vscode.CodeActionProviderMetadata;
//# sourceMappingURL=inline-fix-provider.d.ts.map