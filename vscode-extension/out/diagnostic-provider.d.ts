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
 * Diagnostic Provider
 * Creates and manages VS Code diagnostic markers from PyNEAT scan results
 */
import * as vscode from 'vscode';
import { PyneatFinding, PyneatWrapper } from './pyneat-wrapper';
export declare class DiagnosticProvider {
    private pyneat;
    private diagnosticCollection;
    private statusBarItem;
    private disposables;
    private debounceTimers;
    private findingsMap;
    constructor(_context: vscode.ExtensionContext, pyneat: PyneatWrapper);
    /**
     * Setup event handlers for file changes and saves
     */
    private setupEventHandlers;
    /**
     * Check if document should be scanned
     */
    private shouldScan;
    /**
     * Debounce scan requests
     */
    private debounceScan;
    /**
     * Scan a document and update diagnostics
     */
    scanDocument(doc: vscode.TextDocument): Promise<void>;
    /**
     * Update diagnostics for a URI
     */
    private updateDiagnostics;
    /**
     * Get findings for URI
     */
    getFindings(uri: vscode.Uri): PyneatFinding[];
    /**
     * Create a VS Code Diagnostic from PyNEAT finding
     */
    private createDiagnostic;
    /**
     * Map PyNEAT severity to VS Code DiagnosticSeverity
     */
    private mapSeverity;
    /**
     * Create range from finding
     */
    private createRange;
    /**
     * Build hover message
     */
    private buildHoverMessage;
    /**
     * Update VS Code context keys
     */
    private updateContextKeys;
    /**
     * Update status bar item
     */
    private updateStatus;
    /**
     * Clear all diagnostics
     */
    clearAll(): void;
    /**
     * Get diagnostics for a specific file
     */
    getDiagnostics(uri: vscode.Uri): vscode.Diagnostic[];
    /**
     * Scan all open documents
     */
    scanAllOpen(): Promise<void>;
    /**
     * Dispose resources
     */
    dispose(): void;
}
//# sourceMappingURL=diagnostic-provider.d.ts.map