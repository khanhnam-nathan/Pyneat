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
exports.DiagnosticProvider = void 0;
/**
 * Diagnostic Provider
 * Creates and manages VS Code diagnostic markers from PyNEAT scan results
 */
const vscode = __importStar(require("vscode"));
class DiagnosticProvider {
    pyneat;
    diagnosticCollection;
    statusBarItem;
    disposables = [];
    debounceTimers = new Map();
    findingsMap = new Map();
    constructor(_context, pyneat) {
        this.pyneat = pyneat;
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('pyneat');
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
        this.statusBarItem.text = '$(search) PyNEAT Ready';
        this.statusBarItem.command = 'pyneat.checkFile';
        this.setupEventHandlers();
    }
    /**
     * Setup event handlers for file changes and saves
     */
    setupEventHandlers() {
        // On document open
        const openHandler = vscode.workspace.onDidOpenTextDocument((doc) => {
            if (this.shouldScan(doc)) {
                this.scanDocument(doc);
            }
        });
        this.disposables.push(openHandler);
        // On document change (real-time)
        const changeHandler = vscode.workspace.onDidChangeTextDocument((event) => {
            const resourceUri = event.document.uri;
            const config = vscode.workspace.getConfiguration('pyneat', resourceUri);
            if (config.get('enableRealTime', true)) {
                this.debounceScan(event.document, 1000);
            }
        });
        this.disposables.push(changeHandler);
        // On document save
        const saveHandler = vscode.workspace.onDidSaveTextDocument((doc) => {
            const resourceUri = doc.uri;
            const config = vscode.workspace.getConfiguration('pyneat', resourceUri);
            if (config.get('scanOnSave', true)) {
                this.scanDocument(doc);
            }
        });
        this.disposables.push(saveHandler);
        // On document close - clear diagnostics
        const closeHandler = vscode.workspace.onDidCloseTextDocument((doc) => {
            this.diagnosticCollection.delete(doc.uri);
        });
        this.disposables.push(closeHandler);
    }
    /**
     * Check if document should be scanned
     */
    shouldScan(doc) {
        return ['python', 'javascript', 'typescript'].includes(doc.languageId);
    }
    /**
     * Debounce scan requests
     */
    debounceScan(doc, delay) {
        const existing = this.debounceTimers.get(doc.uri.toString());
        if (existing) {
            clearTimeout(existing);
        }
        const timer = setTimeout(() => {
            this.scanDocument(doc);
            this.debounceTimers.delete(doc.uri.toString());
        }, delay);
        this.debounceTimers.set(doc.uri.toString(), timer);
    }
    /**
     * Scan a document and update diagnostics
     */
    async scanDocument(doc) {
        const startTime = Date.now();
        this.updateStatus('scanning', doc.fileName);
        try {
            const result = await this.pyneat.checkFile(doc.fileName);
            if (result && result.findings) {
                this.updateDiagnostics(doc.uri, result.findings, doc);
                this.updateStatus('ready', `${result.findings.length} issue(s) found`);
            }
            else {
                this.diagnosticCollection.delete(doc.uri);
                this.updateStatus('ready', 'No issues found');
            }
        }
        catch (error) {
            const duration = Date.now() - startTime;
            this.updateStatus('error', `Scan failed (${duration}ms)`);
        }
    }
    /**
     * Update diagnostics for a URI
     */
    updateDiagnostics(uri, findings, doc) {
        const config = vscode.workspace.getConfiguration('pyneat', uri);
        const threshold = config.get('severityThreshold', 'info');
        const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
        const thresholdIndex = severityOrder.indexOf(threshold);
        const diagnostics = findings
            .filter((finding) => {
            const findingIndex = severityOrder.indexOf(finding.severity);
            return findingIndex <= thresholdIndex;
        })
            .map((finding) => this.createDiagnostic(finding, doc));
        this.diagnosticCollection.set(uri, diagnostics);
        this.findingsMap.set(uri.toString(), findings);
        // Update context keys for keybindings
        this.updateContextKeys(diagnostics.length);
    }
    /**
     * Get findings for URI
     */
    getFindings(uri) {
        return this.findingsMap.get(uri.toString()) || [];
    }
    /**
     * Create a VS Code Diagnostic from PyNEAT finding
     */
    createDiagnostic(finding, doc) {
        const severity = this.mapSeverity(finding.severity);
        const range = this.createRange(finding, doc);
        const diagnostic = new vscode.Diagnostic(range, finding.problem, severity);
        // Set source and code
        diagnostic.source = 'PyNEAT';
        diagnostic.code = `SEC-${finding.rule_id}`;
        // Set tags based on auto-fix availability
        if (finding.auto_fix_available) {
            diagnostic.tags = [vscode.DiagnosticTag.Unnecessary];
        }
        // Add related information
        diagnostic.relatedInformation = [
            new vscode.DiagnosticRelatedInformation(new vscode.Location(doc.uri, new vscode.Range(finding.start_line - 1, 0, finding.start_line - 1, 0)), `Severity: ${finding.severity.toUpperCase()} | CWE: ${finding.cwe_id || 'N/A'}`),
            new vscode.DiagnosticRelatedInformation(new vscode.Location(doc.uri, new vscode.Range(finding.start_line - 1, 0, finding.start_line - 1, 0)), `Fix: ${finding.fix_constraints[0] || 'See documentation'}`)
        ];
        // Set hover message
        diagnostic.message = this.buildHoverMessage(finding);
        return diagnostic;
    }
    /**
     * Map PyNEAT severity to VS Code DiagnosticSeverity
     */
    mapSeverity(severity) {
        switch (severity) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
            case 'info':
            default:
                return vscode.DiagnosticSeverity.Information;
        }
    }
    /**
     * Create range from finding
     */
    createRange(finding, doc) {
        const startLine = Math.max(0, finding.start_line - 1);
        const endLine = Math.max(startLine, (finding.end_line || finding.start_line) - 1);
        try {
            const startPos = doc.lineAt(startLine).range.start;
            const endPos = doc.lineAt(Math.min(endLine, doc.lineCount - 1)).range.end;
            return new vscode.Range(startPos, endPos);
        }
        catch {
            return new vscode.Range(0, 0, 0, 0);
        }
    }
    /**
     * Build hover message
     */
    buildHoverMessage(finding) {
        const lines = [];
        lines.push(`$(warning) **[SEC-${finding.rule_id}]** ${finding.severity.toUpperCase()}`);
        lines.push('');
        lines.push(`**Problem:** ${finding.problem}`);
        lines.push('');
        if (finding.fix_constraints.length > 0) {
            lines.push('**Fix:**');
            finding.fix_constraints.forEach((c) => {
                lines.push(`- ${c}`);
            });
            lines.push('');
        }
        if (finding.do_not.length > 0) {
            lines.push('**DO NOT:**');
            finding.do_not.forEach((d) => {
                lines.push(`- ~~${d}~~`);
            });
            lines.push('');
        }
        lines.push('---');
        lines.push(`[A] Auto-fix | [B] Send to AI Agent | [C] Ignore`);
        return lines.join('\n');
    }
    /**
     * Update VS Code context keys
     */
    updateContextKeys(issueCount) {
        vscode.commands.executeCommand('setContext', 'pyneat:hasIssues', issueCount > 0);
        vscode.commands.executeCommand('setContext', 'pyneat:issueCount', issueCount);
    }
    /**
     * Update status bar item
     */
    updateStatus(state, message) {
        switch (state) {
            case 'scanning':
                this.statusBarItem.text = `$(sync~spin) PyNEAT Scanning...`;
                break;
            case 'error':
                this.statusBarItem.text = `$(error) PyNEAT ${message}`;
                this.statusBarItem.color = '#f14c4c';
                break;
            default:
                this.statusBarItem.text = `$(check) PyNEAT ${message}`;
                this.statusBarItem.color = undefined;
        }
        this.statusBarItem.show();
    }
    /**
     * Clear all diagnostics
     */
    clearAll() {
        this.diagnosticCollection.clear();
        this.updateContextKeys(0);
    }
    /**
     * Get diagnostics for a specific file
     */
    getDiagnostics(uri) {
        return [...(this.diagnosticCollection.get(uri) || [])];
    }
    /**
     * Scan all open documents
     */
    async scanAllOpen() {
        for (const doc of vscode.workspace.textDocuments) {
            if (this.shouldScan(doc)) {
                await this.scanDocument(doc);
            }
        }
    }
    /**
     * Dispose resources
     */
    dispose() {
        for (const timer of this.debounceTimers.values()) {
            clearTimeout(timer);
        }
        this.debounceTimers.clear();
        this.diagnosticCollection.dispose();
        this.statusBarItem.dispose();
        for (const disp of this.disposables) {
            disp.dispose();
        }
    }
}
exports.DiagnosticProvider = DiagnosticProvider;
//# sourceMappingURL=diagnostic-provider.js.map