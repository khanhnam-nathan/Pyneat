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
exports.AIContextProvider = void 0;
/**
 * AI Context Provider
 * Formats PyNEAT findings as AI agent context and manages AI integration
 */
const vscode = __importStar(require("vscode"));
class AIContextProvider {
    constructor(_context, _pyneat) {
        // Commands are registered in InlineFixProvider
    }
    /**
     * Generate full scan context for all files in workspace
     */
    async generateWorkspaceContext() {
        const findings = [];
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
                        rule: diag.code || 'unknown',
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
    summarizeBySeverity(findings) {
        const counts = {
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
    dispose() {
        // Nothing to dispose
    }
}
exports.AIContextProvider = AIContextProvider;
//# sourceMappingURL=ai-context-provider.js.map