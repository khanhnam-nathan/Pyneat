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
exports.PyneatWrapper = void 0;
exports.getPyneatWrapper = getPyneatWrapper;
/**
 * PyNEAT CLI Wrapper
 * Handles communication between VS Code extension and PyNEAT Python CLI
 */
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const child_process_1 = require("child_process");
class PyneatWrapper {
    pythonPath;
    config;
    runningProcesses = new Map();
    constructor(_context) {
        const resourceUri = vscode.workspace.workspaceFolders?.[0]?.uri ?? null;
        this.config = vscode.workspace.getConfiguration('pyneat', resourceUri);
        this.pythonPath = this.config.get('pythonPath', 'python');
    }
    /**
     * Run PyNEAT check and return parsed results
     */
    async checkFile(filePath) {
        const args = [
            '-m', 'pyneat.cli',
            'check', filePath,
            '--format', 'json',
            '--output', '-'
        ];
        const result = await this.runPyneat(args);
        if (!result) {
            return null;
        }
        try {
            return JSON.parse(result);
        }
        catch {
            vscode.window.showErrorMessage('PyNEAT: Failed to parse scan results');
            return null;
        }
    }
    /**
     * Run PyNEAT check on workspace
     */
    async checkWorkspace(dirPath) {
        const args = [
            '-m', 'pyneat.cli',
            'check', dirPath,
            '--format', 'json',
            '--output', '-'
        ];
        const result = await this.runPyneat(args);
        if (!result) {
            return null;
        }
        try {
            return JSON.parse(result);
        }
        catch {
            vscode.window.showErrorMessage('PyNEAT: Failed to parse scan results');
            return null;
        }
    }
    /**
     * Get a quick scan with dry-run (faster)
     */
    async quickScan(filePath) {
        const args = [
            '-m', 'pyneat.cli',
            'clean', filePath,
            '--dry-run',
            '--format', 'json'
        ];
        const result = await this.runPyneat(args);
        if (!result) {
            return [];
        }
        try {
            const parsed = JSON.parse(result);
            return parsed.findings || [];
        }
        catch {
            return [];
        }
    }
    /**
     * Apply auto-fix to file
     */
    async applyFix(filePath) {
        const args = [
            '-m', 'pyneat.cli',
            'check', filePath,
            '--apply',
            '--yes'
        ];
        const result = await this.runPyneat(args, 60000);
        return result !== null;
    }
    /**
     * Add context comment to file
     */
    async addContext(filePath, finding) {
        const content = fs.readFileSync(filePath, 'utf-8');
        const lines = content.split('\n');
        if (finding.start_line < 1 || finding.start_line > lines.length) {
            return false;
        }
        const comment = this.buildContextComment(finding);
        lines.splice(finding.start_line - 1, 0, comment);
        try {
            fs.writeFileSync(filePath, lines.join('\n'), 'utf-8');
            return true;
        }
        catch {
            return false;
        }
    }
    /**
     * Build context comment for a finding
     */
    buildContextComment(finding) {
        const fix = finding.fix_constraints[0] || 'See documentation';
        return `# [SEC-${finding.rule_id}] SECURITY WARNING
# Severity: ${finding.severity.toUpperCase()}
# Reason: ${finding.problem}
# Fix: ${fix}`;
    }
    /**
     * Check if PyNEAT is available
     */
    async isAvailable() {
        try {
            const result = await this.runPyneat(['--version']);
            return result !== null;
        }
        catch {
            return false;
        }
    }
    /**
     * Get PyNEAT version
     */
    async getVersion() {
        const result = await this.runPyneat(['--version']);
        return result?.trim() || null;
    }
    /**
     * Ignore an issue at specific location
     */
    async ignoreIssue(finding, reason) {
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspaceRoot) {
            vscode.window.showWarningMessage('No workspace folder open');
            return false;
        }
        const ignorePath = path.join(workspaceRoot, this.config.get('workspaceIgnore', '.pyneatignore'));
        const entry = `SEC-${finding.rule_id} ${finding.file}:${finding.start_line} # ${reason}\n`;
        try {
            if (fs.existsSync(ignorePath)) {
                const existing = fs.readFileSync(ignorePath, 'utf-8');
                fs.writeFileSync(ignorePath, existing + entry, 'utf-8');
            }
            else {
                fs.writeFileSync(ignorePath, entry, 'utf-8');
            }
            return true;
        }
        catch {
            vscode.window.showErrorMessage('PyNEAT: Failed to write ignore file');
            return false;
        }
    }
    /**
     * Format finding as AI agent context
     */
    formatAIGentContext(finding) {
        const context = `## PyNEAT Security Finding

**File:** \`${finding.file}\`
**Line:** ${finding.start_line}
**Rule:** SEC-${finding.rule_id}
**Severity:** ${finding.severity.toUpperCase()}
**CWE:** ${finding.cwe_id || 'N/A'}
**OWASP:** ${finding.owasp_id || 'N/A'}

**Code Snippet:**
\`\`\`
${finding.snippet}
\`\`\`

**Problem:** ${finding.problem}

**Fix Constraints:**
${finding.fix_constraints.map((c, i) => `${i + 1}. ${c}`).join('\n')}

**DO NOT:**
${finding.do_not.map(d => `- ${d}`).join('\n')}

**How to Verify:**
${finding.verify.map(v => `- ${v}`).join('\n')}

**Resources:**
${finding.resources.map(r => `- ${r}`).join('\n')}
`;
        return context;
    }
    /**
     * Clean up running processes
     */
    dispose() {
        for (const [key, proc] of this.runningProcesses) {
            try {
                proc.kill();
            }
            catch {
                // Process already terminated
            }
            this.runningProcesses.delete(key);
        }
    }
    /**
     * Run PyNEAT CLI command
     */
    async runPyneat(args, timeout = 30000) {
        return new Promise((resolve) => {
            const proc = (0, child_process_1.spawn)(this.pythonPath, args, {
                cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
                env: { ...process.env, PYTHONIOENCODING: 'utf-8' }
            });
            const processId = `${Date.now()}-${Math.random()}`;
            this.runningProcesses.set(processId, proc);
            let stdout = '';
            let stderr = '';
            proc.stdout?.on('data', (data) => {
                stdout += data.toString();
            });
            proc.stderr?.on('data', (data) => {
                stderr += data.toString();
            });
            const timer = setTimeout(() => {
                proc.kill();
                vscode.window.showWarningMessage('PyNEAT: Scan timed out');
                resolve(null);
            }, timeout);
            proc.on('close', (code) => {
                clearTimeout(timer);
                this.runningProcesses.delete(processId);
                if (code === 0 || stdout) {
                    resolve(stdout || stderr);
                }
                else {
                    if (stderr) {
                        vscode.window.showWarningMessage(`PyNEAT: ${stderr.slice(0, 200)}`);
                    }
                    resolve(null);
                }
            });
            proc.on('error', (err) => {
                clearTimeout(timer);
                this.runningProcesses.delete(processId);
                vscode.window.showErrorMessage(`PyNEAT: Failed to run - ${err.message}`);
                resolve(null);
            });
        });
    }
}
exports.PyneatWrapper = PyneatWrapper;
/**
 * Get instance of PyneatWrapper (singleton)
 */
let wrapperInstance = null;
function getPyneatWrapper(context) {
    if (!wrapperInstance) {
        wrapperInstance = new PyneatWrapper(context);
    }
    return wrapperInstance;
}
//# sourceMappingURL=pyneat-wrapper.js.map