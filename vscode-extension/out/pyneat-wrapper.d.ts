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
 * PyNEAT CLI Wrapper
 * Handles communication between VS Code extension and PyNEAT Python CLI
 */
import * as vscode from 'vscode';
export interface PyneatFinding {
    rule_id: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    confidence: number;
    cwe_id: string;
    owasp_id: string;
    cvss_score: number;
    cvss_vector: string;
    file: string;
    start_line: number;
    end_line: number;
    snippet: string;
    problem: string;
    fix_constraints: string[];
    do_not: string[];
    verify: string[];
    resources: string[];
    can_auto_fix: boolean;
    auto_fix_available: boolean;
    auto_fix_before: string | null;
    auto_fix_after: string | null;
}
export interface PyneatScanResult {
    scan_version: string;
    timestamp: string;
    target: string;
    total_files: number;
    scan_duration_seconds: number;
    summary: Record<string, number>;
    findings: PyneatFinding[];
    dependency_findings?: PyneatDependencyFinding[];
}
export interface PyneatDependencyFinding {
    rule_id: string;
    severity: string;
    package: string;
    version: string;
    ecosystem: string;
    cve_id: string | null;
    ghsa_id: string | null;
    description: string;
    fixed_version: string | null;
    source: string;
    recommendation: string;
}
export interface PyneatIgnoreEntry {
    rule_id: string;
    file: string;
    line: number | null;
    reason: string;
}
export declare class PyneatWrapper {
    private pythonPath;
    private config;
    private runningProcesses;
    constructor(_context: vscode.ExtensionContext);
    /**
     * Run PyNEAT check and return parsed results
     */
    checkFile(filePath: string): Promise<PyneatScanResult | null>;
    /**
     * Run PyNEAT check on workspace
     */
    checkWorkspace(dirPath: string): Promise<PyneatScanResult | null>;
    /**
     * Get a quick scan with dry-run (faster)
     */
    quickScan(filePath: string): Promise<PyneatFinding[]>;
    /**
     * Apply auto-fix to file
     */
    applyFix(filePath: string): Promise<boolean>;
    /**
     * Add context comment to file
     */
    addContext(filePath: string, finding: PyneatFinding): Promise<boolean>;
    /**
     * Build context comment for a finding
     */
    buildContextComment(finding: PyneatFinding): string;
    /**
     * Check if PyNEAT is available
     */
    isAvailable(): Promise<boolean>;
    /**
     * Get PyNEAT version
     */
    getVersion(): Promise<string | null>;
    /**
     * Ignore an issue at specific location
     */
    ignoreIssue(finding: PyneatFinding, reason: string): Promise<boolean>;
    /**
     * Format finding as AI agent context
     */
    formatAIGentContext(finding: PyneatFinding): string;
    /**
     * Clean up running processes
     */
    dispose(): void;
    /**
     * Run PyNEAT CLI command
     */
    private runPyneat;
}
export declare function getPyneatWrapper(context: vscode.ExtensionContext): PyneatWrapper;
//# sourceMappingURL=pyneat-wrapper.d.ts.map