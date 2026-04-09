"use strict";
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
const vscode = __importStar(require("vscode"));
let diagnosticCollection;
function activate(context) {
    console.log('PyNEAT extension activating...');
    // Create diagnostic collection
    diagnosticCollection = vscode.languages.createDiagnosticCollection('pyneat');
    context.subscriptions.push(diagnosticCollection);
    // Register commands
    registerCommands(context);
    // Register code lens provider
    registerCodeLens(context);
    // Auto-run on save if enabled
    registerOnSave(context);
    // Status bar
    createStatusBar(context);
    console.log('PyNEAT extension activated!');
}
function registerCommands(context) {
    // Clean command
    const cleanCmd = vscode.commands.registerCommand('pyneat.clean', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showInformationMessage('No active editor');
            return;
        }
        const doc = editor.document;
        if (doc.languageId !== 'python') {
            vscode.window.showInformationMessage('Not a Python file');
            return;
        }
        await runPyneat(['clean', doc.uri.fsPath], 'Cleaned');
    });
    // Check command
    const checkCmd = vscode.commands.registerCommand('pyneat.check', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor)
            return;
        await runPyneat(['check', editor.document.uri.fsPath], 'Checked');
    });
    // Security scan command
    const securityCmd = vscode.commands.registerCommand('pyneat.securityScan', async () => {
        const workspace = vscode.workspace.workspaceFolders;
        if (!workspace) {
            vscode.window.showInformationMessage('No workspace open');
            return;
        }
        await runPyneat(['check', workspace[0].uri.fsPath, '--verbose'], 'Security scan complete');
    });
    // Dry run command
    const dryRunCmd = vscode.commands.registerCommand('pyneat.dryRun', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor)
            return;
        await runPyneat(['clean', editor.document.uri.fsPath, '--dry-run', '--diff'], 'Dry run complete');
    });
    // List rules command
    const listRulesCmd = vscode.commands.registerCommand('pyneat.listRules', async () => {
        const terminal = vscode.window.createTerminal('PyNEAT Rules');
        terminal.sendText('python -m pyneat rules');
        terminal.show();
    });
    // Show report command
    const reportCmd = vscode.commands.registerCommand('pyneat.showReport', async () => {
        const workspace = vscode.workspace.workspaceFolders;
        if (!workspace)
            return;
        await runPyneat(['report', workspace[0].uri.fsPath], 'Report generated');
    });
    // Clean directory command
    const cleanDirCmd = vscode.commands.registerCommand('pyneat.cleanDir', async () => {
        const workspace = vscode.workspace.workspaceFolders;
        if (!workspace)
            return;
        const pick = await vscode.window.showQuickPick(['safe', 'conservative', 'destructive'], {
            placeHolder: 'Select cleaning package'
        });
        if (pick) {
            await runPyneat(['clean-dir', workspace[0].uri.fsPath, '--package', pick], 'Directory cleaned');
        }
    });
    context.subscriptions.push(cleanCmd, checkCmd, securityCmd, dryRunCmd, listRulesCmd, reportCmd, cleanDirCmd);
}
function registerCodeLens(context) {
    vscode.languages.registerCodeLensProvider('python', {
        provideCodeLenses(document) {
            const lenses = [];
            // Add code lens for security check
            const securityLens = new vscode.CodeLens(new vscode.Range(0, 0, 0, 0), {
                title: '🔒 PyNEAT Security Check',
                command: 'pyneat.check',
                arguments: [document.uri]
            });
            lenses.push(securityLens);
            // Add code lens for clean
            const cleanLens = new vscode.CodeLens(new vscode.Range(0, 0, 0, 0), {
                title: '✨ PyNEAT Clean',
                command: 'pyneat.clean',
                arguments: [document.uri]
            });
            lenses.push(cleanLens);
            return lenses;
        }
    });
}
function registerOnSave(context) {
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(async (doc) => {
        if (doc.languageId !== 'python')
            return;
        const config = vscode.workspace.getConfiguration('pyneat');
        if (config.get('formatOnSave') && config.get('enable')) {
            await runPyneat(['clean', doc.uri.fsPath, '--dry-run', '--diff'], '');
        }
    }));
}
function createStatusBar(context) {
    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBar.text = '$(check) PyNEAT';
    statusBar.tooltip = 'PyNEAT - AI Python Code Cleaner';
    statusBar.command = 'pyneat.check';
    context.subscriptions.push(statusBar);
    statusBar.show();
}
async function runPyneat(args, successMessage) {
    const config = vscode.workspace.getConfiguration('pyneat');
    const pyneatPath = config.get('path', 'python');
    const terminal = vscode.window.createTerminal('PyNEAT');
    const fullArgs = [pyneatPath, '-m', 'pyneat', ...args];
    terminal.sendText(fullArgs.join(' '));
    terminal.show();
    if (successMessage) {
        vscode.window.showInformationMessage(successMessage);
    }
}
function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.clear();
    }
}
//# sourceMappingURL=extension.js.map