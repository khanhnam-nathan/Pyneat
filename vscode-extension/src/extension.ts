import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';

let diagnosticCollection: vscode.DiagnosticCollection | undefined;

export function activate(context: vscode.ExtensionContext) {
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

function registerCommands(context: vscode.ExtensionContext) {
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
        if (!editor) return;
        
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
        if (!editor) return;

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
        if (!workspace) return;

        await runPyneat(['report', workspace[0].uri.fsPath], 'Report generated');
    });

    // Clean directory command
    const cleanDirCmd = vscode.commands.registerCommand('pyneat.cleanDir', async () => {
        const workspace = vscode.workspace.workspaceFolders;
        if (!workspace) return;

        const pick = await vscode.window.showQuickPick(['safe', 'conservative', 'destructive'], {
            placeHolder: 'Select cleaning package'
        });

        if (pick) {
            await runPyneat(['clean-dir', workspace[0].uri.fsPath, '--package', pick], 'Directory cleaned');
        }
    });

    context.subscriptions.push(cleanCmd, checkCmd, securityCmd, dryRunCmd, listRulesCmd, reportCmd, cleanDirCmd);
}

function registerCodeLens(context: vscode.ExtensionContext) {
    vscode.languages.registerCodeLensProvider('python', {
        provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
            const lenses: vscode.CodeLens[] = [];
            
            // Add code lens for security check
            const securityLens = new vscode.CodeLens(
                new vscode.Range(0, 0, 0, 0),
                {
                    title: '🔒 PyNEAT Security Check',
                    command: 'pyneat.check',
                    arguments: [document.uri]
                }
            );
            lenses.push(securityLens);

            // Add code lens for clean
            const cleanLens = new vscode.CodeLens(
                new vscode.Range(0, 0, 0, 0),
                {
                    title: '✨ PyNEAT Clean',
                    command: 'pyneat.clean',
                    arguments: [document.uri]
                }
            );
            lenses.push(cleanLens);

            return lenses;
        }
    });
}

function registerOnSave(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (doc) => {
            if (doc.languageId !== 'python') return;

            const config = vscode.workspace.getConfiguration('pyneat');
            if (config.get<boolean>('formatOnSave') && config.get<boolean>('enable')) {
                await runPyneat(['clean', doc.uri.fsPath, '--dry-run', '--diff'], '');
            }
        })
    );
}

function createStatusBar(context: vscode.ExtensionContext) {
    const statusBar = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        100
    );
    statusBar.text = '$(check) PyNEAT';
    statusBar.tooltip = 'PyNEAT - AI Python Code Cleaner';
    statusBar.command = 'pyneat.check';
    context.subscriptions.push(statusBar);
    statusBar.show();
}

async function runPyneat(args: string[], successMessage: string): Promise<void> {
    const config = vscode.workspace.getConfiguration('pyneat');
    const pyneatPath = config.get<string>('path', 'python');

    const terminal = vscode.window.createTerminal('PyNEAT');
    
    const fullArgs = [pyneatPath, '-m', 'pyneat', ...args];
    terminal.sendText(fullArgs.join(' '));
    terminal.show();

    if (successMessage) {
        vscode.window.showInformationMessage(successMessage);
    }
}

export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.clear();
    }
}
