import * as vscode from 'vscode';
import { LanguageClient, LanguageClientOptions, ServerOptions, TransportKind } from 'vscode-languageclient/node';

let client: LanguageClient | undefined;

function getPyneatBinary(): { path: string; found: boolean } {
    const configPath = vscode.workspace.getConfiguration('pyneat').get<string>('binaryPath', '');
    if (configPath && configPath.trim() !== '') {
        return { path: configPath, found: true };
    }

    const { homedir } = require('os');
    const { existsSync, accessSync, constants } = require('fs');
    const home = homedir();

    const candidates: string[] = [];

    if (process.platform === 'win32') {
        candidates.push(
            'pyneat.exe',
            'C:\\Users\\' + require('os').userInfo().username + '\\.cargo\\bin\\pyneat.exe',
            'D:\\pyneat-final\\pyneat-rs\\target\\release\\pyneat.exe',
            home + '\\.cargo\\bin\\pyneat.exe',
            home + '\\.cargo\\bin\\pyneat',
            'pyneat',
        );
    } else {
        candidates.push(
            home + '/.cargo/bin/pyneat',
            home + '/.cargo/bin/pyneat.exe',
            'pyneat',
        );
    }

    for (const candidate of candidates) {
        try {
            if (existsSync(candidate)) {
                accessSync(candidate, constants.X_OK);
                const { spawnSync } = require('child_process');
                const result = spawnSync(candidate, ['--version'], { timeout: 5000 });
                if (result.status === 0) {
                    return { path: candidate, found: true };
                }
            }
        } catch {
            // try next candidate
        }
    }

    return { path: 'pyneat', found: false };
}

function showErrorNotification(message: string, detail?: string): void {
    const options: vscode.MessageOptions = { modal: false };
    if (detail) {
        vscode.window.showErrorMessage(message, options).then(selection => {
            if (selection === 'View Output') {
                vscode.commands.executeCommand('workbench.action.output.toggleOutput');
            }
        });
    } else {
        vscode.window.showErrorMessage(message, options);
    }
}

export function activate(context: vscode.ExtensionContext) {
    const { path: pyneatBinary, found } = getPyneatBinary();
    const pyneatConfig = vscode.workspace.getConfiguration('pyneat');

    if (!found) {
        showErrorNotification(
            'PyNEAT binary not found in PATH.',
            `Please install pyneat-rs from: https://github.com/khanhnam-nathan/Pyneat\n\nOr set the path in VS Code settings: pyneat.binaryPath`
        );
        console.error('[PyNEAT] Binary not found. Candidates checked include: pyneat.exe, ~/.cargo/bin/pyneat.exe');
        return;
    }

    console.log(`[PyNEAT] Using binary: ${pyneatBinary}`);

    const outputChannel = vscode.window.createOutputChannel('PyNEAT');
    outputChannel.appendLine(`[PyNEAT] Starting with binary: ${pyneatBinary}`);

    const serverArgs = ['lsp'];
    const scanOnSave = pyneatConfig.get<boolean>('scanOnSave', true);
    const scanOnType = pyneatConfig.get<boolean>('scanOnType', true);
    const debounceMs = pyneatConfig.get<number>('debounceMs', 500);
    const severityThreshold = pyneatConfig.get<string>('severityThreshold', 'medium');
    const enabledRules = pyneatConfig.get<string[]>('enabledRules', []);

    if (scanOnSave) {
        serverArgs.push('--scan-on-save');
    }
    if (scanOnType) {
        serverArgs.push('--scan-on-type');
    }
    serverArgs.push(`--debounce-ms=${debounceMs}`);
    serverArgs.push(`--severity=${severityThreshold}`);

    if (enabledRules.length > 0) {
        serverArgs.push(`--rules=${enabledRules.join(',')}`);
    }

    const serverOptions: ServerOptions = {
        command: pyneatBinary,
        args: serverArgs,
        transport: TransportKind.stdio,
        options: {
            env: {
                ...process.env,
                PYNEAT_LSP: '1',
            },
        },
    };

    const clientOptions: LanguageClientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'python' },
            { scheme: 'file', language: 'javascript' },
            { scheme: 'file', language: 'typescript' },
            { scheme: 'file', language: 'go' },
            { scheme: 'file', language: 'java' },
            { scheme: 'file', language: 'rust' },
            { scheme: 'file', language: 'ruby' },
            { scheme: 'file', language: 'php' },
            { scheme: 'file', language: 'csharp' },
        ],
        diagnosticCollectionName: 'pyneat',
        outputChannel: outputChannel,
        revealOutputChannelOn: 2,
        initializationOptions: {
            debounceMs,
            severityThreshold,
            enabledRules,
            scanOnSave,
            scanOnType,
        },
        initializationFailedHandler: (error) => {
            outputChannel.appendLine(`[PyNEAT] Initialization failed: ${error.message}`);
            showErrorNotification(
                'PyNEAT server failed to initialize.',
                error.message
            );
            return false;
        },
    };

    client = new LanguageClient('pyneat', 'PyNEAT Security Scanner', serverOptions, clientOptions);

    client.start();

    // Wait for server to be ready
    const checkReady = setInterval(() => {
        try {
            outputChannel.appendLine('[PyNEAT] Checking server status...');
            clearInterval(checkReady);
        } catch {
            // not ready yet
        }
    }, 1000);

    setTimeout(() => clearInterval(checkReady), 30000);

    context.subscriptions.push(
        vscode.commands.registerCommand('pyneat.scanFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showInformationMessage('No active editor');
                return;
            }
            if (!client) {
                vscode.window.showWarningMessage('PyNEAT server is not ready yet. Please wait...');
                return;
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('pyneat.explain', async (args?: { ruleId?: string }) => {
            const ruleId = args?.ruleId ?? await vscode.window.showInputBox({
                prompt: 'Enter the rule ID to explain (e.g., SEC-001)',
                placeHolder: 'SEC-001',
            });

            if (!ruleId) { return; }

            const terminal = vscode.window.createTerminal('PyNEAT');
            terminal.sendText(`"${pyneatBinary}" explain ${ruleId}`);
            terminal.show();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('pyneat.disableRule', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) { return; }

            const diagnostics = vscode.languages.getDiagnostics(editor.document.uri)
                .filter(d => d.source === 'PyNEAT');

            if (diagnostics.length === 0) {
                vscode.window.showInformationMessage('No PyNEAT findings in this file');
                return;
            }

            const items = diagnostics.map(d => ({
                label: `${d.message.split('\n')[0]}`,
                detail: d.code ? `Rule: ${d.code}` : undefined,
                finding: d,
            }));

            const selected = await vscode.window.showQuickPick(items, {
                placeHolder: 'Select a finding to ignore',
            });

            if (!selected) { return; }

            const line = editor.selection.active.line;
            const comment = `# pyneat-ignore-next-line\n`;
            const edit = new vscode.WorkspaceEdit();
            edit.insert(editor.document.uri, new vscode.Position(line, 0), comment);
            await vscode.workspace.applyEdit(edit);
            vscode.window.showInformationMessage('Added ignore comment');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('pyneat.openSettings', async () => {
            vscode.commands.executeCommand('workbench.action.openSettings', '@id:pyneat');
        })
    );

    vscode.workspace.onDidChangeConfiguration(event => {
        if (event.affectsConfiguration('pyneat')) {
            const newConfig = vscode.workspace.getConfiguration('pyneat');
            const debounceMs = newConfig.get<number>('debounceMs', 500);
            const severityThreshold = newConfig.get<string>('severityThreshold', 'medium');
            const enabledRules = newConfig.get<string[]>('enabledRules', []);

            if (client) {
                client.sendNotification('workspace/didChangeConfiguration', {
                    settings: {
                        pyneat: {
                            debounceMs,
                            severityThreshold,
                            enabledRules,
                        },
                    },
                });
            }
        }
    });
}

export function deactivate(): void {
    if (client) {
        client.stop();
    }
}
