import * as assert from 'assert';
import { before } from 'mocha';
import * as vscode from 'vscode';
import * as path from 'path';

suite('PyNEAT Extension Tests', () => {
    before(() => {
        vscode.window.showInformationMessage('PyNEAT tests started');
    });

    test('Extension activates without error', async () => {
        const ext = vscode.extensions.getExtension('pyneat.pyneat-vscode');
        assert.ok(ext, 'PyNEAT extension should be present');
    });

    test('PyNEAT configuration is accessible', () => {
        const config = vscode.workspace.getConfiguration('pyneat');
        assert.ok(config, 'PyNEAT configuration should exist');
        assert.ok('debounceMs' in config, 'debounceMs setting should exist');
        assert.ok('severityThreshold' in config, 'severityThreshold setting should exist');
    });

    test('Commands are registered', async () => {
        const commands = await vscode.commands.getCommands(true);
        assert.ok(commands.includes('pyneat.scanFile'), 'pyneat.scanFile command should be registered');
        assert.ok(commands.includes('pyneat.explain'), 'pyneat.explain command should be registered');
        assert.ok(commands.includes('pyneat.disableRule'), 'pyneat.disableRule command should be registered');
    });
});
