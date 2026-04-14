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
 * PyNEAT Extension for VS Code - Enhanced LSP Client
 * Integrates with pyneat-rs LSP server for real-time diagnostics
 */

import * as vscode from 'vscode';
import * as net from 'net';
import { PyneatWrapper } from './pyneat-wrapper';

interface LSPMessage {
  jsonrpc: string;
  id?: number | string;
  method?: string;
  params?: any;
}

/**
 * Minimal LSP client implementation for pyneat-rs
 */
export class PyneatLSPClient {
  private socket: net.Socket | undefined;
  private process: vscode.ProcessExecution | undefined;
  private outputChannel: vscode.OutputChannel;
  private documentSync: vscode.TextDocumentChangeConnection | undefined;
  private connection: vscode.StreamConnection | undefined;
  private messageId = 0;
  private pendingRequests = new Map<number, { resolve: (v: any) => void; reject: (e: any) => void }>();
  private initialized = false;

  constructor(
    private context: vscode.ExtensionContext,
    private pyneat: PyneatWrapper,
  ) {
    this.outputChannel = vscode.window.createOutputChannel('PyNEAT LSP');
  }

  async connect(port: number = 4444): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket = new net.Socket();

      this.socket.connect(port, '127.0.0.1', () => {
        this.outputChannel.appendLine(`Connected to PyNEAT LSP on port ${port}`);
        this.initialized = true;
        this.startReading();
        resolve();
      });

      this.socket.on('error', (err) => {
        this.outputChannel.appendLine(`LSP connection error: ${err.message}`);
        this.outputChannel.appendLine('Falling back to CLI mode...');
        reject(err);
      });

      this.socket.on('close', () => {
        this.outputChannel.appendLine('LSP connection closed');
        this.initialized = false;
      });
    });
  }

  private startReading(): void {
    let buffer = '';

    this.socket?.on('data', (data: Buffer) => {
      buffer += data.toString();

      // Process complete JSON-RPC messages
      let newlineIdx: number;
      while ((newlineIdx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.substring(0, newlineIdx);
        buffer = buffer.substring(newlineIdx + 1);

        if (line.trim()) {
          try {
            const msg: LSPMessage = JSON.parse(line);
            this.handleMessage(msg);
          } catch {
            this.outputChannel.appendLine(`Invalid LSP message: ${line.substring(0, 100)}`);
          }
        }
      }
    });
  }

  private handleMessage(msg: LSPMessage): void {
    if (msg.id !== undefined && this.pendingRequests.has(msg.id as number)) {
      const pending = this.pendingRequests.get(msg.id as number);
      this.pendingRequests.delete(msg.id as number);
      pending?.resolve(msg);
    }

    // Handle server-initiated notifications
    if (msg.method === 'textDocument/publishDiagnostics') {
      this.handlePublishDiagnostics(msg.params);
    }
  }

  private handlePublishDiagnostics(params: any): void {
    const { uri, diagnostics } = params;
    const doc = vscode.workspace.textDocuments.find(d => d.uri.toString() === uri);
    if (doc) {
      // Let the diagnostic provider handle this
      vscode.commands.executeCommand('pyneat.handleLSPDiagnostics', { uri, diagnostics });
    }
  }

  sendRequest(method: string, params: any): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.socket || !this.initialized) {
        reject(new Error('Not connected to LSP server'));
        return;
      }

      const id = this.messageId++;
      const msg: LSPMessage = {
        jsonrpc: '2.0',
        id,
        method,
        params,
      };

      this.pendingRequests.set(id, { resolve, reject });

      this.socket.write(JSON.stringify(msg) + '\n');

      // Timeout after 30 seconds
      setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`LSP request ${method} timed out`));
        }
      }, 30000);
    });
  }

  sendNotification(method: string, params: any): void {
    if (!this.socket || !this.initialized) {
      return;
    }

    const msg: LSPMessage = {
      jsonrpc: '2.0',
      method,
      params,
    };

    this.socket.write(JSON.stringify(msg) + '\n');
  }

  async initialize(): Promise<void> {
    const rootUri = vscode.workspace.workspaceFolders?.[0]?.uri.toString() || '';

    const result = await this.sendRequest('initialize', {
      processId: process.pid,
      rootUri,
      capabilities: {
        textDocument: {
          synchronization: {
            full: true,
          },
          hover: {},
          codeAction: {},
        },
        workspace: {
          applyEdit: true,
        },
      },
    });

    this.sendNotification('initialized', {});

    this.outputChannel.appendLine(`LSP initialized with capabilities: ${JSON.stringify(result.capabilities)}`);
  }

  textDocumentDidOpen(doc: vscode.TextDocument): void {
    this.sendNotification('textDocument/didOpen', {
      textDocument: {
        uri: doc.uri.toString(),
        languageId: doc.languageId,
        version: doc.version,
        text: doc.getText(),
      },
    });
  }

  textDocumentDidChange(doc: vscode.TextDocument): void {
    this.sendNotification('textDocument/didChange', {
      textDocument: {
        uri: doc.uri.toString(),
        version: doc.version,
      },
      contentChanges: [{
        range: {
          start: { line: 0, character: 0 },
          end: { line: doc.lineCount, character: 0 },
        },
        rangeLength: doc.getText().length,
        text: doc.getText(),
      }],
    });
  }

  textDocumentDidClose(doc: vscode.TextDocument): void {
    this.sendNotification('textDocument/didClose', {
      textDocument: { uri: doc.uri.toString() },
    });
  }

  async shutdown(): Promise<void> {
    await this.sendRequest('shutdown', {});
    this.sendNotification('exit', {});
    this.socket?.destroy();
    this.initialized = false;
  }

  dispose(): void {
    if (this.initialized) {
      this.shutdown().catch(() => {});
    }
    this.socket?.destroy();
    this.outputChannel.dispose();
  }
}

/**
 * LSP server manager - starts the pyneat-rs LSP server
 */
export class LSPServerManager {
  private serverProcess: vscode.Process | undefined;
  private port: number = 4444;

  constructor(
    private context: vscode.ExtensionContext,
    private pyneat: PyneatWrapper,
  ) {}

  async start(port: number = 4444): Promise<number> {
    this.port = port;

    // Try to start pyneat-rs server
    const pythonPath = vscode.workspace.getConfiguration('pyneat').get('pythonPath', 'python');
    const pyneatRsPath = vscode.workspace.getConfiguration('pyneat').get('pyneatRsPath', '');

    if (pyneatRsPath) {
      // Start native Rust binary
      const proc = await vscode.process.exec(
        `"${pyneatRsPath}" server --port ${port}`,
        { cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath }
      );

      proc.onExit((code) => {
        if (code !== 0) {
          vscode.window.showWarningMessage(
            `PyNEAT LSP server exited with code ${code}. Using CLI fallback.`
          );
        }
      });
    }

    return this.port;
  }

  stop(): void {
    this.serverProcess?.kill();
    this.serverProcess = undefined;
  }
}
