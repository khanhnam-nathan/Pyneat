# PyNEAT VS Code Extension

Real-time AI-powered security scanner for VS Code using the PyNEAT Language Server Protocol (LSP) server.

## Features

- **Real-time diagnostics** - Security issues appear as you code with squiggly underlines
- **Multi-language support** - Python, JavaScript, TypeScript, Go, Java, Rust, Ruby, PHP, C#
- **200+ security rules** - OWASP Top 10, prompt injection, AI-specific risks, secrets, etc.
- **Hover tooltips** - Get rule explanations on hover
- **Quick-fix actions** - Add ignore comments directly from the editor
- **Debounced scanning** - Configurable delay to avoid performance impact
- **Severity filtering** - Focus on what matters (critical, high, medium, low, info)
- **Scan on save / scan on type** - Choose your preferred scanning mode

## Installation

### Prerequisites

**You must have `pyneat.exe` installed.** The extension requires the Rust binary from `pyneat-rs`.

#### Install pyneat-rs (once)

```bash
# Build from source
git clone https://github.com/khanhnam-nathan/Pyneat.git
cd Pyneat/pyneat-rs
cargo build --release

# Add to PATH (Windows)
copy target\release\pyneat.exe %USERPROFILE%\.cargo\bin\pyneat.exe

# Verify
pyneat --version
# pyneat-rs 3.1.0
```

### Install Extension

#### Option 1: From VSIX file (recommended for testing)

1. Open VS Code
2. Press `Ctrl+Shift+P` → type **"Extensions: Install from VSIX"**
3. Browse to `pyneat-vscode-1.0.1.vsix`
4. Click **Install**

#### Option 2: From Terminal

```bash
code --install-extension pyneat-vscode-1.0.1.vsix
```

#### Option 3: Development Mode

```bash
cd .vscode-extension
npm install
code .
# Press F5 to launch extension in debug mode
```

## Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `pyneat.binaryPath` | `string` | `""` | Path to pyneat binary (leave empty to auto-detect) |
| `pyneat.debounceMs` | `number` | `500` | Delay in ms before scanning after keystroke |
| `pyneat.severityThreshold` | `string` | `"medium"` | Minimum severity to show (critical/high/medium/low/info) |
| `pyneat.scanOnSave` | `boolean` | `true` | Scan automatically when file is saved |
| `pyneat.scanOnType` | `boolean` | `true` | Scan as you type (real-time) |
| `pyneat.enabledRules` | `array` | `[]` | Specific rule IDs to enable (empty = all rules) |

Example in `.vscode/settings.json`:

```json
{
  "pyneat.debounceMs": 500,
  "pyneat.severityThreshold": "medium",
  "pyneat.scanOnSave": true,
  "pyneat.scanOnType": true
}
```

## Commands

| Command | Description |
|---------|-------------|
| `PyNeat: Scan Active File` | Run a scan on the currently open file |
| `PyNeat: Explain Rule` | Show detailed explanation for a security rule |
| `PyNeat: Disable Rule for Line` | Add an ignore comment at the cursor |
| `PyNeat: Open Settings` | Open PyNeat extension settings |

Right-click context menu also provides "Explain Rule" and "Disable Rule" options.

## Troubleshooting

### "PyNEAT binary not found in PATH"

1. Make sure `pyneat.exe` is installed (see Prerequisites above)
2. Verify it works in terminal:

```bash
pyneat --version
# Should output: pyneat-rs 3.1.0

pyneat lsp --help
# Should show LSP options
```

3. If not in PATH, set the full path in settings:

```json
{
  "pyneat.binaryPath": "D:\\pyneat-final\\pyneat-rs\\target\\release\\pyneat.exe"
}
```

### "Server crashed 5 times"

- Check the **Output** panel (`View` → `Output` → select **PyNEAT** channel)
- Verify `pyneat.exe` supports the `lsp` subcommand: `pyneat.exe lsp --help`
- Make sure the binary is executable and in your PATH

### Extension not activating

- Press `Ctrl+Shift+P` → type "Developer: Reload Window"
- Check **Extensions** panel for any error messages
- Open the **PyNEAT** output channel for logs

## Requirements

- VS Code 1.75.0 or higher
- `pyneat.exe` (Rust binary from `pyneat-rs`) installed and in PATH

## Extension Architecture

```
.vscode-extension/
  src/
    extension.ts      # Main extension entry point (LanguageClient setup)
  out/
    extension.js      # Compiled JavaScript
  package.json        # Extension manifest
  tsconfig.json       # TypeScript configuration
```

The extension spawns `pyneat lsp` as a subprocess and communicates via the Language Server Protocol over stdio. The LSP server handles all security scanning and reports findings as diagnostics back to VS Code.

## Publishing

### VS Code Marketplace (requires publisher account)

```bash
cd .vscode-extension
npx vsce publish
```

Requires a Personal Access Token (PAT) from https://dev.azure.com.

### Open VSX Registry (free)

```bash
npx ovsx publish pyneat-vscode-1.0.1.vsix
```

---

**Support**: https://github.com/khanhnam-nathan/Pyneat
