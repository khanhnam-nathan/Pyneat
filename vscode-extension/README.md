# PyNEAT VS Code Extension

Official PyNEAT extension for Visual Studio Code.

## Features

- **Security Scanning** - Detects 50+ vulnerabilities (SEC-001 ~ SEC-059)
- **Auto-fix** - Automatically fix code issues
- **Dry Run** - Preview changes
- **Code Lens** - Quick actions in code
- **Problem Matcher** - Integration with VS Code Problems panel

## Commands

| Command | Keyboard | Description |
|---------|----------|-------------|
| `PyNEAT: Clean Code` | `Ctrl+Shift+6` | Clean current file |
| `PyNEAT: Security Check` | `Ctrl+Shift+7` | Security scan |
| `PyNEAT: Clean Directory` | - | Clean all files |
| `PyNEAT: Dry Run` | - | Preview changes |
| `PyNEAT: List Rules` | - | Show rules list |
| `PyNEAT: Show Report` | - | Generate report |

## Installation

### From VSIX

```bash
code --install-extension pyneat-*.vsix
```

### Build from Source

```bash
cd vscode-extension
npm install
npm run compile
npm run vscode:prepublish
code --install-extension ./pyneat-*.vsix
```

### Publish to Marketplace

```bash
npm run compile
npx vsce package
npx vsce publish
```

## Configuration

```json
{
  "pyneat.enable": true,
  "pyneat.package": "safe",
  "pyneat.autoFix": false,
  "pyneat.formatOnSave": false,
  "pyneat.enableSecurityScan": true,
  "pyneat.showNotifications": true,
  "pyneat.debugMode": false
}
```

## Packages

| Package | Description |
|---------|-------------|
| `safe` | Default, will not break code |
| `conservative` | Additional cleanup rules |
| `destructive` | Aggressive rules |

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Shift+6` | Clean Code |
| `Ctrl+Shift+7` | Security Check |

## Context Menu

Right-click on a Python file to see PyNEAT options:

- PyNEAT: Clean Code
- PyNEAT: Security Check
- PyNEAT: Dry Run

## Problem Matcher

PyNEAT integrates with the VS Code Problems panel:

```json
{
  "pyneat.enable": true,
  "pyneat.showNotifications": true
}
```

## Troubleshooting

### "PyNEAT not found" error

```bash
pip install pyneat-cli
```

### Permission error

Check Python path in settings:

```json
{
  "pyneat.pythonPath": "/usr/bin/python"
}
```

## License

MIT License — see LICENSE file in root directory.
