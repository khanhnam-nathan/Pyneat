# PyNEAT LSP (Language Server Protocol)

PyNEAT Language Server for real-time code analysis, diagnostics, and auto-fix.

## Features

- **Real-time Diagnostics** - Detect issues as you type
- **Code Actions** - Quick fixes for detected issues
- **Hover Information** - Hover to view rule details
- **Formatting** - Format code with PyNEAT rules
- **Workspace Symbols** - Search symbols in workspace

## Installation

### VS Code

```bash
pip install pyneat-cli[server]
```

In `settings.json`:

```json
{
    "python.languageServer": "None",
    "pylance.enabled": false
}
```

Install the PyNEAT VS Code Extension and enable LSP:

```json
{
    "pyneat.enableLsp": true
}
```

### Neovim (nvim-lspconfig)

```lua
-- init.lua
local lspconfig = require('lspconfig')

lspconfig.pyneat.setup({
    cmd = {'python', '-m', 'pyneat.lsp'},
    filetypes = {'python'},
    settings = {
        pyneat = {
            enable = true,
            package = "safe"
        }
    }
})
```

### Neovim (vim-lsp)

```vim
" init.vim
function! PyneatSetup()
    lsp#start_server({
        \ 'name': 'pyneat',
        \ 'cmd': {server_info->['python', '-m', 'pyneat.lsp']},
        \ 'root_uri': {server_info->lsp#utils#path_to_uri(lsp#utils#find_git_roots(lsp#utils#get_buffer_path()))},
        \ 'whitelist': ['python'],
        \ })
endfunction

autocmd FileType python call PyneatSetup()
```

### Helix

```toml
# config.toml
[[language]]
name = "python"
language-servers = ["pyneat"]
```

```toml
[language-server.pyneat]
command = "python"
args = ["-m", "pyneat.lsp"]
```

### Emacs (eglot)

```elisp
(require 'eglot)

(add-to-list 'eglot-server-programs
             '(python-mode . ("python" "-m" "pyneat.lsp")))

(add-hook 'python-mode-hook 'eglot-ensure)
```

### Zed

```json
// settings.json
{
  "languages": {
    "Python": {
      "lsp": "pyneat"
    }
  }
}
```

## Usage

### Command Line

```bash
# Start LSP server
python -m pyneat.lsp

# With options
python -m pyneat.lsp --port 8765

# Debug mode
python -m pyneat.lsp --debug
```

### Options

| Option | Default | Description |
|--------|---------|------------|
| `--port` | 8765 | TCP port |
| `--socket` | - | Unix socket path |
| `--debug` | false | Debug mode |

## Protocol Support

PyNEAT LSP supports:

| Feature | Status |
|---------|--------|
| textDocument/didOpen | ✅ |
| textDocument/didChange | ✅ |
| textDocument/codeAction | ✅ |
| textDocument/diagnostic | ✅ |
| textDocument/formatting | ✅ |
| textDocument/hover | ✅ |
| textDocument/symbols | ✅ |
| workspace/symbol | ✅ |

## Configuration

### Server Settings

```json
{
    "pyneat.lsp": {
        "enable": true,
        "package": "safe",
        "enableSecurity": false,
        "trace": "off"
    }
}
```

### Per-workspace Configuration

```json
{
    "pyneat.enable": true,
    "pyneat.package": "conservative",
    "pyneat.enableSecurityScan": true
}
```

## Troubleshooting

### LSP not starting

```bash
# Check if pyneat is installed
python -m pyneat --version

# Check if lsp module exists
python -c "import pyneat.lsp"
```

### Connection refused

```bash
# Start with debug mode
python -m pyneat.lsp --debug

# Check port
python -m pyneat.lsp --port 8765
```

### Performance issues

```json
{
    "pyneat.lsp": {
        "debounceMs": 500,
        "maxFileSize": 1048576
    }
}
```

## Architecture

```
┌─────────────────────────────────────────┐
│           Editor (VS Code, Neovim)     │
└─────────────────┬───────────────────────┘
                  │ JSON-RPC (stdin/stdout)
┌─────────────────┴───────────────────────┐
│           PyNEAT LSP Server            │
│  ┌─────────────────────────────────┐   │
│  │   Protocol Handler               │   │
│  └───────────────┬─────────────────┘   │
│  ┌───────────────┴─────────────────┐   │
│  │   Diagnostics Engine             │   │
│  └───────────────┬─────────────────┘   │
│  ┌───────────────┴─────────────────┐   │
│  │   PyNEAT Rule Engine            │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

## License

MIT License
