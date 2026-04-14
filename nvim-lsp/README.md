# PyNEAT Neovim LSP Plugin

A Language Server Protocol (LSP) plugin for Neovim that provides real-time security scanning with PyNEAT.

## Features

- Real-time security diagnostics as you code
- Multi-language support (Python, JavaScript, TypeScript, Go, Java, Rust, C#, PHP, Ruby)
- Hover information with rule details
- Code actions for quick fixes
- Integration with telescope.nvim for finding security issues
- SARIF format output for CI/CD integration
- Severity filtering (critical, high, medium, low, info)
- Debounced scanning for performance

## Installation

### Using packer.nvim

```lua
use { 'pyneat/pyneat', opt = true, run = 'pip install pyneat-cli' }
```

### Using lazy.nvim

```lua
{
  'pyneat/pyneat',
  ft = { 'python', 'javascript', 'typescript' },
  config = function()
    require('pyneat_lsp').setup({
      python_path = 'python',
      severity_threshold = 'info',
      enable_real_time = true,
    })
  end,
}
```

### Manual Installation

1. Copy `nvim-lsp/pyneat_lsp.lua` to `~/.config/nvim/lua/pyneat_lsp.lua`
2. Add to your `init.lua` or `init.vim`:

```lua
lua << EOF
require('pyneat_lsp').setup({
  python_path = 'python',
  severity_threshold = 'info',
  enable_real_time = true,
})
EOF
```

## Configuration

```lua
lua << EOF
require('pyneat_lsp').setup({
  -- Path to Python interpreter
  python_path = 'python',

  -- Minimum severity to show (info, low, medium, high, critical)
  severity_threshold = 'info',

  -- Enable real-time scanning
  enable_real_time = true,

  -- Scan on file save
  scan_on_save = true,

  -- Debounce delay (ms)
  debounce_delay = 1000,

  -- Languages to scan
  languages = {
    'python', 'javascript', 'typescript',
    'go', 'java', 'rust', 'csharp', 'php', 'ruby',
  },

  -- LSP server configuration (optional)
  server = {
    cmd = { 'pyneat', 'server' },
    name = 'pyneat',
  },
})
EOF
```

## Commands

| Command | Description |
|---------|-------------|
| `:PyNEATScan [file]` | Scan a file for security issues |
| `:PyNEATWorkspace` | Scan entire workspace |
| `:PyNEATClear` | Clear diagnostics for current buffer |

## Keymaps

| Keymap | Description |
|--------|-------------|
| `K` | Hover (show rule details) |
| `<leader>fa` | Code actions |
| `[d` | Previous diagnostic |
| `]d` | Next diagnostic |

## Telescope Integration

For telescope.nvim users:

```lua
local telescope = require('telescope')
telescope.load_extension('pyneat')

-- Find files with security issues
vim.keymap.set('n', '<leader>tp', function()
  telescope.extensions.pyneat.find_files()
end)
```

## Performance Tips

1. Increase `debounce_delay` if scanning is too slow
2. Use `severity_threshold = 'medium'` to reduce noise
3. Disable `enable_real_time` for large files
4. Use pyneat-rs binary for faster native scanning

## Requirements

- Neovim 0.8+
- Python 3.10+
- pyneat-cli (`pip install pyneat-cli`)
- Optional: pyneat-rs binary for faster native scanning
- Optional: nvim-lspconfig for LSP server integration
- Optional: telescope.nvim for file finding
