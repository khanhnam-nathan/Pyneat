# PyNEAT Vim/Neovim Plugin
#
# Installation:
#
# For Vim:
#   - Install vim-plug: https://github.com/junegunn/vim-plug
#   - Add to .vimrc:
#     Plug 'pyneat/pyneat-vim'
#
# For Neovim (Lua):
#   - Install packer.nvim or lazy.nvim
#   - Add to config:
#     use 'pyneat/pyneat-vim'
#
# Requirements:
#   - Python 3.8+ with pyneat installed
#   - Neovim 0.8+ or Vim 8.2+

# ============================================
# Configuration
# ============================================

# Enable/disable PyNEAT
let g:pyneat_enable = 1

# Default package: safe, conservative, or destructive
let g:pyneat_package = 'safe'

# Auto-run on save
let g:pyneat_auto_fix = 0

# Show notifications
let g:pyneat_show_notifications = 1

# Debug mode
let g:pyneat_debug = 0

# Key mappings
let g:pyneat_keymap_clean = '<Leader>pc'
let g:pyneat_keymap_check = '<Leader>ps'
let g:pyneat_keymap_dryrun = '<Leader>pd'

# ============================================
# Commands
# ============================================

# :PyneatClean - Clean current file
# :PyneatCheck - Security check
# :PyneatDryRun - Preview changes
# :PyneatRules - List available rules
# :PyneatReport - Generate report

# ============================================
# Integration with coc.nvim
# ============================================

# Add to coc-settings.json:
# {
#   "python.linting.pyneatEnabled": true,
#   "python.formatting.pyneatPath": "pyneat"
# }

# ============================================
# Integration with ALE
# ============================================

# Add to .vimrc:
# let g:ale_linters = {
# \   'python': ['pyneat', 'pylint', 'flake8'],
# \}

# ============================================
# Integration with Neovim built-in LSP
# ============================================

# Add to init.lua:
# local lspconfig = require('lspconfig')
# local configs = require('lspconfig.configs')
#
# -- Register PyNEAT LSP
# if not configs.pyneat_lsp then
#   configs.pyneat_lsp = {
#     default_config = {
#       cmd = {'python', '-m', 'pyneat.lsp'},
#       filetypes = {'python'},
#       root_dir = function(fname)
#         return vim.loop.cwd()
#       end,
#       settings = {}
#     }
#   }
# end
#
# lspconfig.pyneat_lsp.setup{}

# ============================================
# Integration with telescope.nvim
# ============================================

# Add to init.lua:
# local telescope = require('telescope')
# telescope.load_extension('pyneat')
#
# -- Search PyNEAT findings
# telescope.extensions.pyneat.findings()

# ============================================
# Status Line Integration
# ============================================

# Add to statusline:
# let &statusline .= ' | PyNEAT: ' . (exists('g:pyneat_last_result') ? g:pyneat_last_result : 'OK')
