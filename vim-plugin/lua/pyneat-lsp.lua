-- PyNEAT LSP Configuration for Neovim
--
-- Add to your init.lua or lsp config:
--
-- local lspconfig = require('lspconfig')
-- local pyneat_lsp = require('pyneat.lsp')
--
-- lspconfig.pyneat.setup({
--   cmd = {'python', '-m', 'pyneat.lsp'},
--   filetypes = {'python'},
--   root_dir = lspconfig.util.root_pattern('pyproject.toml', 'setup.py', '.git'),
--   settings = {
--     pyneat = {
--       enable = true,
--       package = 'safe'
--     }
--   }
-- })

local lspconfig = require('lspconfig')
local util = require('lspconfig.util')

local config = {
    default_config = {
        cmd = {'python', '-m', 'pyneat.lsp', '--stdio'},
        filetypes = {'python'},
        root_dir = function(fname)
            return util.root_pattern('pyproject.toml', 'setup.py', '.git', 'requirements.txt')(fname)
                or util.path.dirname(fname)
        end,
        single_file_support = true,
        settings = {
            pyneat = {
                enable = true,
                package = 'safe',
                auto_fix = false,
                show_notifications = true,
            }
        },
        handlers = {
            ['textDocument/publishDiagnostics'] = function(_, result, ctx, config)
                if result.diagnostics then
                    for _, diag in ipairs(result.diagnostics) do
                        -- Map severity
                        if diag.severity == 1 then
                            diag.severity = vim.diagnostic.severity.ERROR
                        elseif diag.severity == 2 then
                            diag.severity = vim.diagnostic.severity.WARN
                        else
                            diag.severity = vim.diagnostic.severity.INFO
                        end
                    end
                end
                vim.lsp.diagnostic.on_publish_diagnostics(_, result, ctx, config)
            end,
        },
    },

    docs = {
        description = [[
PyNEAT Language Server

Provides real-time Python code analysis, security scanning, and auto-fix capabilities.

Features:
- Security vulnerability detection
- Code quality suggestions
- Auto-fix support
- Real-time diagnostics

Install:
    pip install pyneat-cli[server]

Configuration:
    settings.pyneat.enable = true
    settings.pyneat.package = 'safe'  -- safe, conservative, destructive
        ]],
    },
}

lspconfig.pyneat = {
    default_config = config.default_config,
    docs = config.docs,
}

-- Setup helper
local function setup(user_config)
    lspconfig.pyneat.setup(user_config or {})
end

return {
    setup = setup,
    config = config,
}
