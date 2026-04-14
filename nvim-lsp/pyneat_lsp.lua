--[[
  PyNEAT Neovim LSP Plugin

  Copyright (C) 2026 PyNEAT Authors

  A Language Server Protocol (LSP) client for PyNEAT security scanner.
  Provides real-time diagnostics, hover information, and code actions in Neovim.

  Requirements:
    - Neovim 0.8+
    - pyneat-cli installed (pip install pyneat-cli)
    - Optional: pyneat-rs binary for faster scanning

  Installation:
    - Using packer.nvim:
      use { 'pyneat/pyneat', opt = true, run = 'pip install pyneat-cli' }

    - Manual:
      Copy this file to ~/.config/nvim/lua/pyneat_lsp.lua
      And add to your init.lua: require('pyneat_lsp').setup()

  Configuration:
    > lua require('pyneat_lsp').setup({
        python_path = 'python',
        severity_threshold = 'info',
        enable_real_time = true,
        scan_on_save = true,
        languages = { 'python', 'javascript', 'typescript', 'go', 'java', 'rust' },
        config = {
          cmd = { 'pyneat', 'lsp' },
          name = 'pyneat',
        }
      })
--]]

local M = {}

-- Default configuration
M.config = {
  -- Path to Python interpreter with PyNEAT
  python_path = 'python',
  -- Minimum severity level (info, low, medium, high, critical)
  severity_threshold = 'info',
  -- Enable real-time scanning
  enable_real_time = true,
  -- Scan on file save
  scan_on_save = true,
  -- Debounce delay in ms
  debounce_delay = 1000,
  -- Languages to scan
  languages = {
    'python', 'javascript', 'typescript',
    'go', 'java', 'rust', 'csharp', 'php', 'ruby',
  },
  -- LSP server configuration
  server = {
    cmd = { 'pyneat', 'server' },
    name = 'pyneat',
    -- Or use the CLI wrapper
    -- cmd = { 'python', '-m', 'pyneat', 'lsp' },
  },
  -- Custom rules (optional)
  custom_rules = {},
  -- Enable AI security rules
  enable_ai_rules = true,
}

-- Internal state
M.state = {
  clients = {},
  diagnostics = {},
  handlers = {},
}

-- Utility functions
local function log(msg)
  vim.notify('[PyNEAT] ' .. msg, vim.log.levels.DEBUG)
end

local function error_log(msg)
  vim.notify('[PyNEAT ERROR] ' .. msg, vim.log.levels.ERROR)
end

local function get_severity_level(severity)
  local levels = {
    critical = vim.diagnostic.severity.ERROR,
    high = vim.diagnostic.severity.ERROR,
    medium = vim.diagnostic.severity.WARN,
    low = vim.diagnostic.severity.INFO,
    info = vim.diagnostic.severity.INFO,
  }
  return levels[severity] or vim.diagnostic.severity.WARN
end

local function should_scan_ft(filetype)
  for _, lang in ipairs(M.config.languages) do
    if filetype == lang or filetype == lang .. '.tsx' then
      return true
    end
  end
  return false
end

-- Run PyNEAT scan on a file
local function run_scan(bufnr, filepath)
  local python = M.config.python_path
  local cmd = {
    python, '-m', 'pyneat', 'check',
    '--format', 'sarif',
    filepath,
  }

  local output = vim.fn.system(cmd)
  local result = vim.fn.json_decode(output or '{}')

  if not result or not result.runs or #result.runs == 0 then
    -- Clear diagnostics if no results
    vim.diagnostic.reset(0, bufnr)
    return
  end

  local run = result.runs[1]
  local findings = run.results or {}

  -- Convert SARIF to Neovim diagnostics format
  local diagnostics = {}
  for _, finding in ipairs(findings) do
    local location = finding.locations and finding.locations[1]
    if location and location.physicalLocation then
      local region = location.physicalLocation.region or {}
      local line = (region.startLine or 1) - 1

      local diag = {
        bufnr = bufnr,
        lnum = line,
        end_lnum = (region.endLine or region.startLine or 1) - 1,
        col = (region.startColumn or 1) - 1,
        end_col = (region.endColumn or region.startColumn or 1) - 1,
        severity = get_severity_level(finding.level or 'warning'),
        message = finding.message and finding.message.text or 'Security issue found',
        source = 'PyNEAT',
        code = finding.ruleId,
        user_data = {
          pyneat = {
            rule_id = finding.ruleId,
            level = finding.level,
            properties = finding.properties,
          }
        }
      }

      table.insert(diagnostics, diag)
    end
  end

  -- Set diagnostics
  vim.diagnostic.set('pyneat', bufnr, diagnostics, {
    virtual_text = true,
    signs = true,
    underline = true,
    update_in_insert = false,
  })

  log(string.format('Found %d issues in %s', #diagnostics, filepath))
end

-- Debounce helper
local debounce_timers = {}

local function debounce(id, delay, callback)
  if debounce_timers[id] then
    vim.fn.timer_stop(debounce_timers[id])
  end

  debounce_timers[id] = vim.fn.timer_start(delay, function()
    callback()
    debounce_timers[id] = nil
  end)
end

-- Setup function
function M.setup(user_config)
  -- Merge user config with defaults
  if user_config then
    for k, v in pairs(user_config) do
      if type(v) == 'table' and not vim.tbl_islist(v) then
        M.config[k] = vim.tbl_deep_extend('force', M.config[k] or {}, v)
      else
        M.config[k] = v
      end
    end
  end

  -- Register diagnostics
  vim.diagnostic.config({
    underline = true,
    virtual_text = {
      prefix = '●',
      source = 'if_many',
    },
    signs = true,
    update_in_insert = false,
    severity_sort = true,
  })

  -- Create signs
  vim.fn.sign_define('DiagnosticSignError', {
    text = 'E',
    texthl = 'DiagnosticSignError',
    linehl = '',
    numhl = 'DiagnosticUnderlineError',
  })
  vim.fn.sign_define('DiagnosticSignWarn', {
    text = 'W',
    texthl = 'DiagnosticSignWarn',
    linehl = '',
    numhl = 'DiagnosticUnderlineWarn',
  })
  vim.fn.sign_define('DiagnosticSignInfo', {
    text = 'I',
    texthl = 'DiagnosticSignInfo',
    linehl = '',
    numhl = 'DiagnosticUnderlineInfo',
  })
  vim.fn.sign_define('DiagnosticSignHint', {
    text = 'H',
    texthl = 'DiagnosticSignHint',
    linehl = '',
    numhl = 'DiagnosticUnderlineHint',
  })

  -- Register LSP handler
  if M.config.server and M.config.server.cmd then
    local lspconfig_ok, lspconfig = pcall(require, 'lspconfig')

    if lspconfig_ok and lspconfig[M.config.server.name] then
      lspconfig[M.config.server.name].setup({
        cmd = M.config.server.cmd,
        name = M.config.server.name,
        on_attach = function(client, bufnr)
          log('PyNEAT LSP attached to buffer ' .. bufnr)

          -- Enable hover
          if client.server_capabilities.hoverProvider then
            vim.keymap.set('n', 'K', function()
              vim.lsp.buf.hover()
            end, { buffer = bufnr, desc = 'PyNEAT: Hover' })
          end

          -- Enable code actions
          if client.server_capabilities.codeActionProvider then
            vim.keymap.set('n', '<leader>fa', function()
              vim.lsp.buf.code_action()
            end, { buffer = bufnr, desc = 'PyNEAT: Code Action' })
          end
        end,
      })
    else
      -- Fallback: use CLI-based scanning
      log('LSP server not found, using CLI-based scanning')

      -- Create autocommands for CLI scanning
      local augroup = vim.api.nvim_create_augroup('PyNEAT', { clear = true })

      -- Scan on BufEnter and BufWritePost
      vim.api.nvim_create_autocmd({'BufEnter', 'BufWritePost'}, {
        group = augroup,
        pattern = table.concat(M.config.languages, ','),
        callback = function(args)
          if not should_scan_ft(vim.bo[args.buf].filetype) then
            return
          end

          local filepath = vim.api.nvim_buf_get_name(args.buf)
          if filepath == '' then
            return
          end

          local id = 'buf_' .. args.buf
          debounce(id, M.config.debounce_delay, function()
            run_scan(args.buf, filepath)
          end)
        end,
      })

      -- Scan on TextChanged if real-time enabled
      if M.config.enable_real_time then
        vim.api.nvim_create_autocmd('TextChangedI', {
          group = augroup,
          pattern = table.concat(M.config.languages, ','),
          callback = function(args)
            if not should_scan_ft(vim.bo[args.buf].filetype) then
              return
            end

            local filepath = vim.api.nvim_buf_get_name(args.buf)
            if filepath == '' then
              return
            end

            local id = 'buf_' .. args.buf .. '_realtime'
            debounce(id, M.config.debounce_delay, function()
              run_scan(args.buf, filepath)
            end)
          end,
        })
      end
    end
  end

  -- Register commands
  vim.api.nvim_create_user_command('PyNEATScan', function(args)
    local bufnr = args.buf or vim.api.nvim_get_current_buf()
    local filepath = args.args ~= '' and args.args or vim.api.nvim_buf_get_name(bufnr)
    if filepath == '' then
      vim.notify('No file specified', vim.log.levels.WARN)
      return
    end
    run_scan(bufnr, filepath)
  end, {
    nargs = '?',
    range = 0,
    complete = 'file',
    desc = 'Run PyNEAT scan on a file',
  })

  vim.api.nvim_create_user_command('PyNEATWorkspace', function()
    local root = vim.fn.getcwd()
    local files = vim.fn.globpath(root, '**/*', 0, 1)

    local total_findings = 0
    local total_files = 0

    for _, filepath in ipairs(files) do
      if vim.fn.filereadable(filepath) == 1 then
        local ext = filepath:match('%.(%w+)$')
        local ft_map = {
          py = 'python', js = 'javascript', ts = 'typescript',
          go = 'go', java = 'java', rs = 'rust', cs = 'csharp',
          php = 'php', rb = 'ruby',
        }
        if ext and ft_map[ext] then
          local bufnr = vim.fn.bufadd(filepath)
          run_scan(bufnr, filepath)
          total_files = total_files + 1
        end
      end
    end

    vim.notify(string.format('PyNEAT: Scanned %d files', total_files), vim.log.levels.INFO)
  end, {
    nargs = 0,
    desc = 'Run PyNEAT scan on workspace',
  })

  vim.api.nvim_create_user_command('PyNEATClear', function(args)
    local bufnr = args.buf or vim.api.nvim_get_current_buf()
    vim.diagnostic.reset(0, bufnr)
    log('Cleared PyNEAT diagnostics for buffer ' .. bufnr)
  end, {
    nargs = 0,
    range = 0,
    desc = 'Clear PyNEAT diagnostics',
  })

  log('PyNEAT LSP plugin initialized')
end

-- Telescope integration (optional)
function M.setup_telescope()
  local ok, telescope = pcall(require, 'telescope')
  if not ok then
    return
  end

  telescope.register_extension({
    setup = function(config)
      -- Custom telescope config
    end,
    telescope = {
      find_files = function(opts)
        -- Find files with PyNEAT findings
        local results = {}
        for bufnr, diags in pairs(M.state.diagnostics) do
          if next(diags) then
            local name = vim.api.nvim_buf_get_name(bufnr)
            table.insert(results, name)
          end
        end
        return results
      end,
    },
  })
end

-- Get all findings
function M.get_findings()
  return M.state.diagnostics
end

-- Export for external use
return M
