-- PyNEAT Neovim Lua Plugin
--
-- Install with packer.nvim:
-- use 'pyneat/pyneat-vim'
--
-- Or with lazy.nvim:
-- { 'pyneat/pyneat-vim', ft = 'python', cmd = {'PyneatClean', 'PyneatCheck'} }

local M = {}

M.config = {
    enable = true,
    package = "safe",  -- safe, conservative, destructive
    auto_fix = false,
    show_notifications = true,
    debug = false,
    keymaps = {
        clean = "<leader>pc",
        check = "<leader>ps",
        dryrun = "<leader>pd",
    },
}

function M.setup(opts)
    M.config = vim.tbl_deep_extend("force", M.config, opts or {})

    -- Create commands
    vim.api.nvim_create_user_command("PyneatClean", function(args)
        M.clean(args.args)
    end, {
        nargs = "?",
        desc = "Clean Python code with PyNEAT",
    })

    vim.api.nvim_create_user_command("PyneatCheck", function(args)
        M.check(args.args)
    end, {
        nargs = "?",
        desc = "Run PyNEAT security check",
    })

    vim.api.nvim_create_user_command("PyneatDryRun", function(args)
        M.dryrun(args.args)
    end, {
        nargs = "?",
        desc = "Preview PyNEAT changes",
    })

    vim.api.nvim_create_user_command("PyneatRules", function()
        M.list_rules()
    end, {
        desc = "List PyNEAT rules",
    })

    -- Create keymaps
    if M.config.enable then
        local keymaps = M.config.keymaps
        vim.keymap.set("n", keymaps.clean, "<cmd>PyneatClean<CR>", { desc = "PyNEAT Clean" })
        vim.keymap.set("n", keymaps.check, "<cmd>PyneatCheck<CR>", { desc = "PyNEAT Security Check" })
        vim.keymap.set("n", keymaps.dryrun, "<cmd>PyneatDryRun<CR>", { desc = "PyNEAT Dry Run" })
    end

    -- Add to statusline
    vim.opt.statusline:append("%{pyneat#get_status()}", "after")
end

function M.clean(path)
    local bufnr = vim.api.nvim_get_current_buf()
    local filepath = path or vim.api.nvim_buf_get_name(bufnr)

    if not filepath or filepath == "" then
        vim.notify("PyNEAT: No file path", vim.log.levels.WARN)
        return
    end

    local cmd = string.format(
        "python -m pyneat clean %s --package %s",
        filepath,
        M.config.package
    )

    if M.config.debug then
        vim.notify("PyNEAT: " .. cmd, vim.log.levels.INFO)
    end

    vim.fn.jobstart(cmd, {
        stdout_buffered = true,
        on_stdout = function(_, data)
            if data and data[1] then
                vim.notify("PyNEAT Clean:\n" .. table.concat(data, "\n"), vim.log.levels.INFO)
            end
        end,
        on_stderr = function(_, data)
            if data and data[1] then
                vim.notify("PyNEAT Error:\n" .. table.concat(data, "\n"), vim.log.levels.ERROR)
            end
        end,
    })
end

function M.check(path)
    local filepath = path or vim.api.nvim_buf_get_name(0)

    if not filepath or filepath == "" then
        vim.notify("PyNEAT: No file path", vim.log.levels.WARN)
        return
    end

    local cmd = string.format("python -m pyneat check %s", filepath)

    vim.fn.jobstart(cmd, {
        stdout_buffered = true,
        on_stdout = function(_, data)
            if data and data[1] then
                local output = table.concat(data, "\n")
                -- Create or update quickfix list
                vim.fn.setqflist({}, " ", {
                    title = "PyNEAT Security Check",
                    lines = data,
                })
                vim.cmd("cope")
            end
        end,
        on_stderr = function(_, data)
            if data and data[1] then
                vim.notify("PyNEAT Error:\n" .. table.concat(data, "\n"), vim.log.levels.ERROR)
            end
        end,
    })
end

function M.dryrun(path)
    local filepath = path or vim.api.nvim_buf_get_name(0)

    if not filepath or filepath == "" then
        vim.notify("PyNEAT: No file path", vim.log.levels.WARN)
        return
    end

    local cmd = string.format(
        "python -m pyneat clean %s --package %s --dry-run --diff",
        filepath,
        M.config.package
    )

    vim.fn.jobstart(cmd, {
        stdout_buffered = true,
        on_stdout = function(_, data)
            if data and data[1] then
                local output = table.concat(data, "\n")
                vim.notify("PyNEAT Dry Run:\n" .. output, vim.log.levels.INFO)
            end
        end,
    })
end

function M.list_rules()
    vim.fn.jobstart("python -m pyneat rules", {
        stdout_buffered = true,
        on_stdout = function(_, data)
            if data and data[1] then
                local output = table.concat(data, "\n")
                vim.notify("PyNEAT Rules:\n" .. output, vim.log.levels.INFO, {
                    title = "PyNEAT Rules",
                    timeout = 5000,
                })
            end
        end,
    })
end

-- Status line function
M.get_status = function()
    return "[PyNEAT]"
end

return M
