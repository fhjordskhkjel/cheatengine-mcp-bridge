-- ============================================================================
-- Cheat Engine MCP Bridge :: 13_files_shell
-- File I/O, clipboard (UNIT-20a) and shell execution (UNIT-20b)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

-- >>> BEGIN UNIT-20a File IO Clipboard <<<
-- ============================================================================
-- UNIT-20a: Safe File I/O and Clipboard Tools
-- ============================================================================

local function sanitizeFilename(f)
    if type(f) ~= "string" or f == "" then return nil, "Invalid filename" end
    if f:find("%.%.") then return nil, "Path traversal not allowed" end
    return f, nil
end

function cmd_file_exists(params)
    local filename = params.filename
    local f, err = sanitizeFilename(filename)
    if not f then return { success = false, error = err, error_code = "INVALID_PARAMS" } end
    local ok, result = pcall(fileExists, f)
    if not ok then return { success = false, error = tostring(result), error_code = "INTERNAL_ERROR" } end
    return { success = true, exists = result == true }
end

function cmd_delete_file(params)
    local filename = params.filename
    local f, err = sanitizeFilename(filename)
    if not f then return { success = false, error = err, error_code = "INVALID_PARAMS" } end
    local ok, result = pcall(deleteFile, f)
    if not ok then return { success = false, error = tostring(result), error_code = "INTERNAL_ERROR" } end
    return { success = true }
end

local function listPathEntries(path, ceFn, resultKey)
    local f, err = sanitizeFilename(path)
    if not f then return { success = false, error = err, error_code = "INVALID_PARAMS" } end
    local ok, result = pcall(ceFn, f)
    if not ok then return { success = false, error = tostring(result), error_code = "INTERNAL_ERROR" } end
    local entries = {}
    if type(result) == "table" then
        for _, v in ipairs(result) do table.insert(entries, v) end
    end
    return { success = true, count = #entries, [resultKey] = entries }
end

function cmd_get_file_list(params)
    return listPathEntries(params.path, getFileList, "files")
end

function cmd_get_directory_list(params)
    return listPathEntries(params.path, getDirectoryList, "directories")
end

function cmd_get_temp_folder(params)
    local ok, result = pcall(getTempFolder)
    if not ok then return { success = false, error = tostring(result), error_code = "INTERNAL_ERROR" } end
    return { success = true, path = tostring(result) }
end

function cmd_get_file_version(params)
    local f, err = sanitizeFilename(params.filename)
    if not f then return { success = false, error = err, error_code = "INVALID_PARAMS" } end
    -- getFileVersion returns two values; wrap in a closure so pcall captures both
    local ok, errOrRaw, verTable = pcall(function() return getFileVersion(f) end)
    if not ok then return { success = false, error = tostring(errOrRaw), error_code = "INTERNAL_ERROR" } end
    if type(verTable) ~= "table" then
        return { success = false, error = "getFileVersion did not return a version table", error_code = "INTERNAL_ERROR" }
    end
    local major   = verTable.major   or 0
    local minor   = verTable.minor   or 0
    local release = verTable.release or 0
    local build   = verTable.build   or 0
    return {
        success = true,
        major = major,
        minor = minor,
        release = release,
        build = build,
        version_string = string.format("%d.%d.%d.%d", major, minor, release, build)
    }
end

function cmd_read_clipboard(params)
    local ok, result = pcall(readFromClipboard)
    if not ok then return { success = false, error = tostring(result), error_code = "INTERNAL_ERROR" } end
    return { success = true, text = tostring(result or "") }
end

function cmd_write_clipboard(params)
    local text = params.text
    if type(text) ~= "string" then return { success = false, error = "text must be a string", error_code = "INVALID_PARAMS" } end
    local ok, err = pcall(writeToClipboard, text)
    if not ok then return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" } end
    return { success = true }
end

-- >>> END UNIT-20a <<<

-- ============================================================================
-- UNIT-20b: Shell Execution Handlers
-- Two opt-ins are required. The MCP server checks CE_MCP_ALLOW_SHELL in its own
-- environment; this bridge checks its own, set where Cheat Engine runs:
--   * CE_MCP_ALLOW_SHELL=1 in Cheat Engine's environment, or
--   * `CE_MCP_ALLOW_SHELL = true` executed before loading this script.
-- CE usually runs elevated (DBK/DBVM need it), so a shell command started here
-- runs with CE's privileges; a client that reaches the pipe without going
-- through the MCP server must not get that by default. The setting is captured
-- once at load time, so setting the global later over the pipe does not
-- enable it (evaluate_lua can still run anything, which is why CE_MCP_PROFILE
-- keeps exec tools off the MCP surface unless "full").
-- ============================================================================

local SHELL_ALLOWED = (os and os.getenv and os.getenv("CE_MCP_ALLOW_SHELL") == "1")
    or rawget(_G, "CE_MCP_ALLOW_SHELL") == true

local function shellDenied()
    if SHELL_ALLOWED then return nil end
    return {
        success = false,
        error = "Shell tools are disabled inside Cheat Engine. Set CE_MCP_ALLOW_SHELL=1 in Cheat Engine's "
            .. "environment, or run `CE_MCP_ALLOW_SHELL = true` before loading ce_mcp_bridge.lua, then reload the bridge.",
        error_code = "PERMISSION_DENIED",
    }
end

-- run_command: Wraps CE's runCommand(exepath, parameters, pathtoexecutein)
-- Returns output string and exit code. SECURITY: arbitrary code execution.
function cmd_run_command(params)
    local denied = shellDenied()
    if denied then return denied end
    local command = params.command
    local args = params.args or ""

    if not command or command == "" then
        return { success = false, error = "No command provided", error_code = "INVALID_PARAMS" }
    end

    local ok, output, exitCode = pcall(runCommand, command, args)

    if not ok then
        return { success = false, error = "runCommand failed: " .. tostring(output), error_code = "INTERNAL_ERROR" }
    end

    return {
        success = true,
        output = tostring(output or ""),
        exit_code = tonumber(exitCode) or 0
    }
end

-- shell_execute: Wraps CE's shellExecute(command, parameters, folder, showcommand)
-- SECURITY: arbitrary code execution via Windows ShellExecute.
function cmd_shell_execute(params)
    local denied = shellDenied()
    if denied then return denied end
    local command = params.command
    local args = params.args or ""
    local verb = string.lower(params.verb or "open")
    local workingDir = params.working_dir or ""
    local showCommand = params.showcommand

    if not command or command == "" then
        return { success = false, error = "No command provided", error_code = "INVALID_PARAMS" }
    end

    -- CE's shellExecute wrapper does not expose an explicit "verb" argument.
    -- Keep compatibility explicit to avoid silent behavior differences.
    if verb ~= "open" then
        return { success = false, error = "Unsupported verb for shell_execute: " .. tostring(verb), error_code = "INVALID_PARAMS" }
    end

    if showCommand ~= nil and type(showCommand) ~= "number" then
        return { success = false, error = "showcommand must be a number when provided", error_code = "INVALID_PARAMS" }
    end

    local ok, err = pcall(shellExecute, command, args, workingDir ~= "" and workingDir or nil, showCommand)

    if not ok then
        return { success = false, error = "shellExecute failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

-- >>> END UNIT-20b <<<

-- >>> exports
B.sanitizeFilename = sanitizeFilename
B.listPathEntries = listPathEntries
B.SHELL_ALLOWED = SHELL_ALLOWED
B.shellDenied = shellDenied
