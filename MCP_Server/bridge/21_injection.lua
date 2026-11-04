-- ============================================================================
-- Cheat Engine MCP Bridge :: 21_injection
-- Code injection & execution (UNIT-09)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local requireProcess = B.requireProcess

-- >>> BEGIN UNIT-09 Code Injection <<<
-- ============================================================================
-- COMMAND HANDLERS - CODE INJECTION & EXECUTION
-- ============================================================================

-- Lua 5.1 compat: 'unpack' moved to 'table.unpack' in Lua 5.2+
local unpack = unpack or table.unpack


function cmd_inject_dll(params)
    local ok, err = requireProcess(); if not ok then return err end
    local filepath = params.filepath
    if not filepath then return { success = false, error = "No filepath provided", error_code = "INVALID_PARAMS" } end
    local skip = params.skip_symbol_reload or false

    local ok, result = pcall(injectDLL, filepath, skip)
    if not ok then
        return { success = false, error = "injectDLL failed: " .. tostring(result), error_code = "INTERNAL_ERROR" }
    end
    return { success = result == true }
end

function cmd_inject_dotnet_dll(params)
    local ok, err = requireProcess(); if not ok then return err end
    local dllpath    = params.filepath
    local className  = params.class_name
    local methodName = params.method_name
    local param      = params.param or ""
    local timeout    = params.timeout
    if timeout == nil then timeout = -1 end

    if not dllpath    then return { success = false, error = "No filepath provided", error_code = "INVALID_PARAMS" } end
    if not className  then return { success = false, error = "No class_name provided", error_code = "INVALID_PARAMS" } end
    if not methodName then return { success = false, error = "No method_name provided", error_code = "INVALID_PARAMS" } end

    local ok, result = pcall(injectDotNetDLL, dllpath, className, methodName, param, timeout)
    if not ok then
        return { success = false, error = "injectDotNetDLL failed: " .. tostring(result), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, result = result }
end

function cmd_execute_code(params)
    local ok, err = requireProcess(); if not ok then return err end
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    local param   = params.param   or 0
    local timeout = params.timeout
    if timeout == nil then timeout = -1 end

    local ok, retval = pcall(executeCode, addr, param, timeout)
    if not ok then
        return { success = false, error = "executeCode failed: " .. tostring(retval), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, return_value = retval }
end

function cmd_execute_code_ex(params)
    local ok, err = requireProcess(); if not ok then return err end
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    local callMethod = params.call_method or 0
    local timeout    = params.timeout
    if timeout == nil then timeout = -1 end
    local args = params.args or {}

    local ok, retval = pcall(executeCodeEx, callMethod, timeout, addr, unpack(args))
    if not ok then
        return { success = false, error = "executeCodeEx failed: " .. tostring(retval), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, return_value = retval }
end

function cmd_execute_method(params)
    local ok, err = requireProcess(); if not ok then return err end
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    local instance = params.instance
    if type(instance) == "string" then instance = getAddressSafe(instance) end

    local callMethod = params.call_method or 0
    local timeout    = params.timeout
    if timeout == nil then timeout = -1 end
    local args = params.args or {}

    local ok, retval = pcall(executeMethod, callMethod, timeout, addr, instance, unpack(args))
    if not ok then
        return { success = false, error = "executeMethod failed: " .. tostring(retval), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, return_value = retval }
end

-- No requireProcess() guard: runs in CE's own process, not the target.
function cmd_execute_code_local(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    local param = params.param or 0

    local ok, retval = pcall(executeCodeLocal, addr, param)
    if not ok then
        return { success = false, error = "executeCodeLocal failed: " .. tostring(retval), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, return_value = retval }
end

-- No requireProcess() guard: runs in CE's own process, not the target.
function cmd_execute_code_local_ex(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    local callMethod = params.call_method or 0
    local args = params.args or {}

    local ok, retval = pcall(executeCodeLocalEx, callMethod, addr, unpack(args))
    if not ok then
        return { success = false, error = "executeCodeLocalEx failed: " .. tostring(retval), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, return_value = retval }
end

-- >>> END UNIT-09 <<<

-- >>> exports
B.unpack = unpack
