-- ============================================================================
-- Cheat Engine MCP Bridge :: 07_lua_threading
-- Lua evaluation, threading & synchronisation (UNIT-22)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local json = B.json

-- ============================================================================
-- COMMAND HANDLERS - LUA EVALUATION
-- ============================================================================

-- Convert an arbitrary Lua value into plain JSON-encodable data. Tables are
-- copied with bounded depth/size and cycle detection; functions, userdata
-- and CE objects become their tostring().
local function toPlainData(v, depth, seen)
    local t = type(v)
    if t == "nil" or t == "boolean" or t == "number" or t == "string" then return v end
    if t ~= "table" then return tostring(v) end
    depth = depth or 0
    seen = seen or {}
    if seen[v] then return "<cycle: " .. tostring(v) .. ">" end
    if depth >= 8 then return tostring(v) end
    seen[v] = true
    local out, n = {}, 0
    for k, val in pairs(v) do
        n = n + 1
        if n > 10000 then out["__truncated"] = true; break end
        local key = (type(k) == "number" or type(k) == "string") and k or tostring(k)
        out[key] = toPlainData(val, depth + 1, seen)
    end
    seen[v] = nil
    return out
end

function cmd_evaluate_lua(params)
    local code = params.code
    if not code then return { success = false, error = "No code provided", error_code = "INVALID_PARAMS" } end

    local fn, err = load(code, "mcp_evaluate_lua", "t")
    if not fn then return { success = false, error = "Compile error: " .. tostring(err), error_code = "INVALID_PARAMS" } end

    local packed = table.pack(pcall(fn))
    if not packed[1] then return { success = false, error = "Runtime error: " .. tostring(packed[2]), error_code = "INTERNAL_ERROR" } end

    -- result: tostring() of the first return value (backward compatible).
    -- results: every return value as structured JSON (tables included).
    -- nil return values become json.null so trailing nils keep their slot
    -- (`return 42, nil` -> [42, null], matching result_count).
    local results = {}
    for i = 2, packed.n do
        local v = toPlainData(packed[i])
        if v == nil then v = json.null end
        results[i - 1] = v
    end
    return { success = true, result = tostring(packed[2]), results = results, result_count = packed.n - 1 }
end

-- >>> BEGIN UNIT-22 Threading Sync <<<
-- ============================================================================
-- COMMAND HANDLERS - THREADING & SYNCHRONIZATION
-- These operate on CE's Lua scripting host, NOT the target process.
-- No process guard is needed or appropriate here.
-- ============================================================================

local _unit22_thread_counter = 0

function cmd_create_thread(params)
    -- SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process.
    -- It carries the same risk as evaluate_lua. Only use with trusted code.
    local code = params.code
    local arg  = params.arg or ""
    if not code then return { success = false, error = "No code provided", error_code = "INVALID_PARAMS" } end

    local ok, err = pcall(function()
        createThread(function(thread, a)
            local f, ferr = loadstring(code)
            if not f then error("Compile error: " .. tostring(ferr)) end
            return f(thread, a)
        end, arg)
    end)

    if not ok then
        return { success = false, error = "createThread failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    _unit22_thread_counter = _unit22_thread_counter + 1
    return { success = true, thread_id = _unit22_thread_counter }
end

function cmd_get_global_variable(params)
    local name = params.name
    if not name then return { success = false, error = "No variable name provided", error_code = "INVALID_PARAMS" } end

    local ok, value = pcall(getGlobalVariable, name)
    if not ok then
        return { success = false, error = "getGlobalVariable failed: " .. tostring(value), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, value = tostring(value) }
end

function cmd_set_global_variable(params)
    local name  = params.name
    local value = params.value
    if not name  then return { success = false, error = "No variable name provided", error_code = "INVALID_PARAMS" } end
    if value == nil then return { success = false, error = "No value provided", error_code = "INVALID_PARAMS" } end

    local ok, err = pcall(setGlobalVariable, name, value)
    if not ok then
        return { success = false, error = "setGlobalVariable failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_queue_to_main_thread(params)
    -- SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process
    -- on the main thread. It carries the same risk as evaluate_lua.
    local code = params.code
    if not code then return { success = false, error = "No code provided", error_code = "INVALID_PARAMS" } end

    local ok, err = pcall(function()
        queue(function()
            local f, ferr = loadstring(code)
            if not f then error("Compile error: " .. tostring(ferr)) end
            f()
        end)
    end)

    if not ok then
        return { success = false, error = "queue failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_check_synchronize(params)
    local ok, err = pcall(checkSynchronize)
    if not ok then
        return { success = false, error = "checkSynchronize failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_in_main_thread(params)
    local ok, result = pcall(inMainThread)
    if not ok then
        return { success = false, error = "inMainThread failed: " .. tostring(result), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, is_main_thread = result == true }
end

-- >>> END UNIT-22 <<<

-- >>> exports
B.toPlainData = toPlainData
B._unit22_thread_counter = _unit22_thread_counter
