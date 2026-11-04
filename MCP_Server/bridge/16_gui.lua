-- ============================================================================
-- Cheat Engine MCP Bridge :: 16_gui
-- Window / GUI (UNIT-16)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local toHex = B.toHex

-- >>> BEGIN UNIT-16 Window GUI <<<
-- ============================================================================
-- WINDOW / GUI COMMAND HANDLERS
-- No process guard required: these APIs are system-wide window operations.
-- ============================================================================

-- Shared helper: parse a hex window-handle string into a number.
-- Returns the number, or nil if the string is missing/invalid.
local function parseHandle(hexStr)
    return tonumber(hexStr, 16)
end

function cmd_find_window(params)
    local title      = params.title
    local class_name = params.class_name

    if not title and not class_name then
        return { success = false, error = "At least one of title or class_name must be provided", error_code = "INVALID_PARAMS" }
    end

    local ok, handle = pcall(function()
        return findWindow(class_name, title)
    end)

    if not ok then
        return { success = false, error = tostring(handle), error_code = "INTERNAL_ERROR" }
    end

    if not handle or handle == 0 then
        return { success = false, error_code = "NOT_FOUND" }
    end

    return { success = true, handle = toHex(handle) }
end

function cmd_get_window_caption(params)
    local handle = parseHandle(params.handle)
    if not handle then
        return { success = false, error = "Invalid handle", error_code = "INVALID_PARAMS" }
    end

    local ok, caption = pcall(function()
        return getWindowCaption(handle)
    end)

    if not ok then
        return { success = false, error = tostring(caption), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, caption = caption or "" }
end

function cmd_get_window_class_name(params)
    local handle = parseHandle(params.handle)
    if not handle then
        return { success = false, error = "Invalid handle", error_code = "INVALID_PARAMS" }
    end

    local ok, cls = pcall(function()
        return getWindowClassName(handle)
    end)

    if not ok then
        return { success = false, error = tostring(cls), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, class_name = cls or "" }
end

function cmd_get_window_process_id(params)
    local handle = parseHandle(params.handle)
    if not handle then
        return { success = false, error = "Invalid handle", error_code = "INVALID_PARAMS" }
    end

    local ok, pid = pcall(function()
        return getWindowProcessID(handle)
    end)

    if not ok then
        return { success = false, error = tostring(pid), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, process_id = pid }
end

function cmd_send_window_message(params)
    local handle = parseHandle(params.handle)
    if not handle then
        return { success = false, error = "Invalid handle", error_code = "INVALID_PARAMS" }
    end

    local msg    = params.msg    or 0
    local wparam = params.wparam or 0
    local lparam = params.lparam or 0

    local ok, result = pcall(function()
        return sendMessage(handle, msg, wparam, lparam)
    end)

    if not ok then
        return { success = false, error = tostring(result), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, result = result or 0 }
end

-- Modal dialog — blocks the CE main thread until the user clicks OK.
function cmd_show_message(params)
    local message = params.message
    if not message then
        return { success = false, error = "message is required", error_code = "INVALID_PARAMS" }
    end

    local ok, err = pcall(function()
        showMessage(message)
    end)

    if not ok then
        return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

-- Modal dialog — blocks until the user submits or cancels.
function cmd_input_query(params)
    local caption = params.caption or ""
    local prompt  = params.prompt  or ""
    local default = params.default or ""

    local ok, value = pcall(function()
        return inputQuery(caption, prompt, default)
    end)

    if not ok then
        return { success = false, error = tostring(value), error_code = "INTERNAL_ERROR" }
    end

    -- inputQuery returns nil on cancel (CE contract)
    if value == nil then
        return { success = true, value = "", cancelled = true }
    end

    return { success = true, value = value, cancelled = false }
end

-- Modal dialog — blocks until the user selects an item or cancels.
function cmd_show_selection_list(params)
    local caption = params.caption or ""
    local prompt  = params.prompt  or ""
    local options = params.options

    if type(options) ~= "table" then
        return { success = false, error = "options must be a list of strings", error_code = "INVALID_PARAMS" }
    end

    local sl = createStringlist()
    for _, v in ipairs(options) do
        sl.add(tostring(v))
    end

    local ok, idx, selected = pcall(function()
        return showSelectionList(caption, prompt, sl)
    end)

    sl.destroy()

    if not ok then
        return { success = false, error = tostring(idx), error_code = "INTERNAL_ERROR" }
    end

    if idx == nil or idx < 0 then
        return { success = true, selected_index = -1, selected_value = "", cancelled = true }
    end

    return {
        success        = true,
        selected_index = idx,
        selected_value = selected or "",
        cancelled      = false
    }
end

-- >>> END UNIT-16 <<<

-- >>> exports
B.parseHandle = parseHandle
