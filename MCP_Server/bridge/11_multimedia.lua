-- ============================================================================
-- Cheat Engine MCP Bridge :: 11_multimedia
-- Debug output & multimedia (UNIT-23)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

-- >>> BEGIN UNIT-23 Debug Multimedia <<<

local progressStateMap = {
    none          = tbpsNone,
    normal        = tbpsNormal,
    paused        = tbpsPaused,
    error         = tbpsError,
    indeterminate = tbpsIndeterminate,
}

function cmd_output_debug_string(params)
    local message = params.message
    if type(message) ~= "string" then
        return { success = false, error = "message must be a string", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(outputDebugString, message)
    if not ok then return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" } end
    return { success = true }
end

function cmd_speak_text(params)
    local text = params.text
    if type(text) ~= "string" then
        return { success = false, error = "text must be a string", error_code = "INVALID_PARAMS" }
    end
    local ok, err
    if params.english_only then
        ok, err = pcall(speakEnglish, text)
    else
        ok, err = pcall(speak, text)
    end
    if not ok then return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" } end
    return { success = true }
end

function cmd_play_sound(params)
    if type(params.filename) ~= "string" or params.filename:find("%.%.") then
        return { success = false, error = "Invalid filename", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(playSound, params.filename)
    if not ok then return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" } end
    return { success = true }
end

function cmd_beep(params)
    local ok, err = pcall(beep)
    if not ok then return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" } end
    return { success = true }
end

function cmd_set_progress_state(params)
    local tbState = progressStateMap[params.state]
    if not tbState then
        return { success = false, error = "state must be one of: none, normal, paused, error, indeterminate", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(setProgressState, tbState)
    if not ok then return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" } end
    return { success = true }
end

function cmd_set_progress_value(params)
    local current = params.current
    local max = params.max
    if type(current) ~= "number" or type(max) ~= "number" then
        return { success = false, error = "current and max must be numbers", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(setProgressValue, current, max)
    if not ok then return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" } end
    return { success = true }
end

-- >>> END UNIT-23 <<<

-- >>> exports
B.progressStateMap = progressStateMap
