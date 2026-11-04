-- ============================================================================
-- Cheat Engine MCP Bridge :: 15_input
-- Input automation (UNIT-17)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

-- >>> BEGIN UNIT-17 Input Automation <<<
-- ============================================================================
-- COMMAND HANDLERS - INPUT AUTOMATION (mouse, keyboard, screen)
-- These APIs operate system-wide and require NO attached process.
-- ============================================================================

-- Shared helpers (local to this section)
local function parse_xy(params)
    if params.x == nil then return nil, nil, "Missing parameter: x" end
    if params.y == nil then return nil, nil, "Missing parameter: y" end
    local x, y = tonumber(params.x), tonumber(params.y)
    if x == nil or y == nil then return nil, nil, "Parameters x and y must be numbers" end
    return x, y, nil
end

local function parse_vk(params)
    if params.vk == nil then return nil, "Missing parameter: vk (Windows virtual-key code, e.g. 0x41 for 'A')" end
    local vk = tonumber(params.vk)
    if vk == nil then return nil, "Parameter vk must be a number" end
    return vk, nil
end

-- Execute a no-return CE key API (keyDown / keyUp / doKeyPress) and return {success}.
local function run_key_action(fn, vk, fn_name)
    local ok, err = pcall(fn, vk)
    if not ok then return { success = false, error = fn_name .. " failed: " .. tostring(err), error_code = "INTERNAL_ERROR" } end
    return { success = true }
end

function cmd_get_pixel(params)
    local x, y, err = parse_xy(params)
    if err then return { success = false, error = err, error_code = "INVALID_PARAMS" } end

    local ok, rgb = pcall(getPixel, x, y)
    if not ok then return { success = false, error = "getPixel failed: " .. tostring(rgb), error_code = "INTERNAL_ERROR" } end
    -- Windows COLORREF format: 0x00BBGGRR
    local r = rgb % 256
    local g = math.floor(rgb / 256) % 256
    local b = math.floor(rgb / 65536) % 256
    return { success = true, r = r, g = g, b = b, rgb = rgb }
end

function cmd_get_mouse_pos(params)
    local ok, x, y = pcall(getMousePos)
    if not ok then return { success = false, error = "getMousePos failed: " .. tostring(x), error_code = "INTERNAL_ERROR" } end
    return { success = true, x = x, y = y }
end

function cmd_set_mouse_pos(params)
    local x, y, err = parse_xy(params)
    if err then return { success = false, error = err, error_code = "INVALID_PARAMS" } end

    local ok, e = pcall(setMousePos, x, y)
    if not ok then return { success = false, error = "setMousePos failed: " .. tostring(e), error_code = "INTERNAL_ERROR" } end
    return { success = true }
end

function cmd_is_key_pressed(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err, error_code = "INVALID_PARAMS" } end

    local ok, pressed = pcall(isKeyPressed, vk)
    if not ok then return { success = false, error = "isKeyPressed failed: " .. tostring(pressed), error_code = "INTERNAL_ERROR" } end
    return { success = true, pressed = pressed == true }
end

function cmd_key_down(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err, error_code = "INVALID_PARAMS" } end
    return run_key_action(keyDown, vk, "keyDown")
end

function cmd_key_up(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err, error_code = "INVALID_PARAMS" } end
    return run_key_action(keyUp, vk, "keyUp")
end

function cmd_do_key_press(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err, error_code = "INVALID_PARAMS" } end
    return run_key_action(doKeyPress, vk, "doKeyPress")
end

function cmd_get_screen_info(params)
    local ok_w, width  = pcall(getScreenWidth)
    local ok_h, height = pcall(getScreenHeight)
    local ok_d, dpi    = pcall(getScreenDPI)

    if not ok_w then return { success = false, error = "getScreenWidth failed: " .. tostring(width), error_code = "INTERNAL_ERROR" } end
    if not ok_h then return { success = false, error = "getScreenHeight failed: " .. tostring(height), error_code = "INTERNAL_ERROR" } end
    if not ok_d then return { success = false, error = "getScreenDPI failed: " .. tostring(dpi), error_code = "INTERNAL_ERROR" } end

    return { success = true, width = width, height = height, dpi = dpi }
end

-- >>> END UNIT-17 <<<

-- >>> exports
B.parse_xy = parse_xy
B.parse_vk = parse_vk
B.run_key_action = run_key_action
