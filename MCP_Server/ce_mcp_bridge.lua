-- ============================================================================
-- CHEATENGINE MCP BRIDGE v12.3.0
-- ============================================================================
-- Loader. The bridge itself lives in MCP_Server/bridge/NN_*.lua; this file
-- finds that folder, stops a bridge that is already running, loads the modules
-- in order and starts the pipe server. Load it exactly as before:
--   File -> Execute Script (this file), or
--   dofile([[C:\path\to\cheatengine-mcp-bridge\MCP_Server\ce_mcp_bridge.lua]])
-- If the bridge folder cannot be found (a CE build that runs the script as text,
-- without its file name), set the folder first:
--   CE_MCP_BRIDGE_DIR = [[C:\path\to\cheatengine-mcp-bridge\MCP_Server]]
--
-- Module contract: each module is its own Lua chunk, called with the shared
-- namespace table B (`local B = ...`). It imports the helpers it needs as
-- locals (`local toHex = B.toHex`) and exports its own top-level locals at the
-- end (`B.foo = foo`). Command handlers (cmd_*) stay globals. Because every
-- module is a separate chunk, Cheat Engine's 200-local limit applies per
-- module, not to the whole bridge.
-- ============================================================================

local MODULES = {
    "00_core",
    "01_json",
    "02_process",
    "03_memory_read",
    "04_scan",
    "05_disassembly",
    "06_breakpoints",
    "07_lua_threading",
    "08_regions_utility",
    "09_analysis_tools",
    "10_dbvm",
    "11_multimedia",
    "12_kernel",
    "13_files_shell",
    "14_structures_table",
    "15_input",
    "16_gui",
    "17_scan_advanced",
    "18_memory_ops",
    "19_asm_symbols_context",
    "20_debugger",
    "21_injection",
    "22_allocation",
    "23_process_lifecycle",
    "24_pointer_analysis",
    "25_operations",
    "26_analysis",
    "27_functions_structs",
    "28_xrefs",
    "29_pointer_sets",
    "30_patch_journal",
    "31_dispatcher",
}

local function bridgeDir()
    local configured = rawget(_G, "CE_MCP_BRIDGE_DIR")
    if type(configured) == "string" and configured ~= "" then
        return (configured:gsub("[/\\]+$", "")) .. (configured:find("\\") and "\\" or "/")
    end
    local info = debug and debug.getinfo and debug.getinfo(1, "S")
    local source = info and info.source
    if type(source) == "string" and source:sub(1, 1) == "@" then
        return source:sub(2):match("^(.*[/\\])") or ""
    end
    return nil
end

local dir = bridgeDir()
local sep = (dir and dir:find("\\")) and "\\" or "/"
local function modulePath(name) return (dir or "") .. "bridge" .. sep .. name .. ".lua" end

do
    local probe = dir and io.open(modulePath(MODULES[1]), "r")
    if not probe then
        error("[MCP] Cannot find the bridge modules (" .. modulePath(MODULES[1]) .. "). "
            .. "Load ce_mcp_bridge.lua with dofile([[C:\\path\\to\\MCP_Server\\ce_mcp_bridge.lua]]), "
            .. "or set CE_MCP_BRIDGE_DIR = [[C:\\path\\to\\MCP_Server]] before loading it.", 0)
    end
    probe:close()
end

-- Stop the bridge that is already running, if any. Its StopMCPBridge still
-- holds that instance's state (worker thread, pipe, breakpoints, DBVM watches),
-- so it has to be called before the new modules replace the global.
if type(rawget(_G, "StopMCPBridge")) == "function" then
    local ok, err = pcall(StopMCPBridge)
    if not ok then print("[MCP] Previous bridge did not stop cleanly: " .. tostring(err)) end
end

local B = { BRIDGE_DIR = dir }
for _, name in ipairs(MODULES) do
    local path = modulePath(name)
    local chunk, err = loadfile(path, "t")
    if not chunk then error("[MCP] Failed to load " .. path .. ": " .. tostring(err), 0) end
    chunk(B)
end

StartMCPBridge()
return B
