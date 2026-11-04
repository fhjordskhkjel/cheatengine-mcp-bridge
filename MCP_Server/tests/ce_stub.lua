-- Minimal Cheat Engine API stubs so ce_mcp_bridge.lua can be loaded and its
-- handlers exercised offline (no CE, no target process). Tests drive the
-- MEM / MEM_BYTES tables and inspect BP_CALLBACKS / CONTINUES.
-- The pointer sets and the patch journal are saved to a state folder; the offline tests must never write into the repo.
CE_MCP_STATE_DIR = "off"

MEM = {}          -- MEM[addr] (float/double), MEM["i"..addr] (dword), MEM["q"..addr] (qword)
MEM_BYTES = {}    -- MEM_BYTES[addr] = { byte, byte, ... }
BP_CALLBACKS = {} -- BP_CALLBACKS[addr] = hit callback passed to debug_setBreakpoint
CONTINUES = 0     -- number of debug_continueFromBreakpoint calls

function createThread(fn) return { terminate = function() end } end
function getOpenedProcessID() return 1234 end
function targetIs64Bit() return true end
function getAddressSafe(s)
    if type(s) == "number" then return s end
    return tonumber((s:gsub("^0x", "")), 16)
end
function readInteger(a) return MEM["i" .. a] end
function readQword(a) return MEM["q" .. a] end
function readBytes(a, n)
    local b = MEM_BYTES[a]
    if b and #b >= n then return b end
    return nil
end
function disassemble() return "mov [rcx],eax" end
function debug_setBreakpoint(addr, size, trigger, method, cb) BP_CALLBACKS[addr] = cb end
function debug_removeBreakpoint() end
function debug_continueFromBreakpoint() CONTINUES = CONTINUES + 1 end
print = function() end

-- Cheat Engine's process environment, as seen by os.getenv (tests set CE_ENV.X).
CE_ENV = {}
os.getenv = function(name) return CE_ENV[name] end

-- CE enum constants (vtByte, soExactValue, bptWrite, ...) get unique values.
local nextConst = 1000
setmetatable(_G, { __index = function(t, k)
    if type(k) == "string" and (k:match("^vt%u") or k:match("^so%u") or k:match("^bp[tm]%u")
        or k:match("^fsm%u") or k:match("^rt%u") or k:match("^tsc%u") or k == "co_run") then
        nextConst = nextConst + 1
        rawset(t, k, nextConst)
        return nextConst
    end
end })
