-- ============================================================================
-- Cheat Engine MCP Bridge :: 00_core
-- Shared state, utilities, breakpoint-hit helpers, shared helpers (UNIT-05), zombie cleanup
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local PIPE_NAME = "CE_MCP_Bridge_v99"
local VERSION = "12.3.0"

-- Global State
local serverState = {
    running = false,
    timer = nil,
    pipe = nil,
    connected = false,
    scan_memscan = nil,
    scan_foundlist = nil,
    scan_is_unknown_first = false,   -- last scan_all was an "unknown initial value" first scan
    breakpoints = {},
    breakpoint_hits = {},
    hw_bp_slots = {},      -- Hardware breakpoint slots (max 4)
    active_watches = {},   -- DBVM watch IDs for hypervisor-level tracing
    started_at = os.time(),
    stats = { requests = 0, errors = 0 },   -- updated by executeCommand, reported by bridge_status
    jobs = {},             -- async jobs (UNIT-25)
    job_next_id = 1
}

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

local function toHex(num)
    if not num then return "nil" end
    if math.type(num) == "float" then
        -- string.format("%X") raises on non-integral floats ("number has no
        -- integer representation"), which used to abort the whole command.
        local i = (num == num) and math.tointeger(math.floor(num)) or nil
        if not i then return tostring(num) end
        num = i
    end
    if num >= 0 and num <= 0xFFFFFFFF then
        return string.format("0x%08X", num)
    else
        return string.format("0x%X", num)
    end
end

local function toHexLow32(num)
    if not num then return nil end
    return num & 0xFFFFFFFF
end

local function log(msg)
    print("[MCP v" .. VERSION .. "] " .. msg)
end

-- Universal 32/64-bit architecture helper
-- Returns pointer size, whether target is 64-bit, and current stack/instruction pointers
local function getArchInfo()
    local is64 = targetIs64Bit()
    local ptrSize = is64 and 8 or 4
    local stackPtr = is64 and (RSP or ESP) or ESP
    local instPtr = is64 and (RIP or EIP) or EIP
    return {
        is64bit = is64,
        ptrSize = ptrSize,
        stackPtr = stackPtr,
        instPtr = instPtr
    }
end

-- Universal register capture - works for both 32-bit and 64-bit targets
local function captureRegisters()
    local is64 = targetIs64Bit()
    if is64 then
        return {
            RAX = RAX and toHex(RAX) or nil,
            RBX = RBX and toHex(RBX) or nil,
            RCX = RCX and toHex(RCX) or nil,
            RDX = RDX and toHex(RDX) or nil,
            RSI = RSI and toHex(RSI) or nil,
            RDI = RDI and toHex(RDI) or nil,
            RBP = RBP and toHex(RBP) or nil,
            RSP = RSP and toHex(RSP) or nil,
            RIP = RIP and toHex(RIP) or nil,
            R8 = R8 and toHex(R8) or nil,
            R9 = R9 and toHex(R9) or nil,
            R10 = R10 and toHex(R10) or nil,
            R11 = R11 and toHex(R11) or nil,
            R12 = R12 and toHex(R12) or nil,
            R13 = R13 and toHex(R13) or nil,
            R14 = R14 and toHex(R14) or nil,
            R15 = R15 and toHex(R15) or nil,
            EFLAGS = EFLAGS and toHex(EFLAGS) or nil,
            arch = "x64"
        }
    else
        return {
            EAX = EAX and toHex(EAX) or nil,
            EBX = EBX and toHex(EBX) or nil,
            ECX = ECX and toHex(ECX) or nil,
            EDX = EDX and toHex(EDX) or nil,
            ESI = ESI and toHex(ESI) or nil,
            EDI = EDI and toHex(EDI) or nil,
            EBP = EBP and toHex(EBP) or nil,
            ESP = ESP and toHex(ESP) or nil,
            EIP = EIP and toHex(EIP) or nil,
            EFLAGS = EFLAGS and toHex(EFLAGS) or nil,
            arch = "x86"
        }
    end
end

-- Universal stack capture - reads stack with correct pointer size
local function captureStack(depth)
    local arch = getArchInfo()
    local stack = {}
    local stackPtr = arch.stackPtr
    if not stackPtr then return stack end
    
    -- stack[1] is [SP+0], stack[n] is [SP+(n-1)*ptrSize]. This used to be
    -- 0-based, and the array encoder starts at 1, so [SP+0] (the return
    -- address on a function-entry breakpoint) was silently dropped.
    -- Unreadable slots encode as null so indices stay aligned.
    for i = 0, depth - 1 do
        local val
        if arch.is64bit then
            val = readQword(stackPtr + i * arch.ptrSize)
        else
            val = readInteger(stackPtr + i * arch.ptrSize)
        end
        stack[i + 1] = val and toHex(val) or nil
    end
    return stack
end

-- Pagination helper: parse offset/limit params and slice a table.
-- Returns: limit, offset, page_table, total
-- Usage: local limit, offset, page, total = paginate(params, allItems, 100)
local function paginate(params, items, defaultLimit)
    local limit = math.max(1, math.min(params.limit or params.max or defaultLimit or 100, 10000))
    local offset = math.max(0, params.offset or 0)
    local total = #items
    local page = {}
    for i = offset + 1, math.min(offset + limit, total) do
        page[#page + 1] = items[i]
    end
    return limit, offset, page, total
end

-- Breakpoint hit buffers are ring buffers: only the newest max_hits entries
-- are kept per breakpoint, so a breakpoint on a hot path cannot grow CE's
-- memory without bound or produce a response larger than the frame cap.
local DEFAULT_MAX_BP_HITS = 1000

local function parseMaxHits(value)
    local n = tonumber(value) or DEFAULT_MAX_BP_HITS
    return math.max(1, math.min(math.floor(n), 100000))
end

-- Append a hit for bpId. Creates the buffer lazily: get_breakpoint_hits(clear)
-- may have replaced serverState.breakpoint_hits while the breakpoint is live.
local function recordBreakpointHit(bpId, hitData)
    local hits = serverState.breakpoint_hits[bpId]
    if not hits then
        hits = {}
        serverState.breakpoint_hits[bpId] = hits
    end
    local bp = serverState.breakpoints[bpId]
    local maxHits = (bp and bp.max_hits) or DEFAULT_MAX_BP_HITS
    if bp then
        bp.hit_count = (bp.hit_count or 0) + 1
        hitData.hit_number = bp.hit_count
    end
    hits[#hits + 1] = hitData
    while #hits > maxHits do
        table.remove(hits, 1)
        if bp then bp.dropped_hits = (bp.dropped_hits or 0) + 1 end
    end
end

-- Run a breakpoint's capture function, always resuming the target afterwards.
-- An error inside capture used to skip debug_continueFromBreakpoint and leave
-- the target thread suspended; now it is recorded as a hit with an error field.
local function handleBreakpointHit(bpId, addr, capture)
    local ok, err = pcall(function() recordBreakpointHit(bpId, capture()) end)
    if not ok then
        pcall(recordBreakpointHit, bpId, {
            id = bpId, address = toHex(addr), timestamp = os.time(),
            error = "hit capture failed: " .. tostring(err),
        })
    end
    debug_continueFromBreakpoint(co_run)
    return 1
end

-- Public stats for a breakpoint record (used by list/get_breakpoint_hits).
local function breakpointStats(bp)
    return {
        hit_count = bp.hit_count or 0,
        dropped_hits = bp.dropped_hits or 0,
        max_hits = bp.max_hits or DEFAULT_MAX_BP_HITS,
    }
end

-- Map a human-readable scan_option to a CE scan constant.
-- Returns nil for unrecognized options so callers can report INVALID_PARAMS instead of silently falling back to an exact scan.
-- Global (not local) so handlers defined earlier in the chunk can call it and so it doesn't consume one of Lua's 200 local slots.
function resolveScanOption(opt)
    local o = tostring(opt or "exact"):lower()
    if o == "exact"             then return soExactValue
    elseif o == "unknown"       then return soUnknownValue
    elseif o == "between"       then return soValueBetween
    elseif o == "bigger"        then return soBiggerThan
    elseif o == "smaller"       then return soSmallerThan
    elseif o == "increased"     then return soIncreasedValue
    elseif o == "increased_by"  then return soIncreasedValueBy
    elseif o == "decreased"     then return soDecreasedValue
    elseif o == "decreased_by"  then return soDecreasedValueBy
    elseif o == "changed"       then return soChanged
    elseif o == "unchanged"     then return soUnchanged
    else return nil
    end
end

SCAN_OPTION_NAMES = "exact, unknown, between, bigger, smaller, increased, increased_by, decreased, decreased_by, changed, unchanged"

-- NOTE: "unknown initial value" (soUnknownValue) first scans store candidates
-- per-region (fs_advanced / REGION file header). TFoundList.getCount() returns 0
-- in that mode and the addresses are NOT individually enumerable (GetAddressOnly
-- returns nothing), so the authoritative count is the total scanned addresses —
-- every scanned address is a potential match. UNKNOWN_SCAN_NOTE is attached by the
-- result readers so clients don't mistake the empty result list for a failed scan.
UNKNOWN_SCAN_NOTE = "Unknown initial value scan: candidates are stored per-region and are not individually enumerable. Run a next_scan to narrow them down."
function resolveScanResultCount(ms, fallbackCount)
    local p = ms.getProgress()
    if p and p.TotalAddressesToScan then
        return p.TotalAddressesToScan
    end
    return fallbackCount
end

-- CE's firstScan/nextScan take two inputs; soValueBetween (and the *_by options) need BOTH of them.
-- Passing the bounds as a single "0,1" string with input2 = nil makes CE scan for garbage and return 0 hits.
-- Returns: input1, input2, errorMessage
--   "between" accepts either an explicit value2, or a single value holding both bounds separated by "," or ".." (e.g. "0,1" / "0..1").
--   "-" is deliberately not a separator because it collides with negative numbers.
function resolveScanInputs(scanOpt, value, value2)
    -- Options that compare against the previous scan take no input at all.
    if scanOpt == soUnknownValue or scanOpt == soChanged or scanOpt == soUnchanged
       or scanOpt == soIncreasedValue or scanOpt == soDecreasedValue then
        return nil, nil, nil
    end

    if scanOpt == soValueBetween then
        local lo, hi
        if value2 ~= nil and tostring(value2) ~= "" then
            lo, hi = value, value2
        else
            local s = tostring(value or "")
            lo, hi = s:match("^%s*(.-)%s*,%s*(.-)%s*$")
            if not lo then lo, hi = s:match("^%s*(.-)%s*%.%.%s*(.-)%s*$") end
        end
        if lo == nil or hi == nil or tostring(lo) == "" or tostring(hi) == "" then
            return nil, nil, "'between' needs two bounds: pass value2, or value as \"min,max\" (e.g. \"0,1\")"
        end
        return tostring(lo), tostring(hi), nil
    end

    if value == nil or tostring(value) == "" then
        return nil, nil, "This scan option requires a value"
    end
    return tostring(value), nil, nil
end

-- ============================================================================
-- SHARED HELPERS (Unit 5 refactor — used by multiple cmd_* handlers)
-- ============================================================================
-- >>> BEGIN UNIT-05 Shared helpers <<<

local function parseAddress(input)
    -- Accepts string hex ("0x140001000"), symbol ("game.exe+1000"), or integer.
    -- Returns (address, error) — address nil if invalid.
    if type(input) == "number" then return input, nil end
    if type(input) ~= "string" then return nil, "address must be string or number" end
    local addr = getAddressSafe(input)
    if not addr or addr == 0 then return nil, "Invalid address: " .. tostring(input) end
    return addr, nil
end

-- The one process guard for every unit. Returns true when a process is
-- attached, otherwise false plus a ready-to-return NO_PROCESS error table:
--   local ok, err = requireProcess(); if not ok then return err end
-- (Units used to define their own copies with three different contracts.)
local function requireProcess()
    if (getOpenedProcessID() or 0) == 0 then
        return false, { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    return true, nil
end

local function findModulesViaMZScan(maxCount)
    -- Shared MZ-header AOB scan used by cmd_get_process_info and cmd_enum_modules.
    -- Returns an array of { name, address, size, source } tables.
    maxCount = maxCount or 50
    local moduleList = {}
    local mzScan = AOBScan("4D 5A 90 00 03 00 00 00")
    if mzScan and mzScan.Count > 0 then
        for i = 0, math.min(mzScan.Count - 1, maxCount) do
            local addr = tonumber(mzScan.getString(i), 16)
            if addr then
                local peOffset = readInteger(addr + 0x3C)
                local moduleSize = 0
                local realName = nil

                if peOffset and peOffset > 0 and peOffset < 0x1000 then
                    -- Get Size of Image
                    local sizeOfImage = readInteger(addr + peOffset + 0x50)
                    if sizeOfImage then moduleSize = sizeOfImage end

                    -- TRY TO READ INTERNAL NAME FROM EXPORT DIRECTORY
                    -- PE Header + 0x78 is the Data Directory for Exports (32-bit)
                    local exportRVA = readInteger(addr + peOffset + 0x78)
                    if exportRVA and exportRVA > 0 and exportRVA < 0x10000000 then
                        -- Export Directory + 0x0C is the Name RVA
                        local nameRVA = readInteger(addr + exportRVA + 0x0C)
                        if nameRVA and nameRVA > 0 and nameRVA < 0x10000000 then
                            local name = readString(addr + nameRVA, 64)
                            if name and #name > 0 and #name < 60 then
                                realName = name
                            end
                        end
                    end
                end

                -- Determine module name
                local modName
                if realName then
                    modName = realName
                elseif i == 0 then
                    -- First module is likely main exe - use process name or L2.exe
                    modName = (process ~= "" and process) or "L2.exe"
                else
                    modName = "Module_" .. string.format("%X", addr)
                end

                table.insert(moduleList, {
                    name = modName,
                    address = toHex(addr),
                    size = moduleSize,
                    source = realName and "export_directory" or "aob_fallback"
                })
            end
        end
        mzScan.destroy()
    end
    return moduleList
end

local function findFunctionPrologue(addr, maxSearch)
    -- Searches backward from addr for a function prologue (x86: "55 8B EC" / x64: "55 48 89 E5" / "48 83 EC xx").
    -- Returns (prologueAddress, prologueType) or (nil, nil).
    maxSearch = maxSearch or 4096
    local is64 = targetIs64Bit()
    local funcStart = nil
    local prologueType = nil
    for offset = 0, maxSearch do
        local checkAddr = addr - offset
        local b1 = readBytes(checkAddr, 1, false)
        local b2 = readBytes(checkAddr + 1, 1, false)
        local b3 = readBytes(checkAddr + 2, 1, false)
        local b4 = readBytes(checkAddr + 3, 1, false)

        -- 32-bit prologue: push ebp; mov ebp, esp (55 8B EC)
        if b1 == 0x55 and b2 == 0x8B and b3 == 0xEC then
            funcStart = checkAddr
            prologueType = "x86_standard"
            break
        end

        -- 64-bit prologue: push rbp; mov rbp, rsp (55 48 89 E5)
        if is64 and b1 == 0x55 and b2 == 0x48 and b3 == 0x89 and b4 == 0xE5 then
            funcStart = checkAddr
            prologueType = "x64_standard"
            break
        end

        -- 64-bit alternative: sub rsp, imm8 (48 83 EC xx) - common in leaf functions
        if is64 and b1 == 0x48 and b2 == 0x83 and b3 == 0xEC then
            funcStart = checkAddr
            prologueType = "x64_leaf"
            break
        end
    end
    return funcStart, prologueType
end

-- >>> END UNIT-05 <<<

-- ============================================================================
-- CLEANUP & SAFETY ROUTINES (CRITICAL FOR ROBUSTNESS)
-- ============================================================================
-- Prevents "zombie" breakpoints and DBVM watches when script is reloaded

-- mapMemory() returns (address, mdl); unmapMemory() needs the mdl to release it.
-- Owned by the kernel module (UNIT-21); declared here so cleanupZombieState can
-- release the mappings on bridge stop/restart.
local mappedMemoryMDL = {}

-- Resources owned by later modules register their cleanup here instead of editing cleanupZombieState.
--   early: runs first. A thread left stopped by a break-and-inspect breakpoint must be resumed before anything is torn down.
--   jobs:  runs before the scan objects are destroyed: a running next_scan job shares serverState.scan_memscan,
--          which step 3 destroys (it must never be destroyed twice).
local cleanupHooks = { early = {}, jobs = {} }

local function cleanupZombieState()
    log("Cleaning up zombie resources...")
    local cleaned = { breakpoints = 0, dbvm_watches = 0, scans = 0 }

    for _, hook in ipairs(cleanupHooks.early) do pcall(hook) end
    
    -- 1. Remove all Hardware Breakpoints managed by us
    if serverState.breakpoints then
        for id, bp in pairs(serverState.breakpoints) do
            if bp.address then
                local ok = pcall(function() debug_removeBreakpoint(bp.address) end)
                if ok then cleaned.breakpoints = cleaned.breakpoints + 1 end
            end
        end
    end
    
    -- 2. Stop all DBVM Watches
    if serverState.active_watches then
        for key, watch in pairs(serverState.active_watches) do
            if watch.id then
                local ok = pcall(function() dbvm_watch_disable(watch.id) end)
                if ok then cleaned.dbvm_watches = cleaned.dbvm_watches + 1 end
            end
        end
    end

    for _, hook in ipairs(cleanupHooks.jobs) do pcall(hook) end

    -- 3. Cleanup Scan memory objects
    if serverState.scan_memscan then
        pcall(function() serverState.scan_memscan.destroy() end)
        serverState.scan_memscan = nil
        cleaned.scans = cleaned.scans + 1
    end
    if serverState.scan_foundlist then
        pcall(function() serverState.scan_foundlist.destroy() end)
        serverState.scan_foundlist = nil
    end
    serverState.scan_is_unknown_first = false

    -- 4. Cleanup persistent scans (Unit 15)
    if serverState.persistent_scans then
        for name, entry in pairs(serverState.persistent_scans) do
            if entry then
                if entry.fl then pcall(function() entry.fl.destroy() end) end
                pcall(function() entry.ms.destroy() end)
                cleaned.scans = cleaned.scans + 1
            end
        end
    end

    -- Reset all tracking tables
    serverState.breakpoints = {}
    serverState.breakpoint_hits = {}
    serverState.hw_bp_slots = {}
    serverState.active_watches = {}

    -- 4. Release any mapped memory MDL handles (Unit-21)
    if mappedMemoryMDL then
        for key, mdl in pairs(mappedMemoryMDL) do
            pcall(function() unmapMemory(getAddressSafe(key) or 0, mdl) end)
        end
        -- mappedMemoryMDL is module-level, reassign to clear it
        for k in pairs(mappedMemoryMDL) do mappedMemoryMDL[k] = nil end
    end

    serverState.persistent_scans = {}
    
    if cleaned.breakpoints > 0 or cleaned.dbvm_watches > 0 or cleaned.scans > 0 then
        log(string.format("Cleaned: %d breakpoints, %d DBVM watches, %d scans",
            cleaned.breakpoints, cleaned.dbvm_watches, cleaned.scans))
    end

    -- Extension point (reserved for additive units 7-23):
    -- If you add new long-lived resources to serverState (persistent scans,
    -- custom symbols, injected code caves, etc.), register their cleanup here
    -- so script reload doesn't leak them.

    return cleaned
end

-- >>> exports
B.PIPE_NAME = PIPE_NAME
B.VERSION = VERSION
B.serverState = serverState
B.toHex = toHex
B.toHexLow32 = toHexLow32
B.log = log
B.getArchInfo = getArchInfo
B.captureRegisters = captureRegisters
B.captureStack = captureStack
B.paginate = paginate
B.DEFAULT_MAX_BP_HITS = DEFAULT_MAX_BP_HITS
B.parseMaxHits = parseMaxHits
B.recordBreakpointHit = recordBreakpointHit
B.handleBreakpointHit = handleBreakpointHit
B.breakpointStats = breakpointStats
B.parseAddress = parseAddress
B.requireProcess = requireProcess
B.findModulesViaMZScan = findModulesViaMZScan
B.findFunctionPrologue = findFunctionPrologue
B.mappedMemoryMDL = mappedMemoryMDL
B.cleanupHooks = cleanupHooks
B.cleanupZombieState = cleanupZombieState
