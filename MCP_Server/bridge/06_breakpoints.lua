-- ============================================================================
-- Cheat Engine MCP Bridge :: 06_breakpoints
-- Hardware breakpoints
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local serverState = B.serverState
local toHex = B.toHex
local getArchInfo = B.getArchInfo
local captureRegisters = B.captureRegisters
local captureStack = B.captureStack
local paginate = B.paginate
local parseMaxHits = B.parseMaxHits
local handleBreakpointHit = B.handleBreakpointHit
local breakpointStats = B.breakpointStats

-- ============================================================================
-- COMMAND HANDLERS - BREAKPOINTS
-- ============================================================================

-- Clears any hw_bp_slots entry (and its tracking tables) whose address matches
-- addr, so the slot is available for re-use without leaking the old entry.
local function clearGhostBpSlot(addr)
    for i = 1, 4 do
        if serverState.hw_bp_slots[i] and serverState.hw_bp_slots[i].address == addr then
            local oldId = serverState.hw_bp_slots[i].id
            serverState.hw_bp_slots[i] = nil
            if oldId then
                serverState.breakpoints[oldId] = nil
                serverState.breakpoint_hits[oldId] = nil
            end
        end
    end
end

function cmd_set_breakpoint(params)
    local addr = params.address
    local bpId = params.id
    local captureRegs = params.capture_registers ~= false
    local captureStackFlag = params.capture_stack or false
    local stackDepth = params.stack_depth or 16
    local maxHits = parseMaxHits(params.max_hits)

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    bpId = bpId or tostring(addr)
    -- Avoid collision if an existing breakpoint has the same ID
    if serverState.breakpoints[bpId] then
        local suffix = 2
        while serverState.breakpoints[bpId .. "_" .. suffix] do suffix = suffix + 1 end
        bpId = bpId .. "_" .. suffix
    end

    clearGhostBpSlot(addr)

    -- Find free hardware slot (max 4 debug registers)
    local slot = nil
    for i = 1, 4 do
        if not serverState.hw_bp_slots[i] then
            slot = i
            break
        end
    end

    if not slot then
        return { success = false, error = "No free hardware breakpoint slots (max 4 debug registers)", error_code = "OUT_OF_RESOURCES" }
    end

    -- Remove existing breakpoint at this address
    pcall(function() debug_removeBreakpoint(addr) end)

    serverState.breakpoint_hits[bpId] = {}
    
    -- CRITICAL: Use bpmDebugRegister for hardware breakpoints (anti-cheat safe)
    -- Signature: debug_setBreakpoint(address, size, trigger, breakpointmethod, function)
    debug_setBreakpoint(addr, 1, bptExecute, bpmDebugRegister, function()
        return handleBreakpointHit(bpId, addr, function()
            local hitData = {
                id = bpId,
                address = toHex(addr),
                timestamp = os.time(),
                breakpoint_type = "hardware_execute"
            }
            if captureRegs then
                hitData.registers = captureRegisters()
            end
            if captureStackFlag then
                hitData.stack = captureStack(stackDepth)
            end
            return hitData
        end)
    end)

    serverState.hw_bp_slots[slot] = { id = bpId, address = addr }
    serverState.breakpoints[bpId] = { address = addr, slot = slot, type = "execute", max_hits = maxHits }
    return { success = true, id = bpId, address = toHex(addr), slot = slot, max_hits = maxHits, method = "hardware_debug_register" }
end

function cmd_set_data_breakpoint(params)
    local addr = params.address
    local bpId = params.id
    local accessType = params.access_type or "w"  -- r, w, rw
    local size = params.size or 4
    local maxHits = parseMaxHits(params.max_hits)

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    bpId = bpId or tostring(addr)
    -- Avoid collision if an existing breakpoint has the same ID
    if serverState.breakpoints[bpId] then
        local suffix = 2
        while serverState.breakpoints[bpId .. "_" .. suffix] do suffix = suffix + 1 end
        bpId = bpId .. "_" .. suffix
    end

    clearGhostBpSlot(addr)

    -- Find free hardware slot (max 4 debug registers)
    local slot = nil
    for i = 1, 4 do
        if not serverState.hw_bp_slots[i] then
            slot = i
            break
        end
    end

    if not slot then
        return { success = false, error = "No free hardware breakpoint slots (max 4 debug registers)", error_code = "OUT_OF_RESOURCES" }
    end

    local bpType = bptWrite
    if accessType == "r" then bpType = bptAccess
    elseif accessType == "rw" then bpType = bptAccess end
    
    serverState.breakpoint_hits[bpId] = {}
    
    -- CRITICAL: Use bpmDebugRegister for hardware breakpoints (anti-cheat safe)
    -- Signature: debug_setBreakpoint(address, size, trigger, breakpointmethod, function)
    debug_setBreakpoint(addr, size, bpType, bpmDebugRegister, function()
        return handleBreakpointHit(bpId, addr, function()
            local arch = getArchInfo()
            local instPtr = arch.instPtr
            return {
                id = bpId,
                type = "data_" .. accessType,
                address = toHex(addr),
                timestamp = os.time(),
                breakpoint_type = "hardware_data",
                value = arch.is64bit and readQword(addr) or readInteger(addr),
                registers = captureRegisters(),
                instruction = instPtr and disassemble(instPtr) or "???",
                arch = arch.is64bit and "x64" or "x86"
            }
        end)
    end)

    serverState.hw_bp_slots[slot] = { id = bpId, address = addr }
    serverState.breakpoints[bpId] = { address = addr, slot = slot, type = "data", max_hits = maxHits }

    return { success = true, id = bpId, address = toHex(addr), slot = slot, access_type = accessType, max_hits = maxHits, method = "hardware_debug_register" }
end

function cmd_remove_breakpoint(params)
    local bpId = params.id
    
    if bpId and serverState.breakpoints[bpId] then
        local bp = serverState.breakpoints[bpId]
        pcall(function() debug_removeBreakpoint(bp.address) end)
        
        if bp.slot then
            serverState.hw_bp_slots[bp.slot] = nil
        end
        
        serverState.breakpoints[bpId] = nil
        return { success = true, id = bpId }
    end
    
    return { success = false, error = "Breakpoint not found: " .. tostring(bpId), error_code = "NOT_FOUND" }
end

function cmd_get_breakpoint_hits(params)
    local bpId = params.id
    local clear = params.clear ~= false

    local hits
    if bpId then
        hits = serverState.breakpoint_hits[bpId] or {}
        if clear then serverState.breakpoint_hits[bpId] = {} end
    else
        hits = {}
        for id, hitsForBp in pairs(serverState.breakpoint_hits) do
            for _, hit in ipairs(hitsForBp) do
                hits[#hits + 1] = hit
            end
        end
        if clear then serverState.breakpoint_hits = {} end
    end

    local limit, offset, page, total = paginate(params, hits, 100)
    local result = { success = true, total = total, offset = offset, limit = limit, returned = #page, hits = page }
    if bpId then
        local bp = serverState.breakpoints[bpId]
        if bp then
            for k, v in pairs(breakpointStats(bp)) do result[k] = v end
        end
    else
        local stats = {}
        for id, bp in pairs(serverState.breakpoints) do stats[tostring(id)] = breakpointStats(bp) end
        if next(stats) then result.stats = stats end
    end
    return result
end

function cmd_list_breakpoints(params)
    local list = {}
    for id, bp in pairs(serverState.breakpoints) do
        local entry = {
            id = id,
            address = toHex(bp.address),
            type = bp.type or "execution",
            slot = bp.slot
        }
        for k, v in pairs(breakpointStats(bp)) do entry[k] = v end
        table.insert(list, entry)
    end
    return { success = true, count = #list, breakpoints = list }
end

function cmd_clear_all_breakpoints(params)
    local count = 0
    for id, bp in pairs(serverState.breakpoints) do
        pcall(function() debug_removeBreakpoint(bp.address) end)
        count = count + 1
    end
    serverState.breakpoints = {}
    serverState.breakpoint_hits = {}
    serverState.hw_bp_slots = {}
    return { success = true, removed = count }
end

-- >>> exports
B.clearGhostBpSlot = clearGhostBpSlot
