-- ============================================================================
-- Cheat Engine MCP Bridge :: 06_breakpoints
-- Hardware breakpoints, conditions, break-and-inspect (UNIT-27)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local serverState = B.serverState
local toHex = B.toHex
local log = B.log
local getArchInfo = B.getArchInfo
local captureRegisters = B.captureRegisters
local captureStack = B.captureStack
local paginate = B.paginate
local parseMaxHits = B.parseMaxHits
local recordBreakpointHit = B.recordBreakpointHit
local breakpointStats = B.breakpointStats
local requireProcess = B.requireProcess
local cleanupHooks = B.cleanupHooks

-- ============================================================================
-- COMMAND HANDLERS - BREAKPOINTS
-- ============================================================================

-- Clears any hw_bp_slots entry (and its tracking tables) whose address matches
-- addr, so the slot is available for re-use without leaving a stale entry behind.
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

-- Breakpoint control lives in one table: this chunk is close to CE's 200-locals limit.
--   condition  : sandboxed expression over the registers (RAX, ...), memory readers (u32(addr), ptr(addr), f32(addr) ...)
--                and hits()/seen(); numeric only (no strings, `..`, `:` or brackets, see BPX.compile) and run under
--                an instruction budget, so it can neither hang the target nor exhaust CE's memory
--   stop_after_hits : detach after N matching hits (max_hits is the size of the hit ring buffer, see 00_core)
--   mode=break : leave the thread stopped (break-and-inspect); a watchdog resumes it after halt_timeout_ms
local BPX = { HALT_DEFAULT_MS = 10000, HALT_MAX_MS = 300000, HALT_HARD_LIMIT_S = 600,
              CONDITION_INSTRUCTION_LIMIT = 200000, MAX_CONDITION_ERRORS = 5, MAX_INSPECT = 8 }

-- Hit callbacks MUST reach debug_continueFromBreakpoint, otherwise the target thread stays halted. The body runs under
-- pcall and the thread always continues - except for a break-and-inspect hit, where the body returns "halt" and the thread
-- is left stopped. A body that raises is recorded as a hit with an error field (same as handleBreakpointHit).
-- What CE does with the callback's return value (measured in a live CE, see tests/live_smoke.py): nil, false, true and
-- 0 all make CE resume the thread by itself; a NON-ZERO number (1, 2) means "the script took care of it" and CE leaves
-- the thread stopped. So both paths return 1: the normal one after continuing explicitly, the halt one without.
function BPX.safeCallback(bpId, addr, body)
    return function()
        local ok, result = pcall(body)
        if not ok then
            log("Breakpoint callback error: " .. tostring(result))
            pcall(recordBreakpointHit, bpId, {
                id = bpId, address = toHex(addr), timestamp = os.time(),
                error = "hit capture failed: " .. tostring(result),
            })
        end
        if ok and result == "halt" then return 1 end
        debug_continueFromBreakpoint(co_run)
        return 1
    end
end

BPX.REGISTER_NAMES = {}
for _, n in ipairs({ "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                     "EFLAGS", "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP" }) do
    BPX.REGISTER_NAMES[n] = true
end

function BPX.readNum(addr, size, fmt)
    local ok, bytes = pcall(readBytes, addr, size, true)
    if not ok or not bytes or #bytes ~= size then return nil end
    return (string.unpack(fmt, string.char(table.unpack(bytes))))
end

function BPX.readValue(addr, size)
    return BPX.readNum(addr, size, ({ [1] = "<I1", [2] = "<I2", [4] = "<I4", [8] = "<I8" })[size])
end

-- The only globals a condition can see: registers (CE publishes them while the thread is stopped), memory readers
-- that return nil for unreadable memory, and a few math helpers.
function BPX.makeEnv(bp)
    local env = {}
    for name, spec in pairs({ u8 = { 1, "<I1" }, u16 = { 2, "<I2" }, u32 = { 4, "<I4" }, u64 = { 8, "<I8" },
                              i8 = { 1, "<i1" }, i16 = { 2, "<i2" }, i32 = { 4, "<i4" }, i64 = { 8, "<i8" },
                              f32 = { 4, "<f" }, f64 = { 8, "<d" } }) do
        env[name] = function(a)
            if math.type(a) ~= "integer" then return nil end
            return BPX.readNum(a, spec[1], spec[2])
        end
    end
    env.ptr = targetIs64Bit() and env.u64 or env.u32
    env.hits = function() return bp.hit_count or 0 end
    env.seen = function() return bp.seen_hits or 0 end
    env.abs, env.min, env.max, env.floor = math.abs, math.min, math.max, math.floor
    return setmetatable(env, { __index = function(_, k)
        if type(k) == "string" then
            local up = k:upper()
            if BPX.REGISTER_NAMES[up] then return _G[up] end
        end
    end })
end

function BPX.compile(expr, bp)
    if type(expr) ~= "string" or expr == "" then return nil, "empty expression" end
    if #expr > 500 then return nil, "expression is longer than 500 characters" end
    -- A string value reaches the string library through the string metatable, which the empty environment does not
    -- hide: ("a"):rep(1 << 30) allocates a gigabyte inside CE in a single C call, past the instruction budget.
    -- Conditions are numeric, so refuse every way of making a string (literals, `..`) or calling a method on one.
    if expr:find("[\"'%[%]:]") or expr:find("..", 1, true) then
        return nil, "strings, '..', ':' and brackets are not allowed in a condition"
    end
    local fn, err = load("return (" .. expr .. ")", "=expr", "t", BPX.makeEnv(bp))
    if not fn then return nil, tostring(err) end
    return fn
end

-- Run a compiled expression under an instruction budget (a `while true do end` inside it would otherwise hang the target).
function BPX.run(fn)
    local hookable = type(debug) == "table" and type(debug.sethook) == "function"
    if hookable then
        debug.sethook(function() error("expression exceeded its instruction budget", 2) end, "", BPX.CONDITION_INSTRUCTION_LIMIT)
    end
    local ok, res = pcall(fn)
    if hookable then debug.sethook() end
    return ok, res
end

-- Should this hit be recorded?  Returns pass, conditionError. A failing condition records the hit (flagged) so the
-- failure is visible, and is switched off after MAX_CONDITION_ERRORS failures.
function BPX.test(bp)
    if not bp.condition_fn then return true end
    local ok, res = BPX.run(bp.condition_fn)
    if not ok then
        bp.condition_errors = (bp.condition_errors or 0) + 1
        bp.last_condition_error = tostring(res)
        if bp.condition_errors >= BPX.MAX_CONDITION_ERRORS then
            bp.condition_fn, bp.condition_disabled = nil, true
        end
        return true, tostring(res)
    end
    return (res ~= nil and res ~= false and res ~= 0), nil
end

function BPX.detach(bpId)
    local bp = serverState.breakpoints[bpId]
    if not bp or bp.detached then return end
    pcall(function() debug_removeBreakpoint(bp.address) end)
    if bp.slot then
        serverState.hw_bp_slots[bp.slot] = nil
        bp.slot = nil
    end
    bp.detached = true
end

-- Detaching from inside the breakpoint's own callback is risky, so defer it to the main loop when CE offers queue().
function BPX.scheduleDetach(bpId)
    if type(queue) == "function" and pcall(queue, function() BPX.detach(bpId) end) then return end
    BPX.detach(bpId)
end

function BPX.readInspect(bp)
    local out = {}
    for i, spec in ipairs(bp.inspect or {}) do
        local ok, addr = BPX.run(spec.fn)
        local entry = { expr = spec.expr, size = spec.size }
        if ok and math.type(addr) == "integer" then
            entry.address = toHex(addr)
            local okR, bytes = pcall(readBytes, addr, spec.size, true)
            if okR and bytes then
                local hex = {}
                for k, b in ipairs(bytes) do hex[k] = string.format("%02X", b) end
                entry.hex = table.concat(hex, " ")
            else
                entry.error = "unreadable"
            end
        else
            entry.error = "expression failed: " .. tostring(addr)
        end
        out[i] = entry
    end
    return out
end

-- ---- break-and-inspect --------------------------------------------------------------------------------
function BPX.halt(bpId, bp, hit)
    local now = os.clock()
    local arch = getArchInfo()
    serverState.halted = {
        id = bpId, since = now, timeout_ms = bp.halt_timeout_ms, deadline = now + bp.halt_timeout_ms / 1000,
        hard_deadline = now + BPX.HALT_HARD_LIMIT_S, steps = 0, hit = hit,
        registers = captureRegisters(), stack = captureStack(16), memory = BPX.readInspect(bp),
        instruction = arch.instPtr and disassemble(arch.instPtr) or nil,
    }
    if BPX.ensurePump then BPX.ensurePump() end      -- the pump timer hosts the watchdog
end

function BPX.resume(reason)
    local h = serverState.halted
    if not h then return nil end
    pcall(debug_continueFromBreakpoint, co_run)
    serverState.halted = nil
    serverState.last_halt = { breakpoint = h.id, reason = reason, halted_seconds = os.clock() - h.since, steps = h.steps }
    return h
end

-- Called from the pump timer. Resumes a halted thread whose client went away; returns true while one is still halted.
function BPX.watchdog()
    local h = serverState.halted
    if not h then return false end
    local now = os.clock()
    if now >= h.deadline or now >= h.hard_deadline then
        BPX.resume(now >= h.hard_deadline and "hard limit reached" or "timeout")
        local bp = serverState.breakpoints[h.id]
        if bp then bp.auto_resumed = (bp.auto_resumed or 0) + 1 end
        return false
    end
    return true
end

-- One hit: condition -> record -> stop_after_hits -> optionally halt. Returns "halt" to leave the thread stopped.
function BPX.handle(bpId, buildHit)
    local bp = serverState.breakpoints[bpId]
    if not bp then return nil end                          -- removed while the hit was in flight
    bp.seen_hits = (bp.seen_hits or 0) + 1
    if bp.completed then return nil end                    -- stop_after_hits reached, waiting for the deferred detach
    local pass, condErr = BPX.test(bp)
    if not pass then
        bp.filtered_hits = (bp.filtered_hits or 0) + 1
        return nil
    end
    local hit = buildHit(bp)
    if hit == nil then
        bp.filtered_hits = (bp.filtered_hits or 0) + 1
        return nil
    end
    if condErr then hit.condition_error = condErr end
    recordBreakpointHit(bpId, hit)
    if bp.stop_after and (bp.hit_count or 0) >= bp.stop_after then
        bp.completed = true
        BPX.scheduleDetach(bpId)
    end
    if bp.mode == "break" and not serverState.halted then
        BPX.halt(bpId, bp, hit)
        return "halt"
    end
    return nil
end

function BPX.invalid(msg)
    return { success = false, error = msg, error_code = "INVALID_PARAMS" }
end

-- Shared by set_breakpoint (kind "execute") and set_data_breakpoint (kind "data").
function BPX.install(kind, params)
    local okProc, perr = requireProcess()
    if not okProc then return perr end
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    local mode = params.mode or "log"
    if mode ~= "log" and mode ~= "break" then return BPX.invalid("mode must be 'log' or 'break'") end
    local stopAfter
    if params.stop_after_hits ~= nil then
        stopAfter = math.tointeger(tonumber(params.stop_after_hits))
        if not stopAfter or stopAfter < 1 then return BPX.invalid("stop_after_hits must be a positive integer") end
    end
    local haltMs = math.max(100, math.min(tonumber(params.halt_timeout_ms) or BPX.HALT_DEFAULT_MS, BPX.HALT_MAX_MS))

    local size, accessType, trigger = 1, nil, bptExecute
    if kind == "data" then
        accessType = params.access_type or "w"
        if accessType ~= "r" and accessType ~= "w" and accessType ~= "rw" then return BPX.invalid("access_type must be 'r', 'w' or 'rw'") end
        size = math.tointeger(tonumber(params.size or 4)) or 0
        if size ~= 1 and size ~= 2 and size ~= 4 and size ~= 8 then return BPX.invalid("size must be 1, 2, 4 or 8") end
        if addr % size ~= 0 then
            return BPX.invalid(string.format("a %d-byte hardware data breakpoint must be %d-byte aligned; %s is not", size, size, toHex(addr)))
        end
        trigger = (accessType == "w") and bptWrite or bptAccess     -- x86 debug registers cannot watch reads only
    end

    local bpId = params.id or tostring(addr)
    if serverState.breakpoints[bpId] then
        local suffix = 2
        while serverState.breakpoints[bpId .. "_" .. suffix] do suffix = suffix + 1 end
        bpId = bpId .. "_" .. suffix
    end

    local bp = { address = addr, type = (kind == "data") and "data" or "execute", mode = mode, stop_after = stopAfter, max_hits = parseMaxHits(params.max_hits),
                 halt_timeout_ms = haltMs, size = size, access_type = accessType, created = os.time() }
    if params.condition ~= nil and params.condition ~= "" then
        local fn, err = BPX.compile(params.condition, bp)
        if not fn then return BPX.invalid("Invalid condition: " .. tostring(err)) end
        bp.condition, bp.condition_fn = params.condition, fn
    end
    if params.inspect ~= nil then
        if mode ~= "break" then return BPX.invalid("inspect only applies to mode 'break'") end
        if type(params.inspect) ~= "table" or #params.inspect > BPX.MAX_INSPECT then
            return BPX.invalid("inspect must be a list of at most " .. BPX.MAX_INSPECT .. " {expr, size} entries")
        end
        bp.inspect = {}
        for i, spec in ipairs(params.inspect) do
            local fn, err = BPX.compile(type(spec) == "table" and spec.expr or nil, bp)
            if not fn then return BPX.invalid("inspect[" .. i .. "]: " .. tostring(err)) end
            bp.inspect[i] = { expr = spec.expr, fn = fn, size = math.max(1, math.min(math.tointeger(tonumber(spec.size)) or 16, 256)) }
        end
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

    if kind == "execute" then
        -- Remove existing breakpoint at this address
        pcall(function() debug_removeBreakpoint(addr) end)
    else
        bp.last_value = BPX.readValue(addr, size)       -- baseline for value_changed / read filtering
    end

    bp.slot = slot
    serverState.breakpoint_hits[bpId] = {}
    serverState.breakpoints[bpId] = bp
    serverState.hw_bp_slots[slot] = { id = bpId, address = addr }

    local captureRegs = params.capture_registers ~= false
    local captureStackFlag = params.capture_stack or false
    local stackDepth = params.stack_depth or 16

    local function buildExecuteHit(b)
        local hit = { id = bpId, address = toHex(addr), timestamp = os.time(), breakpoint_type = "hardware_execute" }
        if captureRegs then hit.registers = captureRegisters() end
        if captureStackFlag then hit.stack = captureStack(stackDepth) end
        return hit
    end

    local function buildDataHit(b)
        local arch = getArchInfo()
        local value = BPX.readValue(addr, size)
        local prev = b.last_value
        b.last_value = value
        -- 'r' can only be approximated (the CPU reports reads and writes): a changed value means that was a write
        if accessType == "r" and prev ~= nil and value ~= prev then return nil end
        local changed                                   -- not `x and y or nil`: that turns false into nil
        if prev ~= nil and value ~= nil then changed = (value ~= prev) end
        local instPtr = arch.instPtr
        return {
            id = bpId, type = "data_" .. accessType, address = toHex(addr), size = size, timestamp = os.time(),
            breakpoint_type = "hardware_data", value = value, previous_value = prev,
            value_changed = changed,
            registers = captureRegisters(), instruction = instPtr and disassemble(instPtr) or "???",
            arch = arch.is64bit and "x64" or "x86",
        }
    end

    -- CRITICAL: Use bpmDebugRegister for hardware breakpoints (anti-cheat safe)
    -- Signature: debug_setBreakpoint(address, size, trigger, breakpointmethod, function)
    local build = (kind == "data") and buildDataHit or buildExecuteHit
    local ok, err = pcall(debug_setBreakpoint, addr, size, trigger, bpmDebugRegister,
                          BPX.safeCallback(bpId, addr, function() return BPX.handle(bpId, build) end))
    if not ok then
        serverState.breakpoints[bpId] = nil
        serverState.breakpoint_hits[bpId] = nil
        serverState.hw_bp_slots[slot] = nil
        return { success = false, error = "debug_setBreakpoint failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end

    local out = { success = true, id = bpId, address = toHex(addr), slot = slot, method = "hardware_debug_register", mode = mode,
                  condition = bp.condition, stop_after_hits = stopAfter, max_hits = bp.max_hits }
    if mode == "break" then out.halt_timeout_ms = haltMs end
    if kind == "data" then
        out.access_type, out.size = accessType, size
        if accessType == "r" then
            out.note = "x86 debug registers cannot watch reads only: this watches read+write and drops hits where the value changed (a write). A write of the identical value looks like a read."
        end
    end
    return out
end

function cmd_set_breakpoint(params)
    return BPX.install("execute", params)
end

function cmd_set_data_breakpoint(params)
    return BPX.install("data", params)
end

function cmd_remove_breakpoint(params)
    local bpId = params.id

    if bpId and serverState.breakpoints[bpId] then
        local bp = serverState.breakpoints[bpId]
        if serverState.halted and serverState.halted.id == bpId then BPX.resume("breakpoint removed") end
        if not bp.detached then
            pcall(function() debug_removeBreakpoint(bp.address) end)
        end

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
        local state = "active"
        if bp.completed then state = "completed" end
        if serverState.halted and serverState.halted.id == id then state = "halted" end
        local entry = {
            id = id,
            address = toHex(bp.address),
            type = bp.type or "execution",
            slot = bp.slot,
            state = state,
            mode = bp.mode or "log",
            buffered_hits = #(serverState.breakpoint_hits[id] or {}),
            seen_hits = bp.seen_hits or 0,
            filtered_hits = bp.filtered_hits or 0,
            condition = bp.condition,
            condition_errors = bp.condition_errors,
            condition_disabled = bp.condition_disabled,
            stop_after_hits = bp.stop_after,
            size = bp.size,
            access_type = bp.access_type,
            auto_resumed = bp.auto_resumed,
        }
        for k, v in pairs(breakpointStats(bp)) do entry[k] = v end
        table.insert(list, entry)
    end
    return { success = true, count = #list, breakpoints = list }
end

function cmd_clear_all_breakpoints(params)
    local count = 0
    if serverState.halted then BPX.resume("all breakpoints cleared") end
    for id, bp in pairs(serverState.breakpoints) do
        if not bp.detached then
            pcall(function() debug_removeBreakpoint(bp.address) end)
        end
        count = count + 1
    end
    serverState.breakpoints = {}
    serverState.breakpoint_hits = {}
    serverState.hw_bp_slots = {}
    return { success = true, removed = count }
end

-- State of a thread stopped by a mode="break" breakpoint (or by stepping from one): fresh registers, the instruction,
-- stack, the memory the breakpoint asked to inspect and the time left before the watchdog resumes it.
-- Resume with debug_continue (run / step_into / step_over). `extend_ms` postpones the watchdog.
function cmd_get_halted_state(params)
    local h = serverState.halted
    if not h then
        return { success = true, halted = false, last_halt = serverState.last_halt }
    end
    local now = os.clock()
    local okB, broken = pcall(debug_isBroken)
    local grace = h.stepping and (now - (h.step_started or 0)) < 2
    if okB and not broken and not grace then
        serverState.halted = nil
        serverState.last_halt = { breakpoint = h.id, reason = "resumed outside the bridge", halted_seconds = now - h.since, steps = h.steps }
        return { success = true, halted = false, note = "The thread was resumed outside the bridge (Cheat Engine's UI?).", last_halt = serverState.last_halt }
    end
    if params.extend_ms then
        local ms = math.max(0, math.min(tonumber(params.extend_ms) or 0, BPX.HALT_MAX_MS))
        h.deadline = math.min(now + ms / 1000, h.hard_deadline)
    end
    pcall(debug_getContext, true)             -- the register globals are only valid after a refresh
    local arch = getArchInfo()
    local depth = math.max(1, math.min(tonumber(params.stack_depth) or 16, 256))
    return {
        success = true, halted = true, breakpoint = h.id, stepping = h.stepping or false, steps = h.steps,
        halted_seconds = now - h.since, auto_resume_in_seconds = math.max(0, h.deadline - now),
        registers = captureRegisters(), instruction = arch.instPtr and disassemble(arch.instPtr) or nil,
        stack = captureStack(depth), memory = h.memory, hit = (not h.stepping) and h.hit or nil,
    }
end

-- A thread stopped by a break-and-inspect breakpoint must not stay stopped when the bridge goes away.
cleanupHooks.early[#cleanupHooks.early + 1] = function()
    if serverState.halted then
        pcall(debug_continueFromBreakpoint, co_run)
        serverState.halted = nil
    end
end

-- >>> exports
B.clearGhostBpSlot = clearGhostBpSlot
B.BPX = BPX
