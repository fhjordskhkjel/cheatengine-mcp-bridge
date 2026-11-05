-- ============================================================================
-- Cheat Engine MCP Bridge :: 25_operations
-- Operations: bridge_status, read_struct, batch, async jobs (UNIT-25)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local BPX = B.BPX
local cleanupHooks = B.cleanupHooks
local PIPE_NAME = B.PIPE_NAME
local USER_MODE_MAX = B.USER_MODE_MAX
local VERSION = B.VERSION
local bytesToString = B.bytesToString
local commitFirstScan = B.commitFirstScan
local commitNextScan = B.commitNextScan
local log = B.log
local paginate = B.paginate
local prepareFirstScan = B.prepareFirstScan
local prepareNextScan = B.prepareNextScan
local requireProcess = B.requireProcess
local scanBusyError = B.scanBusyError
local serverState = B.serverState
local toHex = B.toHex

-- >>> BEGIN UNIT-25 Operations: bridge_status, read_struct, batch, async jobs <<<

local function countKeys(tbl)
    local n = 0
    for _ in pairs(tbl or {}) do n = n + 1 end
    return n
end

-- ---------------------------------------------------------------------------
-- bridge_status: one-call health/diagnostics report
-- ---------------------------------------------------------------------------
function cmd_bridge_status(params)
    local warnings = {}
    local info = {
        success = true,
        version = VERSION,
        pipe = PIPE_NAME,
        uptime_seconds = os.time() - (serverState.started_at or os.time()),
        client_connected = serverState.connected and true or false,
        tools_registered = countKeys(serverState.dispatch),
    }

    local okVer, ceVer = pcall(getCEVersion)
    if okVer then info.ce_version = ceVer end

    local okProc, pinfo = pcall(cmd_get_process_info, {})
    local proc = { attached = false }
    if okProc and type(pinfo) == "table" and pinfo.success then
        proc = {}
        for k, v in pairs(pinfo) do if k ~= "success" then proc[k] = v end end
        proc.attached = true
    else
        warnings[#warnings + 1] = "No process attached to Cheat Engine; memory tools will return NO_PROCESS."
    end
    info.process = proc

    local drivers = {}
    local okK, dbk = pcall(dbk_initialized)
    if okK then drivers.dbk_loaded = dbk and true or false end
    local okD, dbvm = pcall(dbvm_initialized)
    if okD then drivers.dbvm_loaded = dbvm and true or false end
    local okG, dbg = pcall(debug_isDebugging)
    if okG then drivers.debugger_attached = dbg and true or false end
    info.drivers = drivers

    local slotsUsed = 0
    for i = 1, 4 do if serverState.hw_bp_slots[i] then slotsUsed = slotsUsed + 1 end end
    local running, tracked = 0, 0
    for _, job in pairs(serverState.jobs or {}) do
        tracked = tracked + 1
        if job.state == "running" then running = running + 1 end
    end
    info.state = {
        breakpoints = countKeys(serverState.breakpoints),
        hw_slots_used = slotsUsed,
        hw_slots_total = 4,
        dbvm_watches = countKeys(serverState.active_watches),
        persistent_scans = countKeys(serverState.persistent_scans),
        scan_session_active = serverState.scan_memscan ~= nil,
        structures = countKeys(serverState.structures),
        jobs_running = running,
        jobs_tracked = tracked,
        scan_job = serverState.scan_job_id,
    }
    info.stats = serverState.stats

    -- CE exposes no documented getter for the "Query memory region routines" checkbox, so this
    -- is a best-effort probe of the settings registry. "unknown" means "could not be read".
    local qmr = "unknown"
    local okS, settings = pcall(getSettings)
    if okS and settings then
        for _, key in ipairs({ "Use DBK QueryMemoryRegion", "Use dbk QueryMemoryRegion", "UseDBKQueryMemoryRegion", "Query memory region routines" }) do
            local okV, v = pcall(function() return settings.Value[key] end)
            if okV and v ~= nil and v ~= "" then
                qmr = (v == true or v == 1 or tostring(v):lower() == "true" or tostring(v) == "1") and "enabled" or "disabled"
                info.query_memory_region_setting_key = key
                break
            end
        end
    end
    info.query_memory_region_routines = qmr
    if qmr == "enabled" then
        warnings[#warnings + 1] = "'Query memory region routines' is ENABLED (Settings > Extra). Scans on DBVM-protected pages can trigger CLOCK_WATCHDOG_TIMEOUT BSODs; disable it."
    elseif qmr == "unknown" and (drivers.dbk_loaded or drivers.dbvm_loaded) then
        warnings[#warnings + 1] = "DBK/DBVM is loaded and the 'Query memory region routines' setting could not be read; confirm it is disabled (Settings > Extra) before scanning."
    end
    if running > 0 then
        warnings[#warnings + 1] = tostring(running) .. " async job(s) running."
    end
    info.warnings = warnings
    return info
end

-- ---------------------------------------------------------------------------
-- read_struct: several typed fields from one memory read
-- ---------------------------------------------------------------------------
local STRUCT_INT = {
    i8  = { fmt = "<i1", size = 1 }, u8  = { fmt = "<I1", size = 1 },
    i16 = { fmt = "<i2", size = 2 }, u16 = { fmt = "<I2", size = 2 },
    i32 = { fmt = "<i4", size = 4 }, u32 = { fmt = "<I4", size = 4 },
    i64 = { fmt = "<i8", size = 8 }, u64 = { fmt = "<I8", size = 8 },
    f32 = { fmt = "<f",  size = 4, float = true }, f64 = { fmt = "<d", size = 8, float = true },
}
local STRUCT_ALIASES = {
    byte = "u8", word = "u16", dword = "u32", qword = "u64", float = "f32", single = "f32",
    double = "f64", int = "i32", uint = "u32", short = "i16", ushort = "u16",
    int8 = "i8", uint8 = "u8", int16 = "i16", uint16 = "u16", int32 = "i32", uint32 = "u32",
    int64 = "i64", uint64 = "u64", pointer = "ptr", boolean = "bool", string = "cstring", utf16 = "wstring",
}
local STRUCT_TYPE_NAMES = "i8,u8,i16,u16,i32,u32,i64,u64,f32,f64,ptr,bool,bytes,cstring,wstring"
local STRUCT_MAX_FIELDS, STRUCT_MAX_SPAN = 512, 65536

local function clampInt(v, lo, hi)
    v = math.floor(tonumber(v) or lo)
    return math.max(lo, math.min(hi, v))
end

local function utf16leToUtf8(s)
    local out, i = {}, 1
    while i + 1 <= #s do
        local cu = string.unpack("<I2", s, i)
        i = i + 2
        if cu == 0 then break end
        if cu >= 0xD800 and cu <= 0xDBFF and i + 1 <= #s then
            local lo = string.unpack("<I2", s, i)
            if lo >= 0xDC00 and lo <= 0xDFFF then
                cu = 0x10000 + ((cu - 0xD800) << 10) + (lo - 0xDC00)
                i = i + 2
            else
                cu = 0xFFFD
            end
        elseif cu >= 0xD800 and cu <= 0xDFFF then
            cu = 0xFFFD
        end
        out[#out + 1] = utf8.char(cu)
    end
    return table.concat(out)
end

local function normalizeStructFields(fields, is64)
    local out, nextOffset = {}, 0
    for i, f in ipairs(fields) do
        if type(f) ~= "table" then
            return nil, { success = false, error = "fields[" .. i .. "] must be an object", error_code = "INVALID_PARAMS" }
        end
        local ftype = tostring(f.type or ""):lower()
        ftype = STRUCT_ALIASES[ftype] or ftype
        local size
        if STRUCT_INT[ftype] then size = STRUCT_INT[ftype].size
        elseif ftype == "ptr" then size = is64 and 8 or 4
        elseif ftype == "bool" then size = 1
        elseif ftype == "bytes" then size = clampInt(f.size or f.length or 16, 1, 4096)
        elseif ftype == "cstring" then size = clampInt(f.size or f.length or 64, 1, 4096)
        elseif ftype == "wstring" then size = 2 * clampInt(f.size or f.length or 32, 1, 2048)  -- size = characters
        else
            return nil, { success = false, error = "fields[" .. i .. "]: unknown type '" .. tostring(f.type) .. "'. Valid: " .. STRUCT_TYPE_NAMES, error_code = "INVALID_PARAMS" }
        end
        local offset = f.offset
        if offset == nil then offset = nextOffset else offset = tonumber(offset) end
        if not offset or offset < 0 then
            return nil, { success = false, error = "fields[" .. i .. "]: invalid offset", error_code = "INVALID_PARAMS" }
        end
        offset = math.floor(offset)
        out[#out + 1] = { name = f.name and tostring(f.name) or ("field" .. i), type = ftype, offset = offset, size = size }
        nextOffset = offset + size
    end
    return out
end

local function fillStructEntry(entry, f, buf, pos, is64)
    local spec = STRUCT_INT[f.type]
    if spec then
        local v = string.unpack(spec.fmt, buf, pos)
        if f.type == "u64" and v < 0 then
            entry.value = toHex(v)                       -- above 2^63: hex string, JSON numbers are signed
        else
            entry.value = v
            if not spec.float and spec.size >= 4 then entry.hex = toHex(v) end
        end
    elseif f.type == "ptr" then
        entry.value = toHex(string.unpack(is64 and "<I8" or "<I4", buf, pos))
    elseif f.type == "bool" then
        entry.value = string.unpack("<I1", buf, pos) ~= 0
    elseif f.type == "bytes" then
        local parts = {}
        for i = 0, f.size - 1 do parts[#parts + 1] = string.format("%02X", buf:byte(pos + i)) end
        entry.value = table.concat(parts, " ")
    elseif f.type == "cstring" then
        local s = buf:sub(pos, pos + f.size - 1)
        local nul = s:find("\0", 1, true)
        entry.value = nul and s:sub(1, nul - 1) or s
    elseif f.type == "wstring" then
        entry.value = utf16leToUtf8(buf:sub(pos, pos + f.size - 1))
    end
end

function cmd_read_struct(params)
    local okProc, perr = requireProcess()
    if not okProc then return perr end

    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    local fields = params.fields
    if type(fields) ~= "table" or #fields == 0 then
        return { success = false, error = "fields must be a non-empty array of {name, type, offset?, size?}", error_code = "INVALID_PARAMS" }
    end
    if #fields > STRUCT_MAX_FIELDS then
        return { success = false, error = "At most " .. STRUCT_MAX_FIELDS .. " fields per call", error_code = "INVALID_PARAMS" }
    end

    local is64 = targetIs64Bit()
    local specs, serr = normalizeStructFields(fields, is64)
    if serr then return serr end

    local spanStart, spanEnd = math.huge, 0
    for _, f in ipairs(specs) do
        spanStart = math.min(spanStart, f.offset)
        spanEnd = math.max(spanEnd, f.offset + f.size)
    end
    local span = spanEnd - spanStart
    if span > STRUCT_MAX_SPAN then
        return { success = false, error = "Field span of " .. span .. " bytes exceeds the " .. STRUCT_MAX_SPAN .. " byte limit", error_code = "INVALID_PARAMS" }
    end

    local whole
    local bytes = readBytes(addr + spanStart, span, true)
    if bytes then whole = bytesToString(bytes) end

    local entries = {}
    for i, f in ipairs(specs) do
        local entry = { name = f.name, type = f.type, offset = f.offset }
        local buf, pos
        if whole then
            buf, pos = whole, f.offset - spanStart + 1
        else
            -- the span as a whole was unreadable: try each field on its own
            local fb = readBytes(addr + f.offset, f.size, true)
            if fb then buf, pos = bytesToString(fb), 1 end
        end
        if not buf then
            entry.error = "unreadable at " .. toHex(addr + f.offset)
        else
            local ok, err = pcall(fillStructEntry, entry, f, buf, pos, is64)
            if not ok then entry.error = tostring(err) end
        end
        entries[i] = entry
    end

    return { success = true, address = toHex(addr), span = span, arch = is64 and "x64" or "x86", fields = entries }
end

-- ---------------------------------------------------------------------------
-- batch: several commands in one round trip (single main-thread slot)
-- ---------------------------------------------------------------------------
local BATCH_MAX = 100
local BATCH_DEFAULT_BUDGET_MS = 20000     -- below the client's default CE_MCP_TIMEOUT (30 s): a batch stops early rather than time out
local BATCH_MAX_BUDGET_MS = 600000

function cmd_batch(params)
    local reqs = params.requests
    if type(reqs) ~= "table" or #reqs == 0 then
        return { success = false, error = "requests must be a non-empty array of {method, params}", error_code = "INVALID_PARAMS" }
    end
    if #reqs > BATCH_MAX then
        return { success = false, error = "At most " .. BATCH_MAX .. " requests per batch", error_code = "INVALID_PARAMS" }
    end

    local stopOnError = params.stop_on_error == true
    -- Wall-time budget, checked BEFORE each request (a request is never interrupted): the whole batch runs in one
    -- main-thread slot, so 100 slow requests would otherwise outlive the client's timeout, the reply would be
    -- lost and the pipe would stay busy until the last one finished.
    local budget = tonumber(params.time_budget_ms) or BATCH_DEFAULT_BUDGET_MS
    budget = math.max(100, math.min(budget, BATCH_MAX_BUDGET_MS)) / 1000
    local t0 = os.clock()
    local results, failed, stoppedEarly = {}, 0, nil
    for i, req in ipairs(reqs) do
        if i > 1 and os.clock() - t0 >= budget then stoppedEarly = "time_budget"; break end
        local method = type(req) == "table" and req.method or nil
        local handler = method and serverState.dispatch[method]
        local result
        if method == "batch" then
            result = { success = false, error = "batch calls cannot be nested", error_code = "INVALID_PARAMS" }
        elseif not handler then
            result = { success = false, error = "Method not found: " .. tostring(method), error_code = "NOT_FOUND" }
        else
            local ok, r = pcall(handler, type(req.params) == "table" and req.params or {})
            if ok then
                result = r
                if result == nil then result = { success = true } end
            else
                result = { success = false, error = "Internal error: " .. tostring(r), error_code = "INTERNAL_ERROR" }
            end
        end
        results[i] = result
        if type(result) == "table" and result.success == false then
            failed = failed + 1
            if stopOnError then stoppedEarly = "stop_on_error"; break end
        end
    end
    local out = { success = true, requested = #reqs, executed = #results, failed = failed, results = results,
                  elapsed_ms = math.floor((os.clock() - t0) * 1000 + 0.5) }
    if stoppedEarly then
        out.stopped_early = stoppedEarly
        out.not_run = #reqs - #results        -- requests[executed + 1 ..] were never started; resend those
    end
    return out
end

-- ---------------------------------------------------------------------------
-- Async jobs: long scans without freezing CE or hitting the client timeout.
--   scan_all / next_scan / aob_scan : native CE memscan, started without waitTillDone
--   find_references / find_call_references : memscan, then post-processed in
--     time-sliced chunks from a CE timer so the GUI stays responsive
-- ---------------------------------------------------------------------------
local MAX_RUNNING_JOBS = 4
local MAX_TRACKED_FINISHED_JOBS = 20
local JOB_TICK_INTERVAL_MS = 15
local JOB_TICK_BUDGET_S = 0.02
local jobFinish, jobAdvance, ensurePump

local function jobReleaseResources(job)
    if job._fl then pcall(function() job._fl.destroy() end); job._fl = nil end
    if job._ms and job._temp then pcall(function() job._ms.destroy() end) end
    job._ms = nil
end

jobFinish = function(job, state, fields)
    job.state = state
    job.phase = state
    job.finished = os.time()
    if fields then for k, v in pairs(fields) do job[k] = v end end
    jobReleaseResources(job)
    job._step, job._after_scan = nil, nil
    if serverState.scan_job_id == job.id then serverState.scan_job_id = nil end
end

local function jobFail(job, message, code)
    jobFinish(job, "failed", { error = message, error_code = code or "INTERNAL_ERROR" })
end

local function jobProgress(job)
    local cur, total, found = 0, 0, nil
    if job.state == "running" and job.phase == "scanning" and job._ms then
        local ok, p = pcall(function() return job._ms.getProgress() end)
        if ok and type(p) == "table" then
            cur, total, found = p.CurrentlyScanned or 0, p.TotalAddressesToScan or 0, p.ResultsFound
        end
    elseif job.progress then
        cur, total = job.progress.current or 0, job.progress.total or 0
    end
    return { current = cur, total = total, percent = total > 0 and math.floor(cur / total * 1000) / 10 or nil, results_found = found }
end

-- Moves a job out of the scanning phase once its memscan has finished. Called from
-- OnScanDone, from the pump timer and from get_job, so it must be idempotent.
jobAdvance = function(job)
    if job.state ~= "running" or job.phase ~= "scanning" or job._advancing then return end
    local ms = job._ms
    local done = job._scan_done
    if not done and ms then
        local ok, p = pcall(function() return ms.getProgress() end)
        if ok and type(p) == "table" and (p.TotalAddressesToScan or 0) > 0
           and (p.CurrentlyScanned or 0) >= p.TotalAddressesToScan then
            -- the scan loop has covered everything; let the worker threads wind down
            job._advancing = true
            pcall(function() ms.waitTillDone() end)
            job._advancing = false
            done = true
        end
    end
    if not done or not job._after_scan then return end
    job._advancing = true
    local ok, err = pcall(job._after_scan, job)
    job._advancing = false
    if not ok and job.state == "running" then
        jobFail(job, "Post-scan processing failed: " .. tostring(err))
    end
end

local function jobPump()
    local deadline = os.clock() + JOB_TICK_BUDGET_S
    local active = BPX.watchdog()    -- also keeps the timer alive while a thread is halted
    for _, job in pairs(serverState.jobs) do
        if job.state == "running" then
            active = true
            if job.phase == "scanning" then
                jobAdvance(job)
            elseif job.phase == "processing" and job._step and os.clock() < deadline then
                local ok, err = pcall(job._step, job, deadline)
                if not ok then jobFail(job, "Job step failed: " .. tostring(err)) end
            end
        end
    end
    if not active and serverState.job_timer then serverState.job_timer.Enabled = false end
end

ensurePump = function()
    if not serverState.job_timer then
        local timer = createTimer(nil, false)
        timer.Interval = JOB_TICK_INTERVAL_MS
        timer.OnTimer = function()
            local ok, err = pcall(jobPump)
            if not ok then log("Job pump error: " .. tostring(err)) end
        end
        serverState.job_timer = timer
    end
    serverState.job_timer.Enabled = true
end
BPX.ensurePump = ensurePump      -- the break-and-inspect watchdog runs from the same timer

-- Bridge stop / reload: stop the pump, free private memscans/foundlists. Runs before the shared scan objects are destroyed:
-- a running next_scan job shares serverState.scan_memscan, which must never be destroyed twice.
cleanupHooks.jobs[#cleanupHooks.jobs + 1] = function()
    if serverState.jobs then
        for _, job in pairs(serverState.jobs) do
            if job._fl then pcall(function() job._fl.destroy() end) end
            if job._ms and job._ms ~= serverState.scan_memscan then
                pcall(function() job._ms.destroy() end)
            end
        end
    end
    if serverState.job_timer then
        pcall(function() serverState.job_timer.destroy() end)
        serverState.job_timer = nil
    end
    serverState.jobs = {}
    serverState.scan_job_id = nil
end

local function pruneJobs()
    local finished = {}
    for _, job in pairs(serverState.jobs) do
        if job.state ~= "running" then finished[#finished + 1] = job end
    end
    if #finished <= MAX_TRACKED_FINISHED_JOBS then return end
    table.sort(finished, function(a, b) return a.seq < b.seq end)
    for i = 1, #finished - MAX_TRACKED_FINISHED_JOBS do
        serverState.jobs[finished[i].id] = nil
    end
end

local function addressToAobPattern(addr, is64)
    local raw
    if is64 and addr > 0xFFFFFFFF then raw = string.pack("<I8", addr) else raw = string.pack("<I4", addr & 0xFFFFFFFF) end
    local parts = {}
    for i = 1, #raw do parts[i] = string.format("%02X", raw:byte(i)) end
    return table.concat(parts, " ")
end

-- The handler only raises a flag: advancing a job can destroy its memscan, and destroying a memscan
-- from inside its own event handler is unsafe. The pump timer (or get_job) does the actual work.
local function onScanDone(job)
    return function() job._scan_done = true end
end

-- Private (temporary) AOB memscan used by aob_scan / find_references / find_call_references.
local function startAobMemscan(job, pattern, protection)
    local ms = createMemScan()
    job._ms, job._temp = ms, true
    job.phase = "scanning"
    ms.OnScanDone = onScanDone(job)
    ms.firstScan(soExactValue, vtByteArray, rtRounded, pattern, "", 0, USER_MODE_MAX, protection, fsmNotAligned, "1", true, false, false, false)
end

local JOB_STARTERS = {}

JOB_STARTERS.scan_all = function(job, p)
    local busy = scanBusyError()
    if busy then return busy end
    local args, err = prepareFirstScan(p)
    if err then return err end

    local ms = createMemScan()
    job._ms = ms               -- not temporary: becomes the scan session when it finishes
    job.phase = "scanning"
    serverState.scan_job_id = job.id
    ms.OnScanDone = onScanDone(job)
    job._after_scan = function(j)
        local count = commitFirstScan(ms, args.scanOpt)
        pcall(function() ms.OnScanDone = nil end)
        j.progress = { current = 1, total = 1 }
        jobFinish(j, "done", { result = { fields = { count = count } } })
    end
    ms.firstScan(args.scanOpt, args.varType, rtRounded, args.input1, args.input2, 0, USER_MODE_MAX, args.protect, fsmNotAligned, "1", false, false, false, false)
end

JOB_STARTERS.next_scan = function(job, p)
    local busy = scanBusyError()
    if busy then return busy end
    local args, err = prepareNextScan(p)
    if err then return err end

    local ms = args.ms
    job._ms = ms
    job._shared_ms = true      -- the active scan session; never destroyed as a job resource
    job.phase = "scanning"
    serverState.scan_job_id = job.id
    ms.OnScanDone = onScanDone(job)
    job._after_scan = function(j)
        local count = commitNextScan(ms)
        pcall(function() ms.OnScanDone = nil end)
        j._ms = nil
        j.progress = { current = 1, total = 1 }
        jobFinish(j, "done", { result = { fields = { count = count } } })
    end
    ms.nextScan(args.scanOpt, rtRounded, args.input1, args.input2, false, false, false, false, false)
end

JOB_STARTERS.aob_scan = function(job, p)
    if not p.pattern then
        return { success = false, error = "No pattern provided", error_code = "INVALID_PARAMS" }
    end
    local limit = clampInt(p.limit or 100, 1, 10000)
    job._after_scan = function(j)
        local fl = createFoundList(j._ms)
        fl.initialize()
        j._fl = fl
        local total = fl.getCount()
        local addrs = {}
        for i = 0, math.min(total, limit) - 1 do
            local s = fl.getAddress(i)
            addrs[#addrs + 1] = { address = "0x" .. s, value = tonumber(s, 16) }
        end
        j.progress = { current = 1, total = 1 }
        jobFinish(j, "done", { result = {
            fields = { pattern = p.pattern, total_matches = total, count = #addrs },
            list_key = "addresses", items = addrs } })
    end
    startAobMemscan(job, p.pattern, p.protection or "+X")
end

-- Phase 2 of find_references / find_call_references: walk the memscan hits in
-- time slices (disassemble / readInteger per hit is what makes the blocking version slow).
local function beginProcessing(job, stepFn)
    local fl = createFoundList(job._ms)
    fl.initialize()
    job._fl = fl
    job._n, job._i, job._items = fl.getCount(), 0, {}
    job.progress = { current = 0, total = job._n }
    job.phase = "processing"
    job._step = stepFn
    ensurePump()
end

local function finishList(job, listKey, fields)
    job.progress = { current = job._n, total = job._n }
    jobFinish(job, "done", { result = { fields = fields, list_key = listKey, items = job._items } })
    return true
end

JOB_STARTERS.find_references = function(job, p)
    local target = p.address
    if type(target) == "string" then target = getAddressSafe(target) end
    if not target then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end
    local is64 = targetIs64Bit()
    local arch = is64 and "x64" or "x86"

    job._after_scan = function(j)
        beginProcessing(j, function(jb, deadline)
            local fl = jb._fl
            while jb._i < jb._n do
                local addr = tonumber(fl.getAddress(jb._i), 16)
                jb._i = jb._i + 1
                if addr then
                    jb._items[#jb._items + 1] = { address = toHex(addr), instruction = disassemble(addr) or "???" }
                end
                if os.clock() >= deadline then jb.progress.current = jb._i; return false end
            end
            return finishList(jb, "references", { target = toHex(target), arch = arch })
        end)
    end
    startAobMemscan(job, addressToAobPattern(target, is64), "+X")
end

JOB_STARTERS.find_call_references = function(job, p)
    local funcAddr = p.address or p.function_address
    if type(funcAddr) == "string" then funcAddr = getAddressSafe(funcAddr) end
    if not funcAddr then return { success = false, error = "Invalid function address", error_code = "INVALID_ADDRESS" } end

    job._after_scan = function(j)
        beginProcessing(j, function(jb, deadline)
            local fl = jb._fl
            while jb._i < jb._n do
                local callAddr = tonumber(fl.getAddress(jb._i), 16)
                jb._i = jb._i + 1
                local rel = callAddr and readInteger(callAddr + 1)
                if rel then
                    if rel > 0x7FFFFFFF then rel = rel - 0x100000000 end
                    if callAddr + 5 + rel == funcAddr then
                        jb._items[#jb._items + 1] = { caller_address = toHex(callAddr), instruction = disassemble(callAddr) or "???" }
                    end
                end
                if os.clock() >= deadline then jb.progress.current = jb._i; return false end
            end
            return finishList(jb, "callers", { function_address = toHex(funcAddr) })
        end)
    end
    startAobMemscan(job, "E8 ?? ?? ?? ??", "+X")
end

-- Job kinds, in the order the "Unknown job kind" error lists them; later modules append their own
local JOB_KIND_NAMES = { "scan_all", "next_scan", "aob_scan", "find_references", "find_call_references" }

local function jobSummary(job)
    local s = {
        job_id = job.id, kind = job.kind, state = job.state, phase = job.phase,
        elapsed_seconds = (job.finished or os.time()) - job.created,
        progress = jobProgress(job),
    }
    if job.state == "failed" then s.error, s.error_code = job.error, job.error_code end
    if job.note then s.note = job.note end
    if job.state == "done" and job.result then
        s.result_ready = true
        s.result_summary = job.result.fields
        if job.result.items then s.result_items = #job.result.items end
    end
    return s
end

local function jobNotFound(id)
    return { success = false, error = "No such job: " .. tostring(id), error_code = "NOT_FOUND" }
end

function cmd_start_job(params)
    local kind = params.kind
    local starter = JOB_STARTERS[kind]
    if not starter then
        return { success = false, error = "Unknown job kind '" .. tostring(kind) .. "'. Valid: " .. table.concat(JOB_KIND_NAMES, ", "), error_code = "INVALID_PARAMS" }
    end
    local p = params.params
    if p ~= nil and type(p) ~= "table" then
        return { success = false, error = "params must be an object", error_code = "INVALID_PARAMS" }
    end
    p = p or {}
    local okProc, perr = requireProcess()
    if not okProc then return perr end

    local running = 0
    for _, job in pairs(serverState.jobs) do
        if job.state == "running" then running = running + 1 end
    end
    if running >= MAX_RUNNING_JOBS then
        return { success = false, error = "Too many running jobs (" .. running .. "); wait for one to finish or cancel_job", error_code = "OUT_OF_RESOURCES" }
    end

    pruneJobs()
    local seq = serverState.job_next_id
    serverState.job_next_id = seq + 1
    local job = { id = "job_" .. seq, seq = seq, kind = kind, state = "running", phase = "starting",
                  created = os.time(), progress = { current = 0, total = 0 } }
    serverState.jobs[job.id] = job

    local function abort()
        if job._ms and not job._shared_ms then pcall(function() job._ms.destroy() end) end
        if job._shared_ms and job._ms then pcall(function() job._ms.OnScanDone = nil end) end
        job._ms = nil
        if serverState.scan_job_id == job.id then serverState.scan_job_id = nil end
        serverState.jobs[job.id] = nil
    end

    local ok, err = pcall(starter, job, p)
    if not ok then
        abort()
        return { success = false, error = "Failed to start job: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    if err then          -- starter returned an error reply
        abort()
        return err
    end
    ensurePump()
    return { success = true, job_id = job.id, kind = kind, state = job.state }
end

function cmd_get_job(params)
    local job = serverState.jobs[params.job_id]
    if not job then return jobNotFound(params.job_id) end
    jobAdvance(job)
    local s = jobSummary(job)
    s.success = true
    return s
end

function cmd_get_job_result(params)
    local job = serverState.jobs[params.job_id]
    if not job then return jobNotFound(params.job_id) end
    jobAdvance(job)
    if job.state ~= "done" or not job.result then
        return { success = false, error = "Job " .. job.id .. " is " .. job.state .. "; no result available",
                 error_code = job.state == "running" and "BUSY" or "NOT_FOUND", state = job.state, error_detail = job.error }
    end
    local out = { success = true, job_id = job.id, kind = job.kind }
    for k, v in pairs(job.result.fields or {}) do out[k] = v end
    if job.result.list_key then
        local limit, offset, page, total = paginate(params, job.result.items, 100)
        out.total, out.offset, out.limit, out.returned = total, offset, limit, #page
        out[job.result.list_key] = page
    end
    return out
end

function cmd_cancel_job(params)
    local job = serverState.jobs[params.job_id]
    if not job then return jobNotFound(params.job_id) end
    if job.state ~= "running" then
        return { success = true, job_id = job.id, state = job.state, note = "Job was not running" }
    end

    local note
    if job.phase == "scanning" and job._ms then
        -- CE has no "stop scan" call; destroying the memscan terminates its scanner threads.
        if job._shared_ms then
            -- next_scan runs on the shared scan session; a half-finished session is unusable.
            if serverState.scan_foundlist then pcall(function() serverState.scan_foundlist.destroy() end); serverState.scan_foundlist = nil end
            pcall(function() job._ms.destroy() end)
            serverState.scan_memscan = nil
            note = "The active scan session was discarded; run scan_all again."
        else
            pcall(function() job._ms.destroy() end)
        end
        job._ms = nil
    end
    jobFinish(job, "cancelled", { note = note })
    return { success = true, job_id = job.id, state = job.state, note = note }
end

function cmd_list_jobs(params)
    local list = {}
    for _, job in pairs(serverState.jobs) do list[#list + 1] = job end
    table.sort(list, function(a, b) return a.seq < b.seq end)
    local out = {}
    for i, job in ipairs(list) do out[i] = jobSummary(job) end
    return { success = true, count = #out, jobs = out }
end

-- >>> END UNIT-25 <<<

-- >>> exports
B.countKeys = countKeys
B.STRUCT_INT = STRUCT_INT
B.STRUCT_ALIASES = STRUCT_ALIASES
B.STRUCT_TYPE_NAMES = STRUCT_TYPE_NAMES
B.STRUCT_MAX_FIELDS = STRUCT_MAX_FIELDS
B.STRUCT_MAX_SPAN = STRUCT_MAX_SPAN
B.clampInt = clampInt
B.utf16leToUtf8 = utf16leToUtf8
B.normalizeStructFields = normalizeStructFields
B.fillStructEntry = fillStructEntry
B.BATCH_MAX = BATCH_MAX
B.BATCH_DEFAULT_BUDGET_MS = BATCH_DEFAULT_BUDGET_MS
B.BATCH_MAX_BUDGET_MS = BATCH_MAX_BUDGET_MS
B.MAX_RUNNING_JOBS = MAX_RUNNING_JOBS
B.MAX_TRACKED_FINISHED_JOBS = MAX_TRACKED_FINISHED_JOBS
B.JOB_TICK_INTERVAL_MS = JOB_TICK_INTERVAL_MS
B.JOB_TICK_BUDGET_S = JOB_TICK_BUDGET_S
B.jobFinish = jobFinish
B.jobAdvance = jobAdvance
B.ensurePump = ensurePump
B.jobReleaseResources = jobReleaseResources
B.jobFail = jobFail
B.jobProgress = jobProgress
B.jobPump = jobPump
B.pruneJobs = pruneJobs
B.addressToAobPattern = addressToAobPattern
B.onScanDone = onScanDone
B.startAobMemscan = startAobMemscan
B.JOB_STARTERS = JOB_STARTERS
B.beginProcessing = beginProcessing
B.finishList = finishList
B.JOB_KIND_NAMES = JOB_KIND_NAMES
B.jobSummary = jobSummary
B.jobNotFound = jobNotFound
