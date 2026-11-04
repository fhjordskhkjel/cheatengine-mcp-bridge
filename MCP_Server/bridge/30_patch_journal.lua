-- ============================================================================
-- Cheat Engine MCP Bridge :: 30_patch_journal
-- Patch journal and undo (UNIT-31)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local U26 = B.U26
local json = B.json
local paginate = B.paginate
local requireProcess = B.requireProcess
local serverState = B.serverState

-- >>> BEGIN UNIT-31 Patch journal and undo <<<
-- Every write made through the bridge's own write tools is recorded with the bytes it replaced, so it can be undone.
-- U26.pjWrap wraps those handlers inside the dispatcher table itself, so writes sent through batch() are journaled
-- too. Covered: write_memory, write_integer, write_string, copy_memory (with a dest) and auto_assemble (undone by
-- running the script's [DISABLE] section with the info CE returned when it was enabled). NOT covered: anything else
-- that changes the target (memory records, kernel/physical writes, injected code, scripts without [DISABLE]).
-- The journal is also appended to a file (U26.PJ_FILE, next to the pointer sets), so a reload of the bridge or a restart
-- of CE keeps it. Byte patches stay undoable across that while the same process is attached; script patches do not
-- (CE's disable information cannot be saved).
U26.PJ_MAX_ENTRIES, U26.PJ_MAX_BYTES, U26.PJ_MAX_TOTAL, U26.PJ_PREVIEW = 500, 0x10000, 16 * 1024 * 1024, 64
serverState.patches, serverState.patch_seq, serverState.patch_bytes, serverState.patch_dropped = {}, 0, 0, 0
serverState.pj_lines = 0                 -- lines in the journal file; it is rewritten (compacted) when it grows too long
U26.PJ_SIZES = { byte = 1, word = 2, ["2bytes"] = 2, dword = 4, ["4bytes"] = 4, qword = 8, ["8bytes"] = 8, float = 4, double = 8 }

-- method -> function(params) -> address, size that the call is about to overwrite (nil: unknown, the call is not journaled
-- as bytes; an invalid call simply fails in its own handler)
U26.pjRanges = {
    write_memory = function(p) return U26.addr(p.address), type(p.bytes) == "table" and #p.bytes or nil end,
    write_integer = function(p) return U26.addr(p.address), U26.PJ_SIZES[p.type or "dword"] end,
    write_string = function(p)
        local s = p.value or p.string
        if type(s) ~= "string" then return nil end
        return U26.addr(p.address), p.wide and 2 * (utf8.len(s) or #s) or #s       -- CE writes no terminator
    end,
    copy_memory = function(p)
        if p.dest == nil then return nil end                                   -- copies into fresh memory: nothing overwritten
        return U26.addr(p.dest), U26.psInt(p.size)
    end,
}
U26.PJ_METHODS = { "write_memory", "write_integer", "write_string", "copy_memory", "auto_assemble" }

function U26.pjHex(s, max)
    local n = math.min(#s, max or #s)
    local out = {}
    for i = 1, n do out[i] = string.format("%02X", s:byte(i)) end
    return table.concat(out, " ") .. (#s > n and " ..." or "")
end

function U26.pjBytes(s)                  -- string -> byte table, in slices (string.byte cannot return 64K values at once)
    local tbl = {}
    for i = 1, #s, 4096 do
        local part = { s:byte(i, math.min(i + 4095, #s)) }
        for k = 1, #part do tbl[#tbl + 1] = part[k] end
    end
    return tbl
end

function U26.pjAdd(entry)
    serverState.patch_seq = serverState.patch_seq + 1
    entry.id = "p" .. serverState.patch_seq
    entry.seq = serverState.patch_seq
    entry.at = os.time()
    local pr = U26.psProcess()
    entry.pid, entry.process = pr.pid, pr.process
    entry.cost = (entry.original and #entry.original * 2 or 0) + (entry.script and #entry.script or 0)
    local list = serverState.patches
    list[#list + 1] = entry
    serverState.patch_bytes = serverState.patch_bytes + entry.cost
    U26.pjTrim()
    U26.pjAppend({ op = "add", e = U26.pjRecord(entry) })
    return entry.id
end

function U26.pjTrim()
    local list = serverState.patches
    while #list > U26.PJ_MAX_ENTRIES or (serverState.patch_bytes > U26.PJ_MAX_TOTAL and #list > 1) do
        local old = table.remove(list, 1)                  -- the oldest entries go first; they can no longer be undone
        serverState.patch_bytes = serverState.patch_bytes - old.cost
        serverState.patch_dropped = serverState.patch_dropped + 1
    end
end

-- Was the entry made in the process CE is attached to now? A pid alone can be reused by another program after a restart,
-- so the process name has to match too (when both are known).
function U26.pjSame(e, pr)
    if e.pid ~= pr.pid then return false end
    return e.process == nil or pr.process == nil or e.process:lower() == pr.process:lower()
end

function U26.pjHexRaw(s) return (s:gsub(".", function(c) return string.format("%02X", c:byte()) end)) end

function U26.pjUnhex(h)
    if type(h) ~= "string" or #h % 2 == 1 or not h:match("^%x*$") then return nil end
    return (h:gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end))
end

-- JSON-safe copy of an entry (byte strings as hex; CE's disable info is left out, it cannot be saved)
function U26.pjRecord(e)
    return { id = e.id, seq = e.seq, at = e.at, pid = e.pid, process = e.process, method = e.method, kind = e.kind,
             address = e.address, size = e.size, original = e.original and U26.pjHexRaw(e.original) or nil,
             written = e.written and U26.pjHexRaw(e.written) or nil, script = e.script, undoable = e.undoable,
             reason = e.reason, undone = e.undone, undone_at = e.undone_at }
end

-- saved record -> entry (nil when it is damaged)
function U26.pjFromRecord(r)
    local seq = U26.psInt(r.seq)
    if not seq or type(r.id) ~= "string" or (r.kind ~= "bytes" and r.kind ~= "script") then return nil end
    local e = { id = r.id, seq = seq, at = U26.psInt(r.at), pid = U26.psInt(r.pid), method = tostring(r.method), kind = r.kind,
                process = type(r.process) == "string" and r.process or nil, undone = r.undone == true or nil,
                undone_at = U26.psInt(r.undone_at) }
    if r.undoable == false then e.undoable, e.reason = false, tostring(r.reason) end
    if e.kind == "bytes" then
        e.address, e.size = U26.psInt(r.address), U26.psInt(r.size)
        if not e.address or not e.size then return nil end
        if r.original ~= nil or r.written ~= nil then
            e.original, e.written = U26.pjUnhex(r.original), U26.pjUnhex(r.written)
            if not e.original or not e.written or #e.original ~= e.size or #e.written ~= e.size then return nil end
        elseif e.undoable ~= false then
            return nil
        end
    else
        e.script = type(r.script) == "string" and r.script or nil
        if e.undoable ~= false and not e.undone then
            e.undoable, e.reason = false, "Cheat Engine's disable information does not survive a reload of the bridge: disable the script in Cheat Engine"
        end
    end
    e.cost = (e.original and #e.original * 2 or 0) + (e.script and #e.script or 0)
    return e
end

-- The whole journal as it is now (also compacts the file: undo lines and dropped entries disappear)
function U26.pjRewrite()
    if not U26.stDir() then return end
    local out = {}
    for _, e in ipairs(serverState.patches) do
        local ok, line = pcall(json.encode, { op = "add", e = U26.pjRecord(e) })
        if ok then out[#out + 1] = line .. "\n" end
    end
    if U26.stWrite(U26.PJ_FILE, table.concat(out)) then serverState.pj_lines = #out end
end

function U26.pjAppend(rec)
    local path = U26.stPath(U26.PJ_FILE)
    if not path then return end
    if serverState.pj_lines >= 2 * U26.PJ_MAX_ENTRIES + 100 then return U26.pjRewrite() end    -- rec is already in the journal
    local ok, line = pcall(json.encode, rec)
    if not ok then serverState.state_error = "cannot encode a journal entry: " .. tostring(line); return end
    local f, err = io.open(path, "ab")
    if not f then serverState.state_error = "cannot append to " .. path .. ": " .. tostring(err); return end
    f:write(line, "\n")
    f:close()
    serverState.pj_lines = serverState.pj_lines + 1
end

-- Called once when the script is executed: replays the journal file of the previous instance of the bridge.
function U26.pjLoad()
    local text = U26.stRead(U26.PJ_FILE)
    if not text then return 0 end
    local list, byId = {}, {}
    for line in text:gmatch("[^\r\n]+") do
        local ok, r = pcall(json.decode, line)                -- a line cut off by a crash is skipped
        if ok and type(r) == "table" then
            if r.op == "add" and type(r.e) == "table" then
                local e = U26.pjFromRecord(r.e)
                if e and not byId[e.id] then list[#list + 1] = e; byId[e.id] = e end
            elseif r.op == "undo" and type(r.id) == "string" and byId[r.id] then
                local e = byId[r.id]
                e.undone, e.undone_at = true, U26.psInt(r.at)
            end
        end
    end
    table.sort(list, function(a, b) return a.seq < b.seq end)
    serverState.patches, serverState.patch_bytes = list, 0
    for _, e in ipairs(list) do
        serverState.patch_bytes = serverState.patch_bytes + e.cost
        if e.seq > serverState.patch_seq then serverState.patch_seq = e.seq end
    end
    U26.pjTrim()
    U26.pjRewrite()
    return #list
end

-- Runs one write handler and journals it when it succeeded.
function U26.pjRun(method, handler, params)
    params = params or {}
    local addr, size
    local rangeFn = U26.pjRanges[method]
    if rangeFn then
        local ok, a, s = pcall(rangeFn, params)
        if ok then addr, size = a, s end
    end
    if size and size < 1 then size = nil end
    local before
    if addr and size and size <= U26.PJ_MAX_BYTES then before = U26.rd(addr, size) end
    serverState.aa_last = nil
    local res = handler(params)
    if type(res) ~= "table" or res.success ~= true then return res end

    local entry
    if method == "auto_assemble" then
        local last = serverState.aa_last
        serverState.aa_last = nil
        local script = last and last.script or params.script or params.code
        local hasDisable = type(script) == "string" and script:lower():find("[disable]", 1, true) ~= nil
        entry = { method = method, kind = "script", script = script, disable_info = last and last.info }
        if not hasDisable then
            entry.undoable, entry.reason = false, "the script has no [DISABLE] section"
        elseif not (last and last.info) then
            entry.undoable, entry.reason = false, "Cheat Engine returned no disable information"
        end
    elseif addr and size then
        entry = { method = method, kind = "bytes", address = addr, size = size }
        if before then
            entry.original, entry.written = before, U26.rd(addr, size)
        elseif size > U26.PJ_MAX_BYTES then
            entry.undoable, entry.reason = false, "larger than " .. U26.PJ_MAX_BYTES .. " bytes: the original bytes were not kept"
        else
            entry.undoable, entry.reason = false, "the original bytes could not be read before the write"
        end
    end
    if entry then
        res.patch_id = U26.pjAdd(entry)
        if entry.undoable == false then res.patch_note = "journaled but cannot be undone: " .. entry.reason end
    end
    return res
end

function U26.pjWrap(handlers)
    for _, m in ipairs(U26.PJ_METHODS) do
        local h = handlers[m]
        if h then handlers[m] = function(params) return U26.pjRun(m, h, params) end end
    end
end

-- live state of one entry: applied | changed | undone | unreadable | other_process | not_undoable
function U26.pjState(e, pr)
    if e.undone then return "undone" end
    if not U26.pjSame(e, pr) then return "other_process" end
    if e.undoable == false then return "not_undoable" end
    if e.kind == "script" then return "applied" end
    local cur = U26.rd(e.address, e.size)
    if not cur then return "unreadable" end
    return cur == e.written and "applied" or "changed"
end

function U26.pjView(e, pr, mods)
    local v = { id = e.id, method = e.method, kind = e.kind, at = e.at, pid = e.pid, process = e.process, state = U26.pjState(e, pr),
                undoable = e.undoable ~= false and not e.undone, reason = e.reason }
    if e.kind == "bytes" then
        v.address, v.size = U26.hex(e.address), e.size
        local m = U26.moduleFor(mods, e.address)
        if m then v.expression = m.name .. "+" .. U26.hex(e.address - m.base) end
        if e.original then
            v.original, v.written = U26.pjHex(e.original, U26.PJ_PREVIEW), U26.pjHex(e.written, U26.PJ_PREVIEW)
        end
    else
        v.script_head = e.script and e.script:sub(1, 200) or nil
    end
    if e.undone then v.undone_at = e.undone_at end
    return v
end

function U26.pjFind(id)
    for i, e in ipairs(serverState.patches) do if e.id == id then return e, i end end
    return nil
end

-- Undo one entry. Returns { id, ok, state?, reason?, conflict? }
function U26.pjUndoOne(e, force)
    local out = { id = e.id }
    if e.undone then out.reason = "already undone"; return out end
    if not U26.pjSame(e, U26.psProcess()) then
        out.reason = "made in another process (" .. tostring(e.process or "pid") .. " " .. tostring(e.pid) .. "): the target was restarted or CE is attached elsewhere"
        return out
    end
    if e.undoable == false then out.reason = e.reason; return out end
    if e.kind == "script" then
        local ok, res, err = pcall(autoAssemble, e.script, e.disable_info)
        if not ok or not res then
            out.reason = "the [DISABLE] section failed: " .. tostring(ok and err or res)
            return out
        end
    else
        local cur = U26.rd(e.address, e.size)
        if not cur then out.reason = "the memory is no longer readable"; return out end
        if cur ~= e.written and not force then
            out.conflict = true
            out.reason = "the bytes changed since this patch (a later patch, the game, or another tool); force=true restores the original anyway"
            return out
        end
        local ok, err = pcall(writeBytes, e.address, U26.pjBytes(e.original))
        if not ok then out.reason = "write failed: " .. tostring(err); return out end
        if U26.rd(e.address, e.size) ~= e.original then out.reason = "the original bytes did not stick (write-protected?)"; return out end
    end
    e.undone, e.undone_at = true, os.time()
    U26.pjAppend({ op = "undo", id = e.id, at = e.undone_at })
    out.ok = true
    return out
end

function cmd_list_patches(params)
    local pr = U26.psProcess()
    local mods = U26.listModules()
    local items = {}
    local list = serverState.patches
    for i = #list, 1, -1 do                                -- newest first
        local e = list[i]
        if not (params.active_only == true and e.undone) then items[#items + 1] = U26.pjView(e, pr, mods) end
    end
    local limit, offset, page, total = paginate(params, items, 50)
    local path, saveErr = U26.stInfo(U26.PJ_FILE)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, patches = page,
             dropped = serverState.patch_dropped > 0 and serverState.patch_dropped or nil, saved_to = path, save_error = saveErr }
end

-- undo_patch(id) or undo_patch(all=true): newest first, stops nothing on a failure (each result is reported)
function cmd_undo_patch(params)
    local okProc, perr = requireProcess()
    if not okProc then return perr end
    local force = params.force == true
    if params.all == true then
        local results, undone, failed = {}, 0, 0
        local pr = U26.psProcess()
        local list = serverState.patches
        for i = #list, 1, -1 do
            local e = list[i]
            if not e.undone and U26.pjSame(e, pr) and e.undoable ~= false then
                local r = U26.pjUndoOne(e, force)
                results[#results + 1] = r
                if r.ok then undone = undone + 1 else failed = failed + 1 end
            end
        end
        return { success = failed == 0, undone = undone, failed = failed, results = results,
                 error = failed > 0 and (failed .. " patch(es) could not be undone; see results") or nil,
                 error_code = failed > 0 and "INTERNAL_ERROR" or nil }
    end
    if type(params.id) ~= "string" then return U26.err("Give the id of a patch (list_patches) or all=true") end
    local e = U26.pjFind(params.id)
    if not e then return U26.err("No such patch: " .. params.id .. " (the journal keeps the latest " .. U26.PJ_MAX_ENTRIES .. ")", "NOT_FOUND") end
    local r = U26.pjUndoOne(e, force)
    if r.ok then
        return { success = true, id = e.id, undone = true, address = e.address and U26.hex(e.address) or nil }
    end
    return { success = false, id = e.id, error = r.reason, error_code = "INVALID_PARAMS", conflict = r.conflict }
end

-- drop_patches(which = "inactive" | "all"): forget journal entries. The target's memory is not touched; a forgotten
-- patch can no longer be undone. "inactive" = undone, made in another process, or not undoable.
function cmd_drop_patches(params)
    local which = params.which or "inactive"
    if which ~= "inactive" and which ~= "all" then
        return U26.err("which must be 'inactive' (undone, other process, not undoable) or 'all'")
    end
    local pr = U26.psProcess()
    local keep, dropped = {}, 0
    serverState.patch_bytes = 0
    for _, e in ipairs(serverState.patches) do
        local st = which == "all" and "all" or U26.pjState(e, pr)
        if st == "all" or st == "undone" or st == "other_process" or st == "not_undoable" then
            dropped = dropped + 1
        else
            keep[#keep + 1] = e
            serverState.patch_bytes = serverState.patch_bytes + e.cost
        end
    end
    serverState.patches = keep
    U26.pjRewrite()
    return { success = true, dropped = dropped, kept = #keep }
end

U26.pjLoad()

-- >>> END UNIT-31 <<<

-- >>> exports
