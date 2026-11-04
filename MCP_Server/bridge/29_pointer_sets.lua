-- ============================================================================
-- Cheat Engine MCP Bridge :: 29_pointer_sets
-- Pointer path sets and saved state files (UNIT-30)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local U26 = B.U26
local clampInt = B.clampInt
local json = B.json
local paginate = B.paginate
local requireProcess = B.requireProcess
local serverState = B.serverState

-- >>> BEGIN UNIT-30 Pointer path sets: comparing pointer chains across runs <<<
-- A pointer chain found in one run is only worth something if it still works after the target restarts. A "set" is a
-- named list of chains {module+RVA, offsets} kept inside the bridge and saved to a file (U26.stDir), so it outlives target
-- restarts, reloads of the bridge and restarts of Cheat Engine. find_pointer_path(save_as=) fills one in run 1; after the restart compare_pointer_paths re-resolves every
-- chain against the new address of the same value and keeps those that land on it. Saving the survivors back narrows
-- the set: a chain with runs=3 has reached its value in three separate runs.
U26.PS_MAX_SETS, U26.PS_MAX_CHAINS, U26.PS_MAX_DEPTH, U26.PS_MAX_HISTORY = 16, 5000, 16, 20
serverState.path_sets = {}

-- State files (pointer sets here, the patch journal in UNIT-31). Folder: the Lua global CE_MCP_STATE_DIR, else the
-- environment variable of that name ("off" disables saving), else the folder of ce_mcp_bridge.lua (B.BRIDGE_DIR), else %LOCALAPPDATA%, else CE's temp folder; the first one that is writable wins. A failed save never fails
-- the command: it is reported as save_error by list_pointer_sets / list_patches.
U26.PS_FILE, U26.PJ_FILE = "ce_mcp_pointer_sets.json", "ce_mcp_patch_journal.jsonl"

-- Windows paths use a backslash; a folder written with "/" (or a test on another OS) keeps its own separator.
function U26.stSep(dir)
    if dir:find("\\", 1, true) or not dir:find("/", 1, true) then return "\\" end
    return "/"
end

function U26.stDir()
    if serverState.state_dir ~= nil then return serverState.state_dir or nil end
    serverState.state_dir = false
    local cands = {}
    local cfg = rawget(_G, "CE_MCP_STATE_DIR") or os.getenv("CE_MCP_STATE_DIR")
    if type(cfg) == "string" and cfg ~= "" then
        if cfg:lower() == "off" then return nil end
        cands[1] = cfg
    else
        local dir = B.BRIDGE_DIR                       -- the folder of ce_mcp_bridge.lua, set by the loader (nil when unknown)
        if type(dir) == "string" and dir ~= "" then cands[#cands + 1] = dir end
        cands[#cands + 1] = os.getenv("LOCALAPPDATA")
        local ok, tmp = pcall(getTempFolder)
        if ok then cands[#cands + 1] = tmp end
    end
    for _, d in ipairs(cands) do
        if type(d) == "string" and d ~= "" then
            d = d:gsub("[\\/]+$", "")
            local probe = d .. U26.stSep(d) .. "ce_mcp_state.probe"
            local f = io.open(probe, "wb")
            if f then
                f:close()
                os.remove(probe)
                serverState.state_dir = d
                return d
            end
        end
    end
    if #cands > 0 then serverState.state_error = "no writable folder for the state files (set CE_MCP_STATE_DIR)" end
    return nil
end

function U26.stPath(file)
    local d = U26.stDir()
    return d and (d .. U26.stSep(d) .. file) or nil
end

-- Replace a state file. The new content goes to a .tmp copy first, so a crash never leaves half a file behind.
function U26.stWrite(file, text)
    local path = U26.stPath(file)
    if not path then return false end
    local tmp = path .. ".tmp"
    local f, err = io.open(tmp, "wb")
    if not f then serverState.state_error = "cannot write " .. tmp .. ": " .. tostring(err); return false end
    local ok, werr = f:write(text)
    f:close()
    if not ok then serverState.state_error = "cannot write " .. tmp .. ": " .. tostring(werr); return false end
    os.remove(path)
    local rok, rerr = os.rename(tmp, path)
    if not rok then serverState.state_error = "cannot replace " .. path .. ": " .. tostring(rerr); return false end
    serverState.state_error = nil
    return true
end

function U26.stRead(file)
    local path = U26.stPath(file)
    if not path then return nil end
    local f = io.open(path, "rb") or io.open(path .. ".tmp", "rb")     -- .tmp only: a save cut off between remove and rename
    if not f then return nil end
    local text = f:read("a")
    f:close()
    return text
end

function U26.stInfo(file)
    return U26.stPath(file), serverState.state_error
end

function U26.psName(v)
    if type(v) == "string" and #v <= 48 and v:match("^[%w_%.%-]+$") then return v end
    return nil, U26.err("Set names use letters, digits, '_', '.' and '-' (at most 48 characters)")
end

function U26.psCount()
    local n = 0
    for _ in pairs(serverState.path_sets) do n = n + 1 end
    return n
end

function U26.psInt(v)
    if type(v) == "string" then v = tonumber(v) end
    if math.type(v) == "float" then return math.tointeger(v) end
    if math.type(v) == "integer" then return v end
    return nil
end

function U26.psProcess()
    local ok, name = pcall(function() return process end)
    return { pid = getOpenedProcessID(), process = (ok and type(name) == "string") and name or nil }
end

function U26.psSigned(n) return n < 0 and "-" .. U26.hex(-n) or U26.hex(n) end

-- One chain as a client sends it ({base = "module+0xRVA" | address, offsets = {...}, runs = n}) -> stored record.
-- An address inside a loaded module is stored module-relative: that is the part that survives a restart.
function U26.psParseChain(c, mods)
    if type(c) ~= "table" then return nil, "not an object with base and offsets" end
    local raw = c.offsets
    if raw == nil then raw = {} end
    if type(raw) ~= "table" or #raw > U26.PS_MAX_DEPTH then
        return nil, "offsets must be a list of at most " .. U26.PS_MAX_DEPTH .. " integers"
    end
    local offs = {}
    for i, o in ipairs(raw) do
        local n = U26.psInt(o)
        if not n then return nil, "offsets[" .. i .. "] is not an integer" end
        offs[i] = n
    end
    local rec = { offsets = offs, runs = U26.psInt(c.runs) or 0 }
    local base = c.base
    if type(base) == "string" then
        local name, tail = base:match("^(.+)%+(%w+)$")
        local rva = tail and (tail:match("^0[xX]%x+$") and tonumber(tail) or (tail:match("^%x+$") and tonumber(tail, 16)))
        if name and rva then
            local lname = name:lower()
            for _, m in ipairs(mods) do        -- the loaded module's own spelling, so "GAME.EXE+10" and "game.exe+10" are one chain
                if m.name:lower() == lname then name = m.name; break end
            end
            rec.module, rec.rva = name, rva
            return rec
        end
        base = U26.addr(base)
    end
    base = U26.psInt(base)
    if not base then return nil, "base must be 'module+0xRVA' or an address" end
    local m = U26.moduleFor(mods, base)
    if m then rec.module, rec.rva = m.name, base - m.base else rec.abs = base end
    return rec
end

function U26.psBaseString(r)
    if r.module then return r.module .. "+" .. U26.hex(r.rva) end
    return U26.hex(r.abs)
end

-- CE-style expression: [[base]+o1]+o2 (a chain without offsets is just the base)
function U26.psExpression(r)
    if #r.offsets == 0 then return U26.psBaseString(r) end
    local expr = "[" .. U26.psBaseString(r) .. "]"
    for i, o in ipairs(r.offsets) do
        expr = expr .. (o < 0 and "-" .. U26.hex(-o) or "+" .. U26.hex(o))
        if i < #r.offsets then expr = "[" .. expr .. "]" end
    end
    return expr
end

function U26.psView(r)
    local hexOffs = {}
    for i, o in ipairs(r.offsets) do hexOffs[i] = U26.psSigned(o) end
    return { base = U26.psBaseString(r), offsets = r.offsets, offsets_hex = hexOffs, depth = #r.offsets,
             expression = U26.psExpression(r), runs = r.runs }
end

function U26.psCost(r)
    local c = 0
    for _, o in ipairs(r.offsets) do c = c + math.abs(o) end
    return c
end

function U26.psSummary(s)
    return { name = s.name, chain_count = #s.chains, runs = s.runs, arch = s.arch, created = s.created, updated = s.updated,
             history = s.history }
end

-- Follow one chain in the CURRENT process: "ok", finalAddress | "module_missing" | "unreadable"
function U26.psEval(rec, byName, is64)
    local cur = rec.abs
    if rec.module then
        local m = byName[rec.module:lower()]
        if not m then return "module_missing" end
        cur = m.base + rec.rva
    end
    for _, off in ipairs(rec.offsets) do
        local ptr = U26.ptr(cur, is64)
        if not ptr then return "unreadable" end
        cur = ptr + off
        if not is64 then cur = cur & 0xFFFFFFFF end
    end
    return "ok", cur
end

-- Store (replace) a set. Returns the set, or nil + reason. Never stores an empty set.
function U26.psPut(name, chains, runs, history)
    local n, nerr = U26.psName(name)
    if not n then return nil, nerr.error end
    if #chains == 0 then return nil, "nothing to store (an existing set is never overwritten with an empty one)" end
    if #chains > U26.PS_MAX_CHAINS then return nil, "a set holds at most " .. U26.PS_MAX_CHAINS .. " chains" end
    local old = serverState.path_sets[name]
    if not old and U26.psCount() >= U26.PS_MAX_SETS then
        return nil, "at most " .. U26.PS_MAX_SETS .. " sets are kept; drop_pointer_set one first"
    end
    while #history > U26.PS_MAX_HISTORY do table.remove(history, 1) end
    local now = os.time()
    local s = { name = name, chains = chains, runs = runs, history = history, created = old and old.created or now, updated = now,
                arch = targetIs64Bit() and "x64" or "x86" }
    serverState.path_sets[name] = s
    U26.psSave()
    return s
end

function U26.psSave()
    if not U26.stDir() then return end
    local list = {}
    for _, s in pairs(serverState.path_sets) do list[#list + 1] = s end
    table.sort(list, function(a, b) return a.name < b.name end)
    local ok, text = pcall(json.encode, { version = 1, sets = list })
    if ok then U26.stWrite(U26.PS_FILE, text) else serverState.state_error = "cannot encode the pointer sets: " .. tostring(text) end
end

-- one chain as it was saved -> record (nil when the file was edited into something that is not a chain)
function U26.psLoadChain(c)
    if type(c) ~= "table" or type(c.offsets) ~= "table" or #c.offsets > U26.PS_MAX_DEPTH then return nil end
    local offs = {}
    for i, o in ipairs(c.offsets) do
        offs[i] = U26.psInt(o)
        if not offs[i] then return nil end
    end
    local rec = { offsets = offs, runs = U26.psInt(c.runs) or 0 }
    if type(c.module) == "string" and c.module ~= "" and U26.psInt(c.rva) then
        rec.module, rec.rva = c.module, U26.psInt(c.rva)
    elseif U26.psInt(c.abs) then
        rec.abs = U26.psInt(c.abs)
    else
        return nil
    end
    return rec
end

-- Called once when the script is executed: the sets saved by the previous instance of the bridge come back.
function U26.psLoad()
    local text = U26.stRead(U26.PS_FILE)
    if not text then return 0 end
    local ok, data = pcall(json.decode, text)
    if not ok or type(data) ~= "table" or type(data.sets) ~= "table" then
        serverState.state_error = "ignored " .. U26.PS_FILE .. ": it is not a pointer set file"
        return 0
    end
    local n = 0
    for _, s in ipairs(data.sets) do
        local name = type(s) == "table" and U26.psName(s.name) or nil
        local chains = {}
        if name and type(s.chains) == "table" then
            for _, c in ipairs(s.chains) do
                local rec = U26.psLoadChain(c)
                if rec and #chains < U26.PS_MAX_CHAINS then chains[#chains + 1] = rec end
            end
        end
        if name and #chains > 0 and n < U26.PS_MAX_SETS and not serverState.path_sets[name] then
            local hist = {}
            if type(s.history) == "table" then
                for _, h in ipairs(s.history) do if type(h) == "table" then hist[#hist + 1] = h end end
            end
            while #hist > U26.PS_MAX_HISTORY do table.remove(hist, 1) end
            serverState.path_sets[name] = { name = name, chains = chains, runs = U26.psInt(s.runs) or 0, history = hist,
                                            created = U26.psInt(s.created) or os.time(), updated = U26.psInt(s.updated) or os.time(),
                                            arch = s.arch == "x86" and "x86" or "x64" }
            n = n + 1
        end
    end
    return n
end

-- find_pointer_path(save_as=): run 1 of a comparison
function U26.psSaveFound(name, recs, target)
    local pr = U26.psProcess()
    return U26.psPut(name, recs, 1, { { run = 1, at = os.time(), pid = pr.pid, process = pr.process, target = U26.hex(target),
                                         tested = #recs, survivors = #recs, source = "find_pointer_path" } })
end

-- Re-resolve every chain of a stored set (name) or an inline list (chains) against the address of the same value in
-- the process as it is NOW (target). Chains that land exactly on it have been confirmed in one more run.
function cmd_compare_pointer_paths(params)
    local okProc, perr = requireProcess()
    if not okProc then return perr end
    local target = U26.addr(params.target)
    if not target then return U26.err("Invalid target address", "INVALID_ADDRESS") end
    if (params.name == nil) == (params.chains == nil) then
        return U26.err("Give exactly one of name (a stored set) or chains (a list of {base, offsets})")
    end
    local saveAs = params.save_as
    if saveAs ~= nil then
        local _, nerr = U26.psName(saveAs)
        if nerr then return nerr end
    end
    local nearDelta = clampInt(params.near_delta or 0x100, 0, 0x10000)
    local nearLimit = clampInt(params.near_limit or 10, 0, 100)

    local mods = U26.listModules()
    local src, input, duplicates = nil, {}, 0
    if params.name ~= nil then
        src = serverState.path_sets[params.name]
        if not src then return U26.err("No such pointer set: " .. tostring(params.name) .. " (list_pointer_sets shows them)", "NOT_FOUND") end
        input = src.chains
    else
        if type(params.chains) ~= "table" or #params.chains == 0 then return U26.err("chains must be a non-empty list") end
        if #params.chains > U26.PS_MAX_CHAINS then
            return U26.err("Too many chains (max " .. U26.PS_MAX_CHAINS .. "); compare them in pages")
        end
        local seenKey = {}
        for i, c in ipairs(params.chains) do
            local rec, why = U26.psParseChain(c, mods)
            if not rec then return U26.err("chains[" .. i .. "]: " .. why) end
            local key = U26.psExpression(rec)          -- the same chain written another way counts once
            if seenKey[key] then
                duplicates = duplicates + 1
            else
                seenKey[key] = true
                input[#input + 1] = rec
            end
        end
    end

    local is64 = targetIs64Bit()
    local byName = {}
    for _, m in ipairs(mods) do
        local k = m.name:lower()
        if not byName[k] then byName[k] = m end
    end

    local hits, near = {}, {}
    local counts = { missed = 0, unreadable = 0, module_missing = 0 }
    for idx, r in ipairs(input) do
        local status, final = U26.psEval(r, byName, is64)
        if status == "ok" and final == target then
            hits[#hits + 1] = { rec = r, idx = idx }
        elseif status == "ok" then
            counts.missed = counts.missed + 1
            local delta = final - target
            if nearLimit > 0 and math.abs(delta) <= nearDelta then near[#near + 1] = { rec = r, idx = idx, final = final, delta = delta } end
        else
            counts[status] = counts[status] + 1
        end
    end

    -- survivors: confirmed in the most runs first, then the shortest and smallest chains
    local survivors = {}
    for i, h in ipairs(hits) do
        local r = h.rec
        survivors[i] = { module = r.module, rva = r.rva, abs = r.abs, offsets = r.offsets, runs = r.runs + 1, idx = h.idx }
    end
    table.sort(survivors, function(a, b)
        if a.runs ~= b.runs then return a.runs > b.runs end
        if #a.offsets ~= #b.offsets then return #a.offsets < #b.offsets end
        local ca, cb = U26.psCost(a), U26.psCost(b)
        if ca ~= cb then return ca < cb end
        return a.idx < b.idx
    end)

    table.sort(near, function(a, b)
        local da, db = math.abs(a.delta), math.abs(b.delta)
        if da ~= db then return da < db end
        return a.idx < b.idx
    end)
    local nearOut = {}
    for i = 1, math.min(#near, nearLimit) do
        local n = near[i]
        local v = U26.psView(n.rec)
        v.final_address = U26.hex(n.final)
        v.delta = (n.delta >= 0 and "+" or "-") .. U26.hex(math.abs(n.delta))
        if #n.rec.offsets > 0 then          -- the last field moved by `delta`: the same chain with that offset corrected
            local fix = {}
            for k, o in ipairs(n.rec.offsets) do fix[k] = o end
            fix[#fix] = fix[#fix] - n.delta
            v.suggested_offsets = fix
        end
        nearOut[i] = v
    end

    local pr = U26.psProcess()
    local last = src and src.history[#src.history]
    local runNo = (src and src.runs or 0) + 1
    local notes = {}
    local sameProcess = last ~= nil and last.pid ~= nil and last.pid == pr.pid
    if sameProcess then
        notes[#notes + 1] = "Same process instance (pid " .. tostring(pr.pid) .. ") as the previous run: the target was not restarted, " ..
                            "so this only shows that the chains survive whatever happened since (level change, reallocation), not a restart."
    end
    if #hits == 0 then
        notes[#notes + 1] = "No chain reaches " .. U26.hex(target) .. ". Is it the same value in this run? Compare in a fresh state, or search again with find_pointer_path."
        if #near > 0 then
            notes[#notes + 1] = #near .. " chain(s) miss by a small distance (near_misses): the last offset probably moved; suggested_offsets shows the corrected chain."
        end
    end

    local out = { success = true, target = U26.hex(target), run = runNo, compared = #input, hits = #hits, missed = counts.missed,
                  unreadable = counts.unreadable, module_missing = counts.module_missing, same_process = sameProcess }
    if src then out.name = src.name end
    if duplicates > 0 then out.duplicates_ignored = duplicates end

    if saveAs ~= nil then
        if #hits == 0 then
            out.save_note = "not saved: no chain survived, so " .. (serverState.path_sets[saveAs] and "the existing set is unchanged" or "there is nothing to store")
        else
            local recs = {}
            for i, s in ipairs(survivors) do recs[i] = { module = s.module, rva = s.rva, abs = s.abs, offsets = s.offsets, runs = s.runs } end
            local hist = {}
            if src then for i, h in ipairs(src.history) do hist[i] = h end end
            hist[#hist + 1] = { run = runNo, at = os.time(), pid = pr.pid, process = pr.process, target = U26.hex(target),
                                tested = #input, survivors = #hits, source = src and "compare" or "inline" }
            local s, why = U26.psPut(saveAs, recs, runNo, hist)
            if s then
                out.saved_as, out.set = s.name, U26.psSummary(s)
            else
                out.save_note = "not saved: " .. why
            end
        end
    end
    if #notes > 0 then out.notes = notes end
    if #nearOut > 0 then out.near_misses = nearOut end

    local limit, offset, page, total = paginate(params, survivors, 100)
    local views = {}
    for i, s in ipairs(page) do views[i] = U26.psView(s) end
    out.total, out.offset, out.limit, out.returned = total, offset, limit, #views
    out.chains = views
    return out
end

function cmd_list_pointer_sets(params)
    local list = {}
    for _, s in pairs(serverState.path_sets) do list[#list + 1] = U26.psSummary(s) end
    table.sort(list, function(a, b)
        if a.created ~= b.created then return a.created < b.created end
        return a.name < b.name
    end)
    local path, saveErr = U26.stInfo(U26.PS_FILE)
    return { success = true, count = #list, sets = list, saved_to = path, save_error = saveErr }
end

function cmd_get_pointer_set(params)
    local s = serverState.path_sets[params.name]
    if not s then return U26.err("No such pointer set: " .. tostring(params.name), "NOT_FOUND") end
    local out = U26.psSummary(s)
    out.success = true
    local limit, offset, page, total = paginate(params, s.chains, 100)
    local views = {}
    for i, r in ipairs(page) do views[i] = U26.psView(r) end
    out.total, out.offset, out.limit, out.returned = total, offset, limit, #views
    out.chains = views
    return out
end

function cmd_drop_pointer_set(params)
    if params.all == true then
        local n = U26.psCount()
        serverState.path_sets = {}
        U26.psSave()
        return { success = true, deleted = n }
    end
    if not serverState.path_sets[params.name] then
        return U26.err("No such pointer set: " .. tostring(params.name), "NOT_FOUND")
    end
    serverState.path_sets[params.name] = nil
    U26.psSave()
    return { success = true, deleted = 1 }
end

U26.psLoad()

-- >>> END UNIT-30 <<<

-- >>> exports
