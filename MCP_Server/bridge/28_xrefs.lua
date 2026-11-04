-- ============================================================================
-- Cheat Engine MCP Bridge :: 28_xrefs
-- Cross-references (UNIT-28)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local JOB_KIND_NAMES = B.JOB_KIND_NAMES
local JOB_STARTERS = B.JOB_STARTERS
local U26 = B.U26
local clampInt = B.clampInt
local jobFinish = B.jobFinish
local requireProcess = B.requireProcess

-- >>> BEGIN UNIT-28 Cross-references <<<

-- ---------------------------------------------------------------------------
-- job: find_xrefs  (everything that references an address or a small range)
--   code: rel32/rel8 call, jmp and jcc; x64 rip-relative operands (lea/mov/cmp/call [rip+x] ...); absolute pointers
--   data: absolute pointers (pointer aligned) and, on x64, 32-bit RVAs (jump tables)
-- Hits are found by byte patterns and validated with the disassembler where an instruction is involved.
-- ---------------------------------------------------------------------------
U26.XREF_KINDS = { call = true, jmp = true, jcc = true, rip = true, abs_code = true, abs_data = true, rva = true }
U26.XREF_KIND_NAMES = "call, jmp, jcc, rip, abs (= abs_code + abs_data), abs_code, abs_data, rva"
U26.XREF_NEEDLE_LIMIT = 16                                   -- larger ranges are matched by value, not by byte string
U26.XREF_IMMS = { 0, 1, 2, 4 }                               -- immediate bytes that may follow a rip-relative displacement

-- kinds: nil/"" = all; otherwise a list or a comma separated string. Returns set  or  nil, message
function U26.xrefKinds(spec)
    local set, names = {}, {}
    if spec == nil or spec == "" or spec == "all" then
        for k in pairs(U26.XREF_KINDS) do set[k] = true end
        return set
    end
    if type(spec) == "string" then
        for w in spec:gmatch("[^,%s]+") do names[#names + 1] = w:lower() end
    elseif type(spec) == "table" then
        for _, w in ipairs(spec) do names[#names + 1] = tostring(w):lower() end
    else
        return nil, "kinds must be a list or a comma separated string"
    end
    for _, n in ipairs(names) do
        if n == "abs" then
            set.abs_code, set.abs_data = true, true
        elseif n == "all" then
            for k in pairs(U26.XREF_KINDS) do set[k] = true end
        elseif U26.XREF_KINDS[n] then
            set[n] = true
        else
            return nil, "Unknown kind '" .. n .. "'. Valid: " .. U26.XREF_KIND_NAMES
        end
    end
    if next(set) == nil then return nil, "kinds is empty" end
    return set
end

-- What does an instruction with a memory operand do to that memory? (read | write | read/write | address | call | jump)
-- Works on CE's "ADDR - BYTES - mnemonic operands" text as well as on the bare instruction.
U26.XREF_RMW = { add = 1, sub = 1, ["and"] = 1, ["or"] = 1, xor = 1, inc = 1, dec = 1, neg = 1, ["not"] = 1, adc = 1, sbb = 1,
                 xchg = 1, xadd = 1, cmpxchg = 1, cmpxchg8b = 1, cmpxchg16b = 1, bts = 1, btr = 1, btc = 1, shl = 1, shr = 1,
                 sar = 1, sal = 1, rol = 1, ror = 1, rcl = 1, rcr = 1, shld = 1, shrd = 1 }
U26.XREF_READONLY = { cmp = 1, test = 1, bt = 1, push = 1 }
function U26.xrefAccess(text)
    if type(text) ~= "string" then return nil end
    local ins = text:match("^.-%s%-%s.-%s%-%s(.*)$") or text
    while true do
        local rest = ins:match("^[Ll][Oo][Cc][Kk]%s+(.*)$") or ins:match("^[Rr][Ee][Pp][EeNnZz]*%s+(.*)$") or ins:match("^[Bb][Nn][Dd]%s+(.*)$")
        if not rest then break end
        ins = rest
    end
    local mn, ops = ins:lower():match("^(%S+)%s*(.*)$")
    if not mn then return nil end
    if mn == "lea" then return "address" end
    if mn == "call" then return "call" end
    if mn == "jmp" then return "jump" end
    local br = ops:find("[", 1, true)
    if not br then return nil end
    local comma = ops:find(",", 1, true)
    if comma and br > comma then return "read" end          -- memory is the source operand
    -- the memory operand is the destination (or the only operand)
    if mn:match("^v?mov") or mn:match("^set") or mn == "pop" or mn:match("^f?n?st") or mn:match("^fist") then return "write" end
    if U26.XREF_READONLY[mn] or mn:match("^v?u?comis") then return "read" end
    if U26.XREF_RMW[mn] then return "read/write" end
    if comma == nil then return "read" end                    -- push/mul/div/fld ... [mem]
    return "read/write"
end

-- Start of the instruction that contains the displacement/immediate field beginning at `fieldStart`, found by decoding
-- forward and taking the instruction that covers that byte. `ends` lists the end addresses the instruction may have; an
-- instruction that ends anywhere else (or starts at the field itself) means the bytes are not that kind of instruction.
-- Decoding starts at `floor` (a function start from .pdata: exact) or U26.XREF_RUNWAY bytes back (x86 decoding
-- resynchronises within a few instructions). Going backwards byte by byte would be ambiguous: the last byte of the
-- previous instruction often looks like a REX prefix (e.g. the 0x40 in `mov rax,[rax+40h]` before `call [rip+x]`).
-- Returns start, length  or nil.
U26.XREF_RUNWAY = 96
U26.XREF_RUNWAY_FROM_FUNCTION = 512
function U26.insnStart(fieldStart, ends, floor)
    local from = fieldStart - U26.XREF_RUNWAY
    if floor then from = math.max(floor, fieldStart - U26.XREF_RUNWAY_FROM_FUNCTION) end
    local pos = from
    while pos < fieldStart do
        local ok, len = pcall(getInstructionSize, pos)
        if not ok or type(len) ~= "number" or len < 1 then len = 1 end          -- undecodable byte: skip it
        local finish = pos + len
        if finish > fieldStart then
            for _, e in ipairs(ends) do
                if finish == e then return pos, e - pos end
            end
            return nil
        end
        pos = finish
    end
    return nil
end

-- Is `addr` the first byte of an instruction? Decodes forward from the same starting point as insnStart. Used for short
-- jumps: two bytes are enough for a coincidence (e.g. the `7D F0` of `cmp [rbp-10h],7` also reads as `jge -14`).
function U26.atBoundary(addr, floor)
    local pos = floor and math.max(floor, addr - U26.XREF_RUNWAY_FROM_FUNCTION) or (addr - U26.XREF_RUNWAY)
    while pos < addr do
        local ok, len = pcall(getInstructionSize, pos)
        if not ok or type(len) ~= "number" or len < 1 then len = 1 end
        pos = pos + len
    end
    return pos == addr
end

-- Builds the scan stages for one module. ctx: { want, lo, hiEx, exact, add(...), full() }
function U26.xrefModuleStages(ctx, mod, pe, stages)
    local is64, P = pe.is64, pe.ptrSize
    local mask = is64 and -1 or 0xFFFFFFFF
    local want, lo, hiEx, add = ctx.want, ctx.lo, ctx.hiEx, ctx.add
    local needles, rvaNeedles = {}, {}
    if ctx.exact then
        for t = lo, hiEx - 1 do
            if is64 or t <= 0xFFFFFFFF then
                needles[#needles + 1] = { t = t, bytes = is64 and string.pack("<I8", t) or string.pack("<I4", t) }
            end
            local r = t - mod.base
            if is64 and r >= 0 and r <= 0xFFFFFFFF then rvaNeedles[#rvaNeedles + 1] = { t = t, bytes = string.pack("<I4", r) } end
        end
    end

    -- ---- code
    local execRanges = U26.sectionRanges(pe, mod, true, true)
    local wantBranch = want.call or want.jmp or want.jcc
    if #execRanges > 0 and (wantBranch or (want.rip and is64) or want.abs_code) then
        stages[#stages + 1] = { ranges = execRanges, carry = 7, process = function(jb, data, dbase)
            if ctx.full() then return end
            local n = #data
            if want.call or want.jmp then
                local pos = 1
                while true do
                    local s = data:find("[\232\233]", pos)
                    if not s or s + 4 > n then break end
                    local kind = data:byte(s) == 232 and "call" or "jmp"
                    if want[kind] then
                        local a = dbase + s - 1
                        local t = (a + 5 + string.unpack("<i4", data, s + 1)) & mask
                        if t >= lo and t < hiEx then add(mod, pe, a, kind, t, { form = "rel32" }) end
                    end
                    pos = s + 1
                end
            end
            if want.jcc then
                local pos = 1
                while true do
                    local s = data:find("\15[\128-\143]", pos)
                    if not s or s + 5 > n then break end
                    local a = dbase + s - 1
                    local t = (a + 6 + string.unpack("<i4", data, s + 2)) & mask
                    if t >= lo and t < hiEx then add(mod, pe, a, "jcc", t, { form = "rel32" }) end
                    pos = s + 1
                end
            end
            if want.jmp or want.jcc then
                -- short jumps (EB, 70-7F) reach +-128 bytes, so only the positions around the target can match
                for a = math.max(dbase, lo - 129), math.min(dbase + n - 2, hiEx + 125) do
                    local b = data:byte(a - dbase + 1)
                    local kind = (b == 0xEB) and "jmp" or ((b >= 0x70 and b <= 0x7F) and "jcc" or nil)
                    if kind and want[kind] then
                        local rel = data:byte(a - dbase + 2)
                        if rel >= 128 then rel = rel - 256 end
                        local t = (a + 2 + rel) & mask
                        if t >= lo and t < hiEx then add(mod, pe, a, kind, t, { form = "rel8" }) end
                    end
                end
            end
            if want.rip and is64 then
                local imms = U26.XREF_IMMS
                local pos = 1
                while true do
                    local s = data:find(U26.MODRM_RIP, pos)
                    if not s or s + 4 > n then break end
                    local m = dbase + s - 1
                    local base = m + 5 + string.unpack("<i4", data, s + 1)
                    for i = 1, 4 do
                        local t = base + imms[i]
                        if t >= lo and t < hiEx then add(mod, pe, m, "rip", t, { imm = imms[i] }) end
                    end
                    pos = s + 1
                end
            end
            if want.abs_code then
                for _, nd in ipairs(needles) do
                    local pos = 1
                    while true do
                        local s = data:find(nd.bytes, pos, true)
                        if not s then break end
                        add(mod, pe, dbase + s - 1, "abs_code", nd.t, { width = P })
                        pos = s + 1
                    end
                end
            end
        end }
    end

    -- ---- data
    local dataRanges = U26.sectionRanges(pe, mod, false, false)
    if want.abs_data and #dataRanges > 0 then
        stages[#stages + 1] = { ranges = dataRanges, carry = P - 1, process = function(jb, data, dbase)
            if ctx.full() then return end
            if ctx.exact then
                for _, nd in ipairs(needles) do
                    local pos = 1
                    while true do
                        local s = data:find(nd.bytes, pos, true)
                        if not s then break end
                        local a = dbase + s - 1
                        if a % P == 0 then add(mod, pe, a, "abs_data", nd.t) end
                        pos = s + 1
                    end
                end
            else
                local fmt = is64 and "<I8" or "<I4"
                for i = ((P - dbase % P) % P) + 1, #data - P + 1, P do
                    local v = string.unpack(fmt, data, i)
                    if v >= lo and v < hiEx then add(mod, pe, dbase + i - 1, "abs_data", v) end
                end
            end
        end }
    end
    if want.rva and is64 then
        local ranges = {}
        for _, r in ipairs(dataRanges) do
            if r.name ~= ".pdata" then ranges[#ranges + 1] = r end       -- the exception table lists every function RVA
        end
        if #ranges > 0 then
            stages[#stages + 1] = { ranges = ranges, carry = 3, process = function(jb, data, dbase)
                if ctx.full() then return end
                if ctx.exact then
                    for _, nd in ipairs(rvaNeedles) do
                        local pos = 1
                        while true do
                            local s = data:find(nd.bytes, pos, true)
                            if not s then break end
                            local a = dbase + s - 1
                            if a % 4 == 0 then add(mod, pe, a, "rva", nd.t) end
                            pos = s + 1
                        end
                    end
                else
                    local rlo, rhi = lo - mod.base, hiEx - mod.base
                    for i = ((4 - dbase % 4) % 4) + 1, #data - 3, 4 do
                        local v = string.unpack("<I4", data, i)
                        if v >= rlo and v < rhi then add(mod, pe, dbase + i - 1, "rva", v + mod.base) end
                    end
                end
            end }
        end
    end
end

-- Turns one raw hit into a result item (or nil to drop a false positive).
function U26.xrefItem(st, r)
    local mod, pe = r.mod, r.pe
    local addr, item = r.addr, { kind = r.kind, target = U26.hex(r.target) }
    local fn
    if r.kind ~= "abs_data" and r.kind ~= "rva" then fn = U26.functionAt(mod, pe, r.addr - mod.base) end
    local floor = fn and (mod.base + fn.primary.begin_rva) or nil
    if r.form == "rel8" and not U26.atBoundary(r.addr, floor) then return nil end     -- two bytes in the middle of another instruction
    if r.kind == "rip" then
        local start = U26.insnStart(r.addr, { r.addr + 5 + r.imm }, floor)
        if not start then return nil end                          -- the bytes are not a rip-relative instruction
        addr = start
    elseif r.kind == "abs_code" then
        local ends = {}
        for i, e in ipairs(U26.XREF_IMMS) do ends[i] = r.addr + r.width + e end
        local start = U26.insnStart(r.addr, ends, floor)
        if start then
            addr = start
            item.field_address = U26.hex(r.addr)                  -- the pointer itself; `address` is the instruction
        end
    end
    local rva = addr - mod.base
    item.address, item.module, item.rva, item.expression = U26.hex(addr), mod.name, rva, mod.name .. "+" .. U26.hex(rva)
    if r.form then item.form = r.form end
    if st.size > 1 then item.offset_in_target = r.target - st.lo end
    local sec = U26.sectionFor(pe, rva)
    if sec then item.section = sec.name end
    if r.kind ~= "abs_data" and r.kind ~= "rva" then
        -- an absolute pointer that no instruction owns is data inside the code (e.g. an x86 switch table): no disassembly
        local text = (r.kind ~= "abs_code" or item.field_address) and disassemble(addr) or nil
        if text then
            item.instruction = text
            if r.kind == "rip" then item.access = U26.xrefAccess(text) end
        end
        if fn then
            item.function_start = mod.name .. "+" .. U26.hex(fn.primary.begin_rva)
            item.function_rva = fn.primary.begin_rva
        end
    end
    return item, addr
end

function U26.xrefResolveStep(job, deadline)
    local st = job._xr
    local recs = st.recs
    while st.i <= #recs do
        if os.clock() >= deadline then return false end
        local item, addr = U26.xrefItem(st, recs[st.i])
        if item then
            st.items[#st.items + 1] = { a = addr, base = recs[st.i].mod.base, item = item }
            if item.function_start then
                local g = st.groups[item.function_start]
                if g then g.count = g.count + 1 else st.groups[item.function_start] = { function_start = item.function_start, function_rva = item.function_rva, count = 1 } end
            end
        end
        st.i = st.i + 1
        job.progress.current = job.progress.current + 1
    end
    table.sort(st.items, function(x, y)
        if x.base ~= y.base then return x.base < y.base end
        if x.a ~= y.a then return x.a < y.a end
        return x.item.kind < y.item.kind
    end)
    local items, byKind = {}, {}
    for i, e in ipairs(st.items) do
        items[i] = e.item
        byKind[e.item.kind] = (byKind[e.item.kind] or 0) + 1
    end
    local groups = {}
    for _, g in pairs(st.groups) do groups[#groups + 1] = g end
    table.sort(groups, function(x, y) if x.count ~= y.count then return x.count > y.count end return x.function_rva < y.function_rva end)
    while #groups > 50 do groups[#groups] = nil end
    local fields = { target = U26.hex(st.lo), size = st.size, modules = st.modules, found = #items }
    if next(byKind) then fields.by_kind = byKind end
    if #groups > 0 then fields.functions = groups end
    if st.ctx.truncated then fields.truncated = true; st.notes[#st.notes + 1] = "stopped at max_results; raise it or narrow the module/kinds" end
    if #st.notes > 0 then fields.notes = st.notes end
    job.progress.current = job.progress.total
    jobFinish(job, "done", { result = { fields = fields, list_key = "references", items = items } })
    return true
end

JOB_STARTERS.find_xrefs = function(job, p)
    local okProc, perr = requireProcess()
    if not okProc then return perr end
    local target = U26.addr(p.address)
    if not target then return U26.err("Invalid address", "INVALID_ADDRESS") end
    local size = clampInt(p.size or 1, 1, 0x10000)
    local want, kerr = U26.xrefKinds(p.kinds)
    if not want then return U26.err(kerr) end
    local maxResults = clampInt(p.max_results or 5000, 1, 50000)

    local mods = U26.listModules()
    if #mods == 0 then return U26.err("No modules found (is a process attached?)", "NO_PROCESS") end
    local picked
    if p.module == "all" then
        picked = mods
    elseif p.module == nil or p.module == "" then
        picked = { U26.moduleFor(mods, target) or mods[1] }       -- the module that holds the target, else the main module
    else
        local m, merr = U26.findModule(p.module)
        if not m then return merr end
        picked = { m }
    end

    local recs, seen, notes = {}, {}, {}
    local ctx = { want = want, lo = target, hiEx = target + size, exact = size <= U26.XREF_NEEDLE_LIMIT, truncated = false }
    ctx.full = function() return ctx.truncated end
    ctx.add = function(mod, pe, addr, kind, tgt, extra)
        local key = kind .. ":" .. addr .. ":" .. tostring(extra and extra.imm or 0)
        if seen[key] then return end
        if #recs >= maxResults then ctx.truncated = true; return end
        seen[key] = true
        local r = { mod = mod, pe = pe, addr = addr, kind = kind, target = tgt }
        if extra then for k, v in pairs(extra) do r[k] = v end end
        recs[#recs + 1] = r
    end

    local stages, scanned = {}, {}
    for _, mod in ipairs(picked) do
        local pe = U26.parsePE(mod.base)
        if pe then
            scanned[#scanned + 1] = mod.name
            U26.xrefModuleStages(ctx, mod, pe, stages)
        else
            notes[#notes + 1] = mod.name .. ": no readable PE header, skipped"
        end
    end
    if #scanned == 0 then return U26.err("None of the selected modules has a readable PE header", "INTERNAL_ERROR") end
    if not ctx.exact and want.abs_code then
        notes[#notes + 1] = "absolute pointers in code are only searched for targets of at most " .. U26.XREF_NEEDLE_LIMIT .. " bytes (size)"
    end

    U26.startStages(job, stages, function(jb)
        table.sort(recs, function(x, y)
            if x.mod.base ~= y.mod.base then return x.mod.base < y.mod.base end
            if x.addr ~= y.addr then return x.addr < y.addr end
            return x.kind < y.kind
        end)
        jb._xr = { recs = recs, i = 1, items = {}, groups = {}, lo = ctx.lo, size = size, modules = scanned, notes = notes, ctx = ctx }
        jb.progress.total = jb.progress.total + #recs         -- resolving the hits (disassembly, functions) is the second half
        jb._step = U26.xrefResolveStep
        return false
    end)
end
JOB_KIND_NAMES[#JOB_KIND_NAMES + 1] = "find_xrefs"

-- >>> END UNIT-28 <<<

-- >>> exports
