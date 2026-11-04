-- ============================================================================
-- Cheat Engine MCP Bridge :: 28_functions_structs
-- Functions (.pdata) and struct recovery (UNIT-27)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local U26 = B.U26
local clampInt = B.clampInt
local commandHandlers = B.commandHandlers
local requireProcess = B.requireProcess
local serverState = B.serverState

-- >>> BEGIN UNIT-27 Functions (.pdata), struct recovery <<<

-- ---------------------------------------------------------------------------
-- x64 function boundaries from the exception table (.pdata): exact start/end for every function that has
-- unwind data. (Leaf functions that never touch the stack have no entry; callers fall back to heuristics.)
-- ---------------------------------------------------------------------------
U26.pdataCache = {}

-- Returns { data = <raw RUNTIME_FUNCTION table>, count = n } or nil, reason
function U26.pdata(mod, pe)
    if pe.machine ~= 0x8664 then return nil, "no .pdata function table on this architecture (x64 only)" end
    local dir = pe.dirs[3]
    if not dir or dir.rva == 0 or dir.size < 12 then return nil, "module has no exception directory" end
    local key = string.format("%X:%X:%X", mod.base, pe.size_of_image, pe.timestamp)
    local cached = U26.pdataCache[key]
    if cached then return cached end
    local size = dir.size - dir.size % 12
    if size > 32 * 1024 * 1024 then return nil, "exception directory is implausibly large" end
    local data, bad = U26.readRegion(mod.base + dir.rva, size)
    if #bad > 0 then return nil, "exception directory is partially unreadable" end
    local n = 0
    for _ in pairs(U26.pdataCache) do n = n + 1 end
    if n >= 4 then U26.pdataCache = {} end
    local tbl = { data = data, count = size // 12 }
    U26.pdataCache[key] = tbl
    return tbl
end

function U26.pdataEntry(tbl, index)
    return string.unpack("<I4I4I4", tbl.data, index * 12 + 1)
end

-- Binary search (the table is sorted by BeginAddress). Returns begin, end, unwind (RVAs; end is exclusive) or nil.
function U26.pdataLookup(tbl, rva)
    local lo, hi = 0, tbl.count - 1
    while lo <= hi do
        local mid = (lo + hi) // 2
        local b, e, u = U26.pdataEntry(tbl, mid)
        if rva < b then hi = mid - 1
        elseif rva >= e then lo = mid + 1
        else return b, e, u end
    end
    return nil
end

U26.UNWIND_REGS = { [0] = "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" }

-- UNWIND_INFO: flags (exception handler / termination handler / chained), prolog size, frame register, handler RVA
-- or the chained parent RUNTIME_FUNCTION.
function U26.unwindInfo(mod, unwindRva)
    local hdr = U26.rd(mod.base + unwindRva, 4)
    if not hdr then return nil end
    local b0, prolog, ncodes, frame = string.unpack("<BBBB", hdr)
    local flags = b0 >> 3
    local info = { version = b0 & 7, prolog_size = prolog, code_count = ncodes }
    if (frame & 0xF) ~= 0 then
        info.frame_register = U26.UNWIND_REGS[frame & 0xF]
        info.frame_offset = (frame >> 4) * 16
    end
    local names = {}
    if (flags & 1) ~= 0 then names[#names + 1] = "EHANDLER" end
    if (flags & 2) ~= 0 then names[#names + 1] = "UHANDLER" end
    if (flags & 4) ~= 0 then names[#names + 1] = "CHAININFO" end
    info.flags = names
    local tail = unwindRva + 4 + ((ncodes + 1) & ~1) * 2         -- unwind codes are padded to an even count
    if (flags & 4) ~= 0 then
        local raw = U26.rd(mod.base + tail, 12)
        if raw then
            local b, e, u = string.unpack("<I4I4I4", raw)
            info.chain = { begin_rva = b, end_rva = e, unwind_rva = u }
        end
    elseif (flags & 3) ~= 0 then
        local h = U26.u32(mod.base + tail)
        if h then info.handler_rva = h end
    end
    return info
end

-- The function covering `rva`. Chained entries (cold/split fragments) are resolved to their primary function.
-- Returns { entry, unwind, primary, primary_unwind, fragment } or nil, reason
function U26.functionAt(mod, pe, rva)
    local tbl, why = U26.pdata(mod, pe)
    if not tbl then return nil, why end
    local b, e, u = U26.pdataLookup(tbl, rva)
    if not b then return nil, "address is not covered by .pdata (leaf function, padding or data)" end
    local entry = { begin_rva = b, end_rva = e, unwind_rva = u }
    local info = U26.unwindInfo(mod, u)
    local primary, primaryInfo, hops = entry, info, 0
    while primaryInfo and primaryInfo.chain and hops < 8 do
        primary = { begin_rva = primaryInfo.chain.begin_rva, end_rva = primaryInfo.chain.end_rva, unwind_rva = primaryInfo.chain.unwind_rva }
        primaryInfo = U26.unwindInfo(mod, primary.unwind_rva)
        hops = hops + 1
    end
    return { entry = entry, unwind = info, primary = primary, primary_unwind = primaryInfo, fragment = (primary.begin_rva ~= entry.begin_rva) }
end

function U26.describeFunction(mod, fn, withUnwind)
    local p = fn.primary
    local out = {
        function_start = U26.hex(mod.base + p.begin_rva), function_end = U26.hex(mod.base + p.end_rva - 1),
        begin_rva = p.begin_rva, end_rva = p.end_rva, size = p.end_rva - p.begin_rva,
        expression = mod.name .. "+" .. U26.hex(p.begin_rva),
    }
    if fn.fragment then
        out.fragment = { begin_rva = fn.entry.begin_rva, end_rva = fn.entry.end_rva, address = U26.hex(mod.base + fn.entry.begin_rva) }
    end
    local info = fn.primary_unwind
    if withUnwind and info then
        out.unwind = info
        if fn.fragment and fn.unwind then out.fragment.unwind = fn.unwind end
    end
    if info and info.handler_rva then
        out.exception_handler = U26.hex(mod.base + info.handler_rva)
    end
    return out
end

-- Used by find_function_boundaries / analyze_function (defined earlier in the file, hence a global).
-- Returns { start, finish (exclusive), fragment, module } or nil when .pdata cannot answer.
function pdataFunctionBoundaries(addr)
    local mod = U26.moduleFor(U26.listModules(), addr)
    if not mod then return nil end
    local pe = U26.parsePE(mod.base)
    if not pe then return nil end
    local fn = U26.functionAt(mod, pe, addr - mod.base)
    if not fn then return nil end
    return { start = mod.base + fn.primary.begin_rva, finish = mod.base + fn.primary.end_rva,
             fragment = fn.fragment, module = mod, handler_rva = fn.primary_unwind and fn.primary_unwind.handler_rva }
end

-- pe_functions: with `address` -> the function that contains it; otherwise a page of the whole function table.
function cmd_pe_functions(params)
    local okProc, perr = requireProcess()
    if not okProc then return perr end
    local a
    if params.address ~= nil and params.address ~= "" then
        a = U26.addr(params.address)
        if not a then return U26.err("Invalid address", "INVALID_ADDRESS") end
    end
    local spec = params.module
    if (spec == nil or spec == "") and a then spec = a end
    local mod, pe, _, err = U26.peFor({ module = spec })
    if not mod then return err end
    local tbl, why = U26.pdata(mod, pe)
    if not tbl then
        return { success = true, module = mod.name, available = false, reason = why, total = 0, functions = {} }
    end

    if a then
        local fn, reason = U26.functionAt(mod, pe, a - mod.base)
        if not fn then
            return { success = true, module = mod.name, available = true, found = false, address = U26.hex(a), reason = reason }
        end
        local out = U26.describeFunction(mod, fn, true)
        out.success, out.module, out.available, out.found, out.address = true, mod.name, true, true, U26.hex(a)
        return out
    end

    local limit = clampInt(params.limit or 100, 1, 1000)
    local offset = clampInt(params.offset or 0, 0, math.max(0, tbl.count - 1))
    local list = {}
    for i = offset, math.min(tbl.count, offset + limit) - 1 do
        local b, e, u = U26.pdataEntry(tbl, i)
        local item = { begin_rva = b, end_rva = e, size = e - b, address = U26.hex(mod.base + b), expression = mod.name .. "+" .. U26.hex(b) }
        if params.include_unwind then
            local info = U26.unwindInfo(mod, u)
            if info then
                item.prolog_size, item.flags, item.frame_register = info.prolog_size, info.flags, info.frame_register
                if info.handler_rva then item.exception_handler = U26.hex(mod.base + info.handler_rva) end
                if info.chain then item.chained_to = mod.name .. "+" .. U26.hex(info.chain.begin_rva) end
            end
        end
        list[#list + 1] = item
    end
    return { success = true, module = mod.name, available = true, total = tbl.count, offset = offset, limit = limit, returned = #list, functions = list }
end

-- ---------------------------------------------------------------------------
-- Struct recovery: MSVC RTTI behind the object's vtable + field inference from live instances
-- ---------------------------------------------------------------------------

-- Base classes of a class hierarchy descriptor: { { name, offset, virtual, contained } ... } (first entry = the class itself)
function U26.readBases(mod, pe, cdRef)
    local is64, P = pe.is64, pe.ptrSize
    local bases = {}
    local hdr = U26.rd(is64 and (mod.base + cdRef) or cdRef, 16)
    if not hdr then return bases end
    local _, _, nb, arr = string.unpack("<I4I4I4I4", hdr)
    local arrAddr = is64 and (mod.base + arr) or arr
    for i = 0, math.min(nb, 64) - 1 do
        local e = U26.rd(arrAddr + i * 4, 4)
        if not e then break end
        local ref = string.unpack("<I4", e)
        local bcd = U26.rd(is64 and (mod.base + ref) or ref, 24)    -- type descriptor, contained bases, PMD{mdisp,pdisp,vdisp}, attributes
        if bcd then
            local tref, contained, mdisp, pdisp = string.unpack("<I4I4i4i4", bcd)
            local nm = U26.cstr((is64 and (mod.base + tref) or tref) + 2 * P, 512)
            bases[#bases + 1] = { name = U26.demangle(nm), offset = mdisp, virtual = (pdisp ~= -1), contained = contained }
        end
    end
    return bases
end

-- RTTI for the vtable at `vtAddr`: the complete object locator sits in the slot just before it.
-- Returns { module, pe, class_name, raw_name, is_struct, vtable, vtable_rva, this_offset, bases } or nil, reason
function U26.rttiAtVtable(vtAddr, mods, peCache)
    mods = mods or U26.listModules()
    peCache = peCache or {}
    local mod = U26.moduleFor(mods, vtAddr)
    if not mod then return nil, "the vtable pointer is not inside a loaded module" end
    local pe = peCache[mod.base]
    if pe == nil then
        pe = U26.parsePE(mod.base) or false
        peCache[mod.base] = pe
    end
    if not pe then return nil, "the module has no readable PE header" end
    local P, is64 = pe.ptrSize, pe.is64
    local colVa = U26.ptr(vtAddr - P, is64)
    if not colVa or colVa < mod.base or colVa >= mod.base + mod.size then return nil, "no object locator before the vtable" end
    local raw = U26.rd(colVa, is64 and 24 or 20)
    if not raw then return nil, "the object locator is unreadable" end
    local sig, thisOff, _, tdRef, cdRef, selfRef = string.unpack(is64 and "<I4I4I4I4I4I4" or "<I4I4I4I4I4", raw)
    if is64 then
        if sig ~= 1 or selfRef ~= colVa - mod.base then return nil, "not an RTTI object locator" end
    elseif sig ~= 0 then
        return nil, "not an RTTI object locator"
    end
    local name, terminated = U26.cstr((is64 and (mod.base + tdRef) or tdRef) + 2 * P, 512)
    if not terminated or not name:match("^%.%?A[VU]") then return nil, "the type descriptor has no class name" end
    return {
        module = mod, pe = pe, class_name = U26.demangle(name), raw_name = name, is_struct = (name:sub(4, 4) == "U"),
        vtable = vtAddr, vtable_rva = vtAddr - mod.base, this_offset = thisOff, bases = U26.readBases(mod, pe, cdRef),
    }
end

-- ---- value classification ------------------------------------------------------------------------
function U26.plausibleFloat(d)
    if d == 0 or d <= 0xFFFF or d >= 0xFFFF0000 then return false end      -- 0 and small ints (either sign) are ints
    local f = string.unpack("<f", string.pack("<I4", d))
    if f ~= f then return false end
    local a = math.abs(f)
    return a >= 1e-6 and a <= 1e7
end

function U26.plausibleDouble(q, low, high)
    if q == 0 then return false end
    local d = string.unpack("<d", string.pack("<I8", q))
    if d ~= d then return false end
    local a = math.abs(d)
    if a < 1e-9 or a > 1e12 then return false end
    -- A small non-zero low half is an int (or small negative int) sitting next to another field, not a mantissa.
    if low ~= 0 and (low <= 0xFFFF or low >= 0xFFFF0000) then return false end
    return not (U26.plausibleFloat(low) and U26.plausibleFloat(high))      -- two plausible floats side by side win
end

function U26.looksLikePointer(v, is64)
    if is64 then
        if v < 0x10000 or v > 0x7FFFFFFFFFFF then return false end
    elseif v < 0x10000 or v > 0xFFFEFFFF then
        return false
    end
    return U26.rd(v, 1) ~= nil
end

-- Printable ASCII text starting at addr (>= 4 chars, terminated by NUL within 32 bytes) or nil
function U26.printableAt(addr)
    local s
    for _, n in ipairs({ 32, 16, 8 }) do
        s = U26.rd(addr, n)
        if s then break end
    end
    if not s then return nil end
    local len = 0
    while len < #s do
        local b = s:byte(len + 1)
        if b < 0x20 or b > 0x7E then break end
        len = len + 1
    end
    if len >= 4 and (len == #s or s:byte(len + 1) == 0) then return s:sub(1, len) end
    return nil
end

-- What does a pointer value point at?  kind: vfptr | object | string | static | heap
function U26.describePointer(v, is64, mods, peCache)
    local mod = U26.moduleFor(mods, v)
    if mod then
        local info = U26.rttiAtVtable(v, mods, peCache)
        if info then return "vfptr", info.class_name end
        return "static", mod.name .. "+" .. U26.hex(v - mod.base)
    end
    local vp = U26.ptr(v, is64)
    if vp and vp >= 0x10000 and U26.moduleFor(mods, vp) then
        local info = U26.rttiAtVtable(vp, mods, peCache)
        if info then return "object", info.class_name end
    end
    local text = U26.printableAt(v)
    if text then return "string", text end
    return "heap", nil
end

function U26.cType(field)
    local k = field.kind
    if k == "vfptr" or k == "static" or k == "heap" then return "void *" end
    if k == "object" then return U26.idaName(field.points_to) .. " *" end
    if k == "string" then return "char *" end
    if k == "float" then return "float" end
    if k == "double" then return "double" end
    if k == "int" then return field.unsigned and "unsigned int" or "int" end
    return nil
end

U26.CE_STRUCT_TYPES = { vfptr = "pointer", static = "pointer", heap = "pointer", object = "pointer", string = "pointer",
                          float = "float", double = "double", int = "dword" }

-- Recover a class layout from live instance(s). `addresses` should be instances of the SAME class (more instances
-- = better type guesses: values that differ between instances are real data, equal ones may be constants).
function cmd_recover_struct(params)
    local okProc, perr = requireProcess()
    if not okProc then return perr end
    local rawList = type(params.addresses) == "table" and params.addresses or { params.address }
    if #rawList == 0 or #rawList > 16 then return U26.err("Give 1 to 16 instance addresses (address or addresses)") end
    local addrs = {}
    for i, v in ipairs(rawList) do
        addrs[i] = U26.addr(v)
        if not addrs[i] then return U26.err("Invalid address: " .. tostring(v), "INVALID_ADDRESS") end
    end
    local is64 = targetIs64Bit()
    local P = is64 and 8 or 4
    local mods, peCache = U26.listModules(), {}

    -- 1. which class is every instance?
    local info
    for i, a in ipairs(addrs) do
        local vptr = U26.ptr(a, is64)
        if not vptr then return U26.err("Unreadable memory at " .. U26.hex(a), "INVALID_ADDRESS") end
        local one, why = U26.rttiAtVtable(vptr, mods, peCache)
        if not one then
            return U26.err("No MSVC RTTI for the object at " .. U26.hex(a) .. " (" .. tostring(why) .. "). Only polymorphic classes with the vtable pointer at offset 0 can be identified.", "NOT_FOUND")
        end
        if i == 1 then
            info = one
        elseif one.raw_name ~= info.raw_name or one.vtable ~= info.vtable then
            return U26.err("Instances are of different classes: " .. info.class_name .. " (" .. U26.hex(addrs[1]) .. ") vs " .. one.class_name .. " (" .. U26.hex(a) .. ")")
        end
    end

    -- 2. read the instances (as much as is readable in all of them), drop the all-zero tail
    local want = clampInt(params.size or 0x100, 16, 0x4000)
    local data, size = {}, want
    for i, a in ipairs(addrs) do
        local n, s = want, nil
        while n >= 16 do
            s = U26.rd(a, n)
            if s then break end
            n = n // 2
        end
        if not s then return U26.err("Cannot read the object at " .. U26.hex(a), "INVALID_ADDRESS") end
        data[i] = s
        size = math.min(size, #s)
    end
    local last = 0
    for i = 1, #data do
        for o = size, 1, -1 do
            if data[i]:byte(o) ~= 0 then last = math.max(last, o); break end
        end
    end
    size = math.max(P, ((last + 3) // 4) * 4)

    -- 3. walk the object: vfptr, then pointers / text / doubles / floats / ints, zero runs become "unknown"
    local n = #addrs
    local fields = {}
    local function add(f) fields[#fields + 1] = f end
    local ptrFmt = is64 and "<I8" or "<I4"
    add({ offset = 0, size = P, kind = "vfptr", type = "vfptr", points_to = info.class_name, name = "vfptr",
          samples = { U26.hex(info.vtable) } })
    local off = P
    while off + 4 <= size do
        local done = false

        if off % P == 0 and off + P <= size then                    -- pointer-sized slot
            local vals, anyPtr, onlyPtrOrNull = {}, false, true
            for k = 1, n do
                local v = string.unpack(ptrFmt, data[k], off + 1)
                vals[k] = v
                if v ~= 0 then
                    if U26.looksLikePointer(v, is64) then anyPtr = true else onlyPtrOrNull = false end
                end
            end
            if anyPtr and onlyPtrOrNull then
                local first
                for k = 1, n do if vals[k] ~= 0 then first = vals[k]; break end end
                local kind, text = U26.describePointer(first, is64, mods, peCache)
                local f = { offset = off, size = P, kind = kind, points_to = text, samples = {} }
                for k = 1, math.min(n, 3) do f.samples[k] = vals[k] == 0 and "null" or U26.hex(vals[k]) end
                if kind == "vfptr" then f.type, f.name = "vfptr (" .. text .. ")", string.format("vfptr_%X", off)
                elseif kind == "object" then f.type, f.name = text .. " *", string.format("obj_%X", off)
                elseif kind == "string" then f.type, f.name = "char *", string.format("str_%X", off); f.text = text
                elseif kind == "static" then f.type, f.name = "void * (" .. text .. ")", string.format("sptr_%X", off)
                else f.type, f.name = "void *", string.format("ptr_%X", off) end
                add(f)
                off, done = off + P, true
            end
        end

        if not done then                                              -- inline text (char buffer)
            local s1 = data[1]
            local len = 0
            while off + len < size do
                local b = s1:byte(off + len + 1)
                if b < 0x20 or b > 0x7E then break end
                len = len + 1
            end
            if len >= 4 and off + len < size and s1:byte(off + len + 1) == 0 then
                local total = ((len + 1 + 3) // 4) * 4
                local f = { offset = off, size = total, kind = "text", type = "char[" .. total .. "]", name = string.format("text_%X", off), samples = {} }
                for k = 1, math.min(n, 3) do f.samples[k] = data[k]:sub(off + 1, off + len):gsub("[^\32-\126]", "?") end
                add(f)
                off, done = off + total, true
            end
        end

        if not done and off % 8 == 0 and off + 8 <= size then         -- double
            local q = string.unpack("<I8", data[1], off + 1)
            local low, high = q & 0xFFFFFFFF, (q >> 32) & 0xFFFFFFFF
            if U26.plausibleDouble(q, low, high) and not U26.looksLikePointer(q, true) then
                local ok = true
                for k = 2, n do
                    local qk = string.unpack("<I8", data[k], off + 1)
                    if qk ~= 0 and not U26.plausibleDouble(qk, qk & 0xFFFFFFFF, (qk >> 32) & 0xFFFFFFFF) then ok = false end
                end
                if ok then
                    local f = { offset = off, size = 8, kind = "double", type = "double", name = string.format("d_%X", off), samples = {} }
                    for k = 1, math.min(n, 3) do f.samples[k] = string.unpack("<d", data[k], off + 1) end
                    add(f)
                    off, done = off + 8, true
                end
            end
        end

        if not done then                                              -- 4-byte value: zero / float / int
            local vals, allZero, allFloat = {}, true, true
            for k = 1, n do
                local d = string.unpack("<I4", data[k], off + 1)
                vals[k] = d
                if d ~= 0 then
                    allZero = false
                    if not U26.plausibleFloat(d) then allFloat = false end
                end
            end
            local f
            if allZero then
                local prev = fields[#fields]
                if prev and prev.kind == "unknown" and prev.offset + prev.size == off then
                    prev.size = prev.size + 4
                    prev.type = "unknown[" .. prev.size .. "]"
                else
                    f = { offset = off, size = 4, kind = "unknown", type = "unknown[4]", name = string.format("unk_%X", off), samples = {} }
                end
            elseif allFloat then
                f = { offset = off, size = 4, kind = "float", type = "float", name = string.format("f_%X", off), samples = {} }
                for k = 1, math.min(n, 3) do f.samples[k] = string.unpack("<f", string.pack("<I4", vals[k])) end
            else
                f = { offset = off, size = 4, kind = "int", type = "int", name = string.format("i_%X", off), samples = {}, unsigned = true }
                for k = 1, math.min(n, 3) do
                    local sv = vals[k] >= 0x80000000 and vals[k] - 0x100000000 or vals[k]
                    f.samples[k] = sv
                    if sv < 0 then f.unsigned = false end
                end
            end
            if f then add(f) end
            off = off + 4
        end
    end

    -- 4. virtual functions (with exact sizes where .pdata knows them)
    local mod, pe = info.module, info.pe
    local vfCount = U26.countVfuncs(info.vtable, P, clampInt(params.max_vtable_entries or 64, 1, 512), U26.sectionRanges(pe, mod, true, true))
    local vfuncs = {}
    for i = 0, vfCount - 1 do
        local fa = U26.ptr(info.vtable + i * P, is64)
        local v = { index = i, address = U26.hex(fa), expression = mod.name .. "+" .. U26.hex(fa - mod.base) }
        local fn = U26.functionAt(mod, pe, fa - mod.base)
        if fn then v.function_size = fn.primary.end_rva - fn.primary.begin_rva end
        vfuncs[#vfuncs + 1] = v
    end

    -- 5. C declaration
    local cname = U26.idaName(info.class_name)
    local decl, forward, padN = {}, {}, 0
    local pos = 0
    for _, f in ipairs(fields) do
        if f.offset > pos then
            padN = padN + 1
            decl[#decl + 1] = string.format("    unsigned char _pad%d[%d];", padN, f.offset - pos)
        end
        local line
        if f.kind == "vfptr" and f.offset == 0 then
            line = "    void **vfptr;  // +0x0 " .. info.class_name .. " vtable"
        elseif f.kind == "text" then
            line = "    char " .. f.name .. "[" .. f.size .. "];"
        elseif f.kind == "unknown" then
            line = "    unsigned char " .. f.name .. "[" .. f.size .. "];"
        else
            local ct = U26.cType(f)
            if f.kind == "object" then forward[U26.idaName(f.points_to)] = true end
            line = "    " .. ct .. (ct:sub(-1) == "*" and "" or " ") .. f.name .. ";"
        end
        decl[#decl + 1] = line:find("//", 1, true) and line or (line .. string.format("  // +0x%X", f.offset))
        pos = f.offset + f.size
    end
    local fwd = {}
    for nm in pairs(forward) do if nm ~= cname then fwd[#fwd + 1] = "struct " .. nm .. ";" end end
    table.sort(fwd)
    local baseNames = {}
    for i, b in ipairs(info.bases) do if i > 1 then baseNames[#baseNames + 1] = b.name end end
    local text = (#fwd > 0 and (table.concat(fwd, "\n") .. "\n") or "") ..
        "struct " .. cname .. " {" .. (#baseNames > 0 and ("  // bases: " .. table.concat(baseNames, ", ")) or "") .. "\n" ..
        table.concat(decl, "\n") .. "\n};"

    local out = {
        success = true, class_name = info.class_name, raw_name = info.raw_name, kind = info.is_struct and "struct" or "class",
        module = mod.name, vtable = U26.hex(info.vtable), vtable_rva = info.vtable_rva, this_offset = info.this_offset,
        bases = info.bases, instances = n, size_analyzed = size, arch = is64 and "x64" or "x86",
        fields = fields, virtual_functions = vfuncs, c_declaration = text,
        notes = { n == 1 and "Single instance: pass several instances of the same class (addresses) to separate data from constants." or nil },
    }

    -- 6. optionally create the CE structure definition
    if params.create then
        local sname = (type(params.name) == "string" and params.name ~= "") and params.name or cname
        local okS, structure = pcall(createStructure, sname)
        if not okS or not structure then
            out.create_error = "createStructure failed: " .. tostring(structure)
        else
            pcall(function() structure.addToGlobalStructureList() end)
            local made = 0
            for _, f in ipairs(fields) do
                local vt = nil
                if f.kind == "text" then vt = vtString
                elseif U26.CE_STRUCT_TYPES[f.kind] then
                    vt = ({ pointer = vtPointer, float = vtSingle, double = vtDouble, dword = vtDword })[U26.CE_STRUCT_TYPES[f.kind]]
                end
                if vt then
                    local okE, el = pcall(function() return structure.addElement() end)
                    if okE and el then
                        pcall(function()
                            el.Name, el.Offset, el.Vartype = f.name, f.offset, vt
                            if f.kind == "text" then el.Bytesize = f.size end
                        end)
                        made = made + 1
                    end
                end
            end
            local id = serverState.structure_next_id
            serverState.structure_next_id = id + 1
            serverState.structures[id] = structure
            out.structure_id, out.structure_name, out.elements_created = id, sname, made
        end
    end
    return out
end

-- >>> END UNIT-27 <<<

-- Dispatcher entries (the dispatcher table itself is built in 25_dispatcher)
for name, handler in pairs({
    pe_functions = cmd_pe_functions,
    recover_struct = cmd_recover_struct,
}) do commandHandlers[name] = handler end

-- >>> exports
