-- ============================================================================
-- Cheat Engine MCP Bridge :: 27_analysis
-- Analysis: PE/modules, address translation, RTTI, string refs, code caves, pointer paths, snapshots (UNIT-26)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local JOB_KIND_NAMES = B.JOB_KIND_NAMES
local JOB_STARTERS = B.JOB_STARTERS
local USER_MODE_MAX = B.USER_MODE_MAX
local bytesToString = B.bytesToString
local clampInt = B.clampInt
local commandHandlers = B.commandHandlers
local ensurePump = B.ensurePump
local jobFinish = B.jobFinish
local onScanDone = B.onScanDone
local paginate = B.paginate
local requireProcess = B.requireProcess
local serverState = B.serverState

-- >>> BEGIN UNIT-26 Analysis: PE/modules, address translation, RTTI, string refs, code caves, pointer paths, snapshots <<<

local U26 = { CHUNK = 0x10000, SNAP_MAX_TOTAL = 128 * 1024 * 1024, SNAP_MAX_ONE = 64 * 1024 * 1024, SNAP_MAX_COUNT = 16 }
serverState.snapshots = {}
serverState.snapshot_bytes = 0
serverState.snapshot_seq = 0
serverState.rtti_cache = {}      -- lower(module name) -> RTTI items from the last rtti_scan job

function U26.err(msg, code)
    return { success = false, error = msg, error_code = code or "INVALID_PARAMS" }
end

function U26.addr(v)
    if type(v) == "number" then return v end
    if type(v) == "string" and v ~= "" then return getAddressSafe(v) end
    return nil
end

function U26.hex(n) return string.format("0x%X", n) end

-- ---------------------------------------------------------------------------
-- memory helpers (all reads go through readBytes so they behave like CE's own)
-- ---------------------------------------------------------------------------
function U26.rd(addr, n)
    local b = readBytes(addr, n, true)
    if not b then return nil end
    return bytesToString(b)
end

function U26.u32(a) local s = U26.rd(a, 4); if s then return (string.unpack("<I4", s)) end end
function U26.u64(a) local s = U26.rd(a, 8); if s then return (string.unpack("<I8", s)) end end
function U26.ptr(a, is64) if is64 then return U26.u64(a) end return U26.u32(a) end

-- NUL-terminated string (<= max bytes). Returns text, terminated?
function U26.cstr(addr, max)
    max = max or 256
    local out, got = {}, 0
    while got < max do
        local n = math.min(64, max - got)
        local s = U26.rd(addr + got, n)
        if not s then
            n = 1
            s = U26.rd(addr + got, 1)     -- near an unmapped page: step byte by byte
            if not s then break end
        end
        local nul = s:find("\0", 1, true)
        if nul then
            out[#out + 1] = s:sub(1, nul - 1)
            return table.concat(out), true
        end
        out[#out + 1] = s
        got = got + #s
    end
    return table.concat(out), false
end

-- ---------------------------------------------------------------------------
-- modules and PE headers
-- ---------------------------------------------------------------------------
function U26.listModules()
    local list = {}
    local ok, mods = pcall(enumModules, getOpenedProcessID())
    if not ok or type(mods) ~= "table" or #mods == 0 then ok, mods = pcall(enumModules) end
    if ok and type(mods) == "table" then
        for _, m in ipairs(mods) do
            if m and m.Address then
                list[#list + 1] = { name = m.Name or "???", base = m.Address, size = m.Size or 0, is64 = m.Is64Bit }
            end
        end
    end
    return list
end

function U26.moduleFor(mods, addr)
    for _, m in ipairs(mods) do
        if addr >= m.base and addr < m.base + m.size then return m end
    end
    return nil
end

-- spec: nil/"" = main module (first), module name (exact, then substring), or an address inside a module.
-- Returns module, nil, allModules   or   nil, errorReply
function U26.findModule(spec)
    local mods = U26.listModules()
    if #mods == 0 then return nil, U26.err("No modules found (is a process attached?)", "NO_PROCESS") end
    if spec == nil or spec == "" then return mods[1], nil, mods end
    if type(spec) == "string" then
        local l = spec:lower()
        for _, m in ipairs(mods) do if m.name:lower() == l then return m, nil, mods end end
        for _, m in ipairs(mods) do if m.name:lower():find(l, 1, true) then return m, nil, mods end end
    end
    local a = U26.addr(spec)
    if a then
        local m = U26.moduleFor(mods, a)
        if m then return m, nil, mods end
    end
    return nil, U26.err("Module not found: " .. tostring(spec), "NOT_FOUND")
end

U26.DIR_NAMES = { [0] = "export", "import", "resource", "exception", "security", "basereloc", "debug", "architecture",
                  "globalptr", "tls", "load_config", "bound_import", "iat", "delay_import", "clr_runtime", "reserved" }
U26.MACHINES = { [0x8664] = "x64", [0x14C] = "x86", [0xAA64] = "arm64", [0x1C4] = "arm" }

function U26.parsePE(base)
    local s = U26.rd(base, 0x1000) or U26.rd(base, 0x400)
    if not s or #s < 0x40 or s:sub(1, 2) ~= "MZ" then
        return nil, "No valid MZ header at " .. U26.hex(base)
    end
    local nt = string.unpack("<I4", s, 0x3D)
    if nt < 0x40 or nt + 0x108 > #s then
        local bigger = nt >= 0x40 and nt < 0x10000 and U26.rd(base, nt + 0x1000)
        if not bigger then return nil, "PE header lies outside the readable header page" end
        s = bigger
    end
    if s:sub(nt + 1, nt + 4) ~= "PE\0\0" then return nil, "Missing PE signature" end

    local pe = { base = base }
    local machine, nsec, stamp = string.unpack("<I2I2I4", s, nt + 5)
    local optSize, fileChars = string.unpack("<I2I2", s, nt + 21)
    local opt = nt + 24
    local magic = string.unpack("<I2", s, opt + 1)
    if magic ~= 0x20B and magic ~= 0x10B then return nil, "Unknown optional header magic " .. U26.hex(magic) end
    local is64 = (magic == 0x20B)
    pe.is64, pe.ptrSize = is64, is64 and 8 or 4
    pe.machine = machine
    pe.machine_name = U26.MACHINES[machine] or U26.hex(machine)
    pe.timestamp, pe.characteristics = stamp, fileChars
    pe.entry_rva = string.unpack("<I4", s, opt + 17)
    pe.preferred_base = is64 and string.unpack("<I8", s, opt + 25) or string.unpack("<I4", s, opt + 29)
    pe.section_alignment = string.unpack("<I4", s, opt + 33)
    pe.size_of_image, pe.size_of_headers = string.unpack("<I4I4", s, opt + 57)
    pe.subsystem, pe.dll_characteristics = string.unpack("<I2I2", s, opt + 69)
    local nDirs = string.unpack("<I4", s, opt + (is64 and 109 or 93))
    local dirOff = opt + (is64 and 112 or 96)
    pe.dirs = {}
    for i = 0, math.min(nDirs, 16) - 1 do
        local rva, size = string.unpack("<I4I4", s, dirOff + i * 8 + 1)
        pe.dirs[i] = { rva = rva, size = size }
    end

    local secOff = opt + optSize
    if secOff + nsec * 40 > #s then
        local bigger = U26.rd(base, secOff + nsec * 40)
        if not bigger then return nil, "Section table is unreadable" end
        s = bigger
    end
    pe.sections = {}
    for i = 0, math.min(nsec, 96) - 1 do
        local o = secOff + i * 40
        local name = s:sub(o + 1, o + 8):gsub("\0.*$", "")
        local vsize, vaddr, rawSize, rawPtr = string.unpack("<I4I4I4I4", s, o + 9)
        local chars = string.unpack("<I4", s, o + 37)
        local flags = ((chars & 0x40000000) ~= 0 and "r" or "-") .. ((chars & 0x80000000) ~= 0 and "w" or "-") .. ((chars & 0x20000000) ~= 0 and "x" or "-")
        pe.sections[#pe.sections + 1] = {
            name = name, rva = vaddr, vsize = vsize, raw_size = rawSize, raw_ptr = rawPtr,
            characteristics = chars, flags = flags,
            exec = (chars & 0x20000000) ~= 0, discardable = (chars & 0x02000000) ~= 0,
        }
    end
    return pe
end

function U26.sectionFor(pe, rva)
    for _, sec in ipairs(pe.sections) do
        if rva >= sec.rva and rva < sec.rva + math.max(sec.vsize, sec.raw_size) then return sec end
    end
    return nil
end

function U26.peFor(params)
    local okProc, perr = requireProcess()
    if not okProc then return nil, nil, nil, perr end
    local mod, merr, mods = U26.findModule(params.module)
    if not mod then return nil, nil, nil, merr end
    local pe, e = U26.parsePE(mod.base)
    if not pe then return nil, nil, nil, U26.err(e, "INTERNAL_ERROR") end
    return mod, pe, mods
end

function cmd_pe_info(params)
    local mod, pe, _, err = U26.peFor(params)
    if not mod then return err end
    local sections, dirs = {}, {}
    for i, sec in ipairs(pe.sections) do
        sections[i] = { name = sec.name, rva = sec.rva, rva_hex = U26.hex(sec.rva), virtual_size = sec.vsize, raw_size = sec.raw_size,
                        flags = sec.flags, characteristics = U26.hex(sec.characteristics), address = U26.hex(mod.base + sec.rva) }
    end
    for i = 0, 15 do
        local d = pe.dirs[i]
        if d and d.rva ~= 0 then dirs[#dirs + 1] = { name = U26.DIR_NAMES[i], index = i, rva = d.rva, rva_hex = U26.hex(d.rva), size = d.size } end
    end
    return {
        success = true, module = mod.name, base = U26.hex(mod.base), arch = pe.machine_name, is_64bit = pe.is64,
        entry_point_rva = pe.entry_rva, entry_point = U26.hex(mod.base + pe.entry_rva),
        preferred_image_base = U26.hex(pe.preferred_base), relocated = (pe.preferred_base ~= mod.base),
        size_of_image = pe.size_of_image, size_of_headers = pe.size_of_headers, subsystem = pe.subsystem,
        dll_characteristics = U26.hex(pe.dll_characteristics), timestamp = pe.timestamp,
        sections = sections, data_directories = dirs,
    }
end

function cmd_pe_imports(params)
    local mod, pe, mods, err = U26.peFor(params)
    if not mod then return err end
    local P = pe.ptrSize
    local dir = pe.dirs[1]
    local dllFilter = (type(params.dll) == "string" and params.dll ~= "") and params.dll:lower() or nil
    local entries, dlls = {}, {}
    if dir and dir.rva ~= 0 then
        local descBase = mod.base + dir.rva
        for di = 0, 4095 do
            local desc = U26.rd(descBase + di * 20, 20)
            if not desc then break end
            local oft, _, _, nameRva, ft = string.unpack("<I4I4I4I4I4", desc)
            if oft == 0 and nameRva == 0 and ft == 0 then break end
            local dllName = U26.cstr(mod.base + nameRva, 260) or "?"
            if not dllFilter or dllName:lower():find(dllFilter, 1, true) then
                local src = (oft ~= 0) and oft or ft
                local count = 0
                for idx = 0, 65535 do
                    local thunk = U26.ptr(mod.base + src + idx * P, pe.is64)
                    if not thunk or thunk == 0 then break end
                    entries[#entries + 1] = { dll = dllName, thunk = thunk, iat_rva = ft + idx * P }
                    count = count + 1
                end
                dlls[#dlls + 1] = { name = dllName, count = count }
            end
        end
    end

    local limit, offset, page, total = paginate(params, entries, 100)
    local ordBit = 1 << (P * 8 - 1)
    local out = {}
    for i, e in ipairs(page) do
        local item = { dll = e.dll, iat_rva = e.iat_rva, iat_address = U26.hex(mod.base + e.iat_rva) }
        if (e.thunk & ordBit) ~= 0 then
            item.ordinal = e.thunk & 0xFFFF
        else
            local hint = U26.rd(mod.base + e.thunk, 2)
            if hint then item.hint = (string.unpack("<I2", hint)) end
            item.name = U26.cstr(mod.base + e.thunk + 2, 256)
        end
        local resolved = U26.ptr(mod.base + e.iat_rva, pe.is64)
        if resolved then
            item.resolved = U26.hex(resolved)
            local rm = U26.moduleFor(mods, resolved)
            if rm then item.resolved_module = rm.name end
        end
        out[i] = item
    end
    return { success = true, module = mod.name, total = total, offset = offset, limit = limit, returned = #out, dlls = dlls, imports = out }
end

function cmd_pe_exports(params)
    local mod, pe, _, err = U26.peFor(params)
    if not mod then return err end
    local dir = pe.dirs[0]
    local entries = {}
    local dllName
    if dir and dir.rva ~= 0 then
        local ed = U26.rd(mod.base + dir.rva, 40)
        if not ed then return U26.err("Export directory is unreadable", "INTERNAL_ERROR") end
        local _, _, _, _, nameRva, ordBase, nFuncs, nNames, funcsRva, namesRva, ordsRva = string.unpack("<I4I4I2I2I4I4I4I4I4I4I4", ed)
        dllName = U26.cstr(mod.base + nameRva, 260)
        nFuncs, nNames = math.min(nFuncs, 65536), math.min(nNames, 65536)
        local funcsRaw = nFuncs > 0 and U26.rd(mod.base + funcsRva, nFuncs * 4) or ""
        local namesRaw = nNames > 0 and U26.rd(mod.base + namesRva, nNames * 4) or ""
        local ordsRaw = nNames > 0 and U26.rd(mod.base + ordsRva, nNames * 2) or ""
        if not funcsRaw or not namesRaw or not ordsRaw then return U26.err("Export tables are unreadable", "INTERNAL_ERROR") end
        local named = {}
        local function isForwarder(rva) return rva >= dir.rva and rva < dir.rva + dir.size end
        for i = 0, nNames - 1 do
            local nRva = string.unpack("<I4", namesRaw, i * 4 + 1)
            local ord = string.unpack("<I2", ordsRaw, i * 2 + 1)
            local fRva = ord < nFuncs and string.unpack("<I4", funcsRaw, ord * 4 + 1) or 0
            named[ord] = true
            local e = { name = U26.cstr(mod.base + nRva, 512), ordinal = ordBase + ord, rva = fRva }
            if fRva ~= 0 and isForwarder(fRva) then e.forwarder = U26.cstr(mod.base + fRva, 512) end
            entries[#entries + 1] = e
        end
        for ord = 0, nFuncs - 1 do
            if not named[ord] then
                local fRva = string.unpack("<I4", funcsRaw, ord * 4 + 1)
                if fRva ~= 0 then
                    local e = { ordinal = ordBase + ord, rva = fRva }
                    if isForwarder(fRva) then e.forwarder = U26.cstr(mod.base + fRva, 512) end
                    entries[#entries + 1] = e
                end
            end
        end
    end
    local filter = (type(params.name_contains) == "string" and params.name_contains ~= "") and params.name_contains:lower() or nil
    if filter then
        local kept = {}
        for _, e in ipairs(entries) do
            if e.name and e.name:lower():find(filter, 1, true) then kept[#kept + 1] = e end
        end
        entries = kept
    end
    local limit, offset, page, total = paginate(params, entries, 100)
    for _, e in ipairs(page) do
        e.rva_hex = U26.hex(e.rva)
        e.address = U26.hex(mod.base + e.rva)
    end
    return { success = true, module = mod.name, export_name = dllName, total = total, offset = offset, limit = limit, returned = #page, exports = page }
end

function cmd_pe_tls_callbacks(params)
    local mod, pe, mods, err = U26.peFor(params)
    if not mod then return err end
    local dir = pe.dirs[9]
    if not dir or dir.rva == 0 then
        return { success = true, module = mod.name, has_tls = false, callbacks = {} }
    end
    local P = pe.ptrSize
    local td = U26.rd(mod.base + dir.rva, P == 8 and 40 or 24)
    if not td then return U26.err("TLS directory is unreadable", "INTERNAL_ERROR") end
    local startRaw, endRaw, indexAddr, cbArray, zeroFill, chars
    if pe.is64 then
        startRaw, endRaw, indexAddr, cbArray, zeroFill, chars = string.unpack("<I8I8I8I8I4I4", td)
    else
        startRaw, endRaw, indexAddr, cbArray, zeroFill, chars = string.unpack("<I4I4I4I4I4I4", td)
    end
    local callbacks = {}
    if cbArray ~= 0 then
        for i = 0, 63 do
            local va = U26.ptr(cbArray + i * P, pe.is64)
            if not va or va == 0 then break end
            local c = { address = U26.hex(va), rva = va - mod.base, rva_hex = U26.hex(va - mod.base) }
            local sec = U26.sectionFor(pe, va - mod.base)
            if sec then c.section = sec.name end
            local m = U26.moduleFor(mods, va)
            if m then c.module = m.name end
            callbacks[#callbacks + 1] = c
        end
    end
    return {
        success = true, module = mod.name, has_tls = true, callback_count = #callbacks, callbacks = callbacks,
        raw_data_start = U26.hex(startRaw), raw_data_end = U26.hex(endRaw), index_address = U26.hex(indexAddr),
        callbacks_array = U26.hex(cbArray), size_of_zero_fill = zeroFill, characteristics = chars,
    }
end

-- ---------------------------------------------------------------------------
-- address translation (CE <-> IDA / any rebased image)
-- ---------------------------------------------------------------------------
function U26.baseOf(spec)
    if type(spec) == "number" then return spec end
    if type(spec) == "string" and spec ~= "" then
        local n = tonumber(spec)
        if n then return math.tointeger(n) or n end
        local m = U26.findModule(spec)
        if m then return m.base end
    end
    return nil
end

function U26.toList(single, many)
    if type(many) == "table" then return many, true end
    return { single }, false
end

function cmd_va_to_rva(params)
    local okProc, perr = requireProcess()
    if not okProc then return perr end
    local list, multi = U26.toList(params.address, params.addresses)
    local mods = U26.listModules()
    local peCache = {}
    local results = {}
    for i, raw in ipairs(list) do
        local a = U26.addr(raw)
        if not a then
            results[i] = { input = tostring(raw), found = false, error = "invalid address" }
        else
            local m = U26.moduleFor(mods, a)
            if not m then
                results[i] = { address = U26.hex(a), found = false }
            else
                local rva = a - m.base
                local r = { address = U26.hex(a), found = true, module = m.name, base = U26.hex(m.base), rva = rva, rva_hex = U26.hex(rva),
                            expression = m.name .. "+" .. U26.hex(rva) }
                if params.ida_image_base then
                    local ib = U26.baseOf(params.ida_image_base)
                    if ib then r.ida_address = U26.hex(ib + rva) end
                end
                if params.include_section ~= false then
                    peCache[m.base] = peCache[m.base] or { U26.parsePE(m.base) }
                    local pe = peCache[m.base][1]
                    local sec = pe and U26.sectionFor(pe, rva)
                    if sec then r.section, r.section_offset = sec.name, rva - sec.rva end
                end
                results[i] = r
            end
        end
    end
    if multi then return { success = true, count = #results, results = results } end
    local single = results[1] or { found = false }
    single.success = true
    return single
end

function cmd_rva_to_va(params)
    local okProc, perr = requireProcess()
    if not okProc then return perr end
    local mod, merr = U26.findModule(params.module)
    if not mod then return merr end
    local list, multi = U26.toList(params.rva, params.rvas)
    local ib = params.ida_image_base and U26.baseOf(params.ida_image_base) or nil
    local results = {}
    for i, raw in ipairs(list) do
        local rva = tonumber(raw)
        if not rva then
            results[i] = { input = tostring(raw), error = "invalid rva" }
        else
            rva = math.tointeger(rva) or rva
            local r = { rva = rva, rva_hex = U26.hex(rva), address = U26.hex(mod.base + rva), module = mod.name, in_module = rva >= 0 and rva < mod.size }
            if ib then r.ida_address = U26.hex(ib + rva) end
            results[i] = r
        end
    end
    if multi then return { success = true, module = mod.name, base = U26.hex(mod.base), count = #results, results = results } end
    local single = results[1]
    single.success = true
    return single
end

-- Moves addresses between two images that are loaded at different bases:
--   from_base|from_module -> to_base|to_module   (e.g. an IDA address into a running module)
function cmd_rebase_address(params)
    local from = U26.baseOf(params.from_base or params.from_module)
    local to = U26.baseOf(params.to_base or params.to_module)
    if not from or not to then
        return U26.err("Give from_base|from_module and to_base|to_module (hex number or module name)", "INVALID_PARAMS")
    end
    local list, multi = U26.toList(params.address, params.addresses)
    local results = {}
    for i, raw in ipairs(list) do
        local a = U26.addr(raw)
        if not a then
            results[i] = { input = tostring(raw), error = "invalid address" }
        else
            results[i] = { from = U26.hex(a), to = U26.hex(a - from + to), rva = a - from, rva_hex = U26.hex(a - from) }
        end
    end
    if multi then return { success = true, from_base = U26.hex(from), to_base = U26.hex(to), count = #results, results = results } end
    local single = results[1]
    single.success = true
    return single
end

-- ---------------------------------------------------------------------------
-- exporting / importing names (CE <-> IDA)
-- ---------------------------------------------------------------------------
function U26.demangle(raw)
    local body = raw:match("^%.%?A[VUTW](.*)@@$")
    if not body then return raw end
    if body:find("?$", 1, true) then return body end        -- template instantiation: keep MSVC text
    local parts = {}
    for part in body:gmatch("[^@]+") do
        if part:match("^%?A0x%x+$") then part = "(anonymous namespace)" end   -- MSVC's unnamed namespace marker
        table.insert(parts, 1, part)
    end
    return table.concat(parts, "::")
end

function U26.idaName(s)
    s = s:gsub("[^%w_]", "_")
    if s:match("^%d") then s = "_" .. s end
    return s
end

function U26.pyStr(s)
    return '"' .. tostring(s):gsub("\\", "\\\\"):gsub('"', "'"):gsub("[\r\n]", " ") .. '"'
end

function cmd_export_names(params)
    local okProc, perr = requireProcess()
    if not okProc then return perr end
    local mod, merr = U26.findModule(params.module)
    if not mod then return merr end
    local wanted = {}
    for _, s in ipairs(type(params.sources) == "table" and params.sources or { "symbols", "rtti" }) do wanted[s] = true end
    local fmt = params.format or "json"
    if fmt ~= "json" and fmt ~= "idapython" then return U26.err("format must be 'json' or 'idapython'") end
    local ib = params.ida_image_base and U26.baseOf(params.ida_image_base) or nil

    local entries, notes = {}, {}
    if wanted.symbols then
        local ok, syms = pcall(enumRegisteredSymbols)
        if ok and type(syms) == "table" then
            for _, sym in ipairs(syms) do
                local a = sym and sym.address
                local name = sym and (sym.symbolname or sym.name)
                if a and name and a >= mod.base and a < mod.base + mod.size then
                    entries[#entries + 1] = { rva = a - mod.base, name = name, kind = "symbol" }
                end
            end
        end
    end
    local rtti = serverState.rtti_cache[mod.name:lower()]
    if wanted.rtti then
        if rtti then
            for _, c in ipairs(rtti) do
                entries[#entries + 1] = { rva = c.vtable_rva, name = c.class_name .. "::vftable", kind = "vtable",
                                          comment = c.class_name .. " vtable (" .. c.vfunc_count .. " virtual functions)" }
            end
        else
            notes[#notes + 1] = "No RTTI data cached for " .. mod.name .. "; run rtti_scan_module first."
        end
    end
    table.sort(entries, function(a, b) if a.rva ~= b.rva then return a.rva < b.rva end return a.name < b.name end)
    for _, e in ipairs(entries) do
        e.rva_hex = U26.hex(e.rva)
        e.ida_name = U26.idaName(e.name)
        if ib then e.ida_address = U26.hex(ib + e.rva) end
    end

    local out = { success = true, module = mod.name, base = U26.hex(mod.base), count = #entries, notes = notes }
    if params.include_types ~= false and rtti and wanted.rtti then
        local decl, seen = {}, {}
        for _, c in ipairs(rtti) do
            local n = U26.idaName(c.class_name)
            if c.vfunc_count > 0 and not seen[n] then
                seen[n] = true
                local slots = {}
                for i = 0, c.vfunc_count - 1 do slots[#slots + 1] = "    void *vf" .. i .. ";" end
                decl[#decl + 1] = "struct " .. n .. "_vtbl {\n" .. table.concat(slots, "\n") .. "\n};"
                decl[#decl + 1] = "struct " .. n .. " {\n    " .. n .. "_vtbl *vfptr;\n};" .. (#c.bases > 1 and ("  // bases: " .. table.concat(c.bases, ", ")) or "")
            end
        end
        out.c_declarations = table.concat(decl, "\n")
    end
    if fmt == "json" then
        out.names = entries
    else
        local lines = {
            "# Generated by cheatengine-mcp-bridge (export_names) for module " .. mod.name,
            "import idaapi, idc",
            "base = idaapi.get_imagebase()",
            "NAMES = [",
        }
        for _, e in ipairs(entries) do
            lines[#lines + 1] = string.format("    (0x%X, %s, %s),", e.rva, U26.pyStr(e.ida_name), U26.pyStr(e.comment or e.name))
        end
        lines[#lines + 1] = "]"
        lines[#lines + 1] = "for rva, name, comment in NAMES:"
        lines[#lines + 1] = "    ea = base + rva"
        lines[#lines + 1] = "    idc.set_name(ea, name, idc.SN_NOWARN | idc.SN_NOCHECK)"
        lines[#lines + 1] = "    idc.set_cmt(ea, comment, 0)"
        lines[#lines + 1] = 'print("applied %d names" % len(NAMES))'
        out.script = table.concat(lines, "\n")
    end
    return out
end

function cmd_import_names(params)
    local okProc, perr = requireProcess()
    if not okProc then return perr end
    local names = params.names
    if type(names) ~= "table" or #names == 0 then
        return U26.err("names must be a non-empty array of {name, rva|address}")
    end
    if #names > 5000 then return U26.err("At most 5000 names per call") end
    local mod
    if params.module and params.module ~= "" then
        local m, merr = U26.findModule(params.module)
        if not m then return merr end
        mod = m
    end
    local ib = params.ida_image_base and U26.baseOf(params.ida_image_base) or nil
    local prefix = params.prefix or ""
    local okCount, failures = 0, {}
    for i, n in ipairs(names) do
        local name = type(n) == "table" and n.name
        local address
        if type(n) == "table" then
            if n.address ~= nil then
                address = U26.addr(n.address)
                if address and ib and params.address_is_ida then address = address - ib + (mod and mod.base or 0) end
            elseif n.rva ~= nil and mod then
                local rva = tonumber(n.rva)
                address = rva and (mod.base + (math.tointeger(rva) or rva))
            end
        end
        if type(name) ~= "string" or name == "" or not address then
            failures[#failures + 1] = { index = i, error = "needs name and (rva with module) or address" }
        else
            local r = cmd_register_symbol({ name = prefix .. name, address = address, do_not_save = params.do_not_save ~= false })
            if r.success then okCount = okCount + 1 else failures[#failures + 1] = { index = i, name = name, error = r.error } end
        end
    end
    while #failures > 50 do table.remove(failures) end
    return { success = true, registered = okCount, failed = #names - okCount, failures = failures }
end

function U26.structType(vt)
    local map = {}
    map[vtByte] = "unsigned char"; map[vtWord] = "unsigned short"; map[vtDword] = "unsigned int"
    map[vtQword] = "unsigned __int64"; map[vtSingle] = "float"; map[vtDouble] = "double"
    map[vtPointer] = "void *"
    return map[vt]
end

-- C declarations for CE structure definitions (feed to IDA's declare_c_type / "Local Types").
function cmd_export_structures(params)
    local okC, count = pcall(getStructureCount)
    if not okC then return U26.err("getStructureCount failed: " .. tostring(count), "CE_API_UNAVAILABLE") end
    local only = type(params.name) == "string" and params.name ~= "" and params.name or nil
    local decls, structs = {}, {}
    for si = 0, count - 1 do
        local okS, s = pcall(getStructure, si)
        if okS and s then
            local okN, sname = pcall(function() return s.Name end)
            if okN and sname and (not only or sname == only) then
                local els = {}
                local okCnt, cnt = pcall(function() return s.Count end)
                for i = 0, (okCnt and cnt or 0) - 1 do
                    local okE, el = pcall(function() return s.getElement(i) end)
                    if okE and el then
                        local name, offset, vt, size
                        pcall(function() name = el.Name end)
                        pcall(function() offset = el.Offset end)
                        pcall(function() vt = el.Vartype end)
                        pcall(function() size = el.Bytesize end)
                        els[#els + 1] = { name = (name and name ~= "") and name or ("field_" .. string.format("%X", offset or 0)), offset = offset or 0, vt = vt, size = size or 0 }
                    end
                end
                table.sort(els, function(a, b) return a.offset < b.offset end)
                local okSz, total = pcall(function() return s.Size end)
                local lines, pos, padN = {}, 0, 0
                for _, el in ipairs(els) do
                    local ctype = U26.structType(el.vt)
                    local sz = el.size
                    local declLine
                    if ctype and el.size > 0 then
                        declLine = "    " .. ctype .. " " .. U26.idaName(el.name) .. ";"
                    elseif el.size > 0 then
                        declLine = "    unsigned char " .. U26.idaName(el.name) .. "[" .. el.size .. "];"
                    end
                    if declLine then
                        if el.offset < pos then
                            lines[#lines + 1] = "    // overlapping field '" .. el.name .. "' at +" .. U26.hex(el.offset) .. " skipped"
                        else
                            if el.offset > pos then
                                padN = padN + 1
                                lines[#lines + 1] = "    unsigned char _pad" .. padN .. "[" .. (el.offset - pos) .. "];"
                            end
                            lines[#lines + 1] = declLine .. "  // +" .. U26.hex(el.offset)
                            pos = el.offset + sz
                        end
                    end
                end
                if okSz and total and total > pos then
                    padN = padN + 1
                    lines[#lines + 1] = "    unsigned char _pad" .. padN .. "[" .. (total - pos) .. "];"
                end
                decls[#decls + 1] = "struct " .. U26.idaName(sname) .. " {\n" .. table.concat(lines, "\n") .. "\n};"
                structs[#structs + 1] = { name = sname, elements = #els, size = okSz and total or nil }
            end
        end
    end
    return { success = true, count = #structs, structures = structs, c_declarations = table.concat(decls, "\n\n") }
end

-- ---------------------------------------------------------------------------
-- time-sliced chunk engine shared by the scanning jobs (rtti_scan, find_string_refs, find_code_caves)
-- stage = { ranges = {{base,size}...}, process = fn(job, data, dataBase), carry = N, onStart = fn, onDone = fn }
-- `carry` bytes of each chunk's tail are prepended to the next chunk so patterns can span chunk borders.
-- ---------------------------------------------------------------------------
function U26.stageStep(job, deadline)
    local stages = job._stages
    while os.clock() < deadline do
        local st = stages[job._si]
        if not st then return job._finish(job) end
        if job._started ~= job._si then
            job._started = job._si
            if st.onStart then st.onStart(job) end
        end
        local r = st.ranges[job._ri]
        if not r then
            if st.onDone then st.onDone(job) end
            job._si, job._ri, job._off, job._carry = job._si + 1, 1, 0, ""
        elseif job._off >= r.size then
            job._ri, job._off, job._carry = job._ri + 1, 0, ""
        else
            local n = math.min(U26.CHUNK, r.size - job._off)
            local addr = r.base + job._off
            local s = U26.rd(addr, n)
            if s then
                local carry = job._carry
                st.process(job, carry .. s, addr - #carry)
                local keep = st.carry or 0
                job._carry = keep > 0 and s:sub(-keep) or ""
            else
                job._carry = ""
                for sub = 0, n - 1, 4096 do      -- unreadable somewhere: salvage the readable pages
                    local ps = U26.rd(addr + sub, math.min(4096, n - sub))
                    if ps then st.process(job, ps, addr + sub) end
                end
            end
            job._off = job._off + n
            job.progress.current = job.progress.current + n
        end
    end
    return false
end

function U26.startStages(job, stages, finish)
    local total = 0
    for _, st in ipairs(stages) do for _, r in ipairs(st.ranges) do total = total + r.size end end
    job._stages, job._finish = stages, finish
    job._si, job._ri, job._off, job._carry, job._started = 1, 1, 0, "", 0
    job.progress = { current = 0, total = total }
    job.phase = "processing"
    job._step = U26.stageStep
    ensurePump()
end

function U26.sectionRanges(pe, mod, wantExec, includeDiscardable)
    local ranges = {}
    for _, sec in ipairs(pe.sections) do
        local size = math.max(sec.vsize, sec.raw_size)
        if size > 0 and sec.exec == wantExec and (includeDiscardable or not sec.discardable) then
            ranges[#ranges + 1] = { base = mod.base + sec.rva, size = size, name = sec.name }
        end
    end
    return ranges
end

function U26.inRanges(ranges, v)
    for _, r in ipairs(ranges) do
        if v >= r.base and v < r.base + r.size then return r end
    end
    return nil
end

-- Lua pattern class matching exactly these byte values. Punctuation must be escaped: a bare '%' (0x25) or '-' (0x2D)
-- inside a hand-written class changes its meaning (the old literal class silently lost modrm 0x25 = reg 4 = r12).
function U26.byteClass(bytes)
    local t = {}
    for i, b in ipairs(bytes) do
        local c = string.char(b)
        t[i] = c:match("%p") and ("%" .. c) or c
    end
    return "[" .. table.concat(t) .. "]"
end
U26.MODRM_RIP = U26.byteClass({ 0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D })   -- mod=00 rm=101 for every reg value
U26.LEA_RIP = "[\72\76\73\77]\141" .. U26.MODRM_RIP                                   -- REX.W/WR/WB/WRB + lea + [rip+disp32]

-- ---------------------------------------------------------------------------
-- job: rtti_scan  (MSVC RTTI: classes, vtables, virtual function counts, base classes)
-- ---------------------------------------------------------------------------
function U26.countVfuncs(vtAddr, P, maxEntries, execRanges)
    local count = 0
    local fmt = P == 8 and "<I8" or "<I4"
    while count < maxEntries do
        local want = math.min(32, maxEntries - count)
        local raw = U26.rd(vtAddr + count * P, want * P)
        local slots = want
        if not raw then
            raw = U26.rd(vtAddr + count * P, P)
            slots = 1
            if not raw then break end
        end
        for i = 0, slots - 1 do
            local v = string.unpack(fmt, raw, i * P + 1)
            if not U26.inRanges(execRanges, v) then return count end
            count = count + 1
        end
    end
    return count
end

JOB_STARTERS.rtti_scan = function(job, p)
    local mod, pe, _, err = U26.peFor(p)
    if not mod then return err end
    local is64, P = pe.is64, pe.ptrSize
    local maxEntries = clampInt(p.max_vtable_entries or 256, 1, 4096)
    local dataRanges = U26.sectionRanges(pe, mod, false, false)
    local execRanges = U26.sectionRanges(pe, mod, true, true)
    local tdSet, colSet, vtables = {}, {}, {}

    local stages = {
        { ranges = dataRanges, carry = 3, process = function(jb, data, dbase)
            local pos = 1
            while true do
                local s = data:find(".?A", pos, true)
                if not s then break end
                local kind = data:sub(s + 3, s + 3)
                if kind == "V" or kind == "U" then
                    local a = dbase + s - 1
                    local name, terminated = U26.cstr(a, 512)
                    if terminated and name:sub(-2) == "@@" then
                        local td = a - 2 * P
                        tdSet[is64 and (td - mod.base) or td] = { td = td, name = name, is_struct = (kind == "U") }
                    end
                end
                pos = s + 3
            end
        end },
        { ranges = dataRanges, process = function(jb, data, dbase)
            local first = ((4 - dbase % 4) % 4) + 1
            for i = first, #data - 3, 4 do
                local v = string.unpack("<I4", data, i)
                local td = tdSet[v]
                if td then
                    local col = dbase + i - 1 - 12
                    local raw = U26.rd(col, is64 and 24 or 20)
                    if raw then
                        local sig, thisOff, _, tdRef, cdRef, selfRef = string.unpack(is64 and "<I4I4I4I4I4I4" or "<I4I4I4I4I4", raw)
                        local ok
                        if is64 then
                            ok = (sig == 1 and selfRef == col - mod.base)
                        else
                            -- x86 locators carry no self reference, so sanity-check the class hierarchy descriptor too
                            -- (a base-class-descriptor reference to the same type would otherwise pass as a "locator")
                            ok = (sig == 0 and cdRef >= mod.base and cdRef < mod.base + mod.size)
                            if ok then
                                local chd = U26.rd(cdRef, 16)
                                if chd then
                                    local _, _, nb, arr = string.unpack("<I4I4I4I4", chd)
                                    ok = nb >= 1 and nb <= 64 and arr >= mod.base and arr < mod.base + mod.size
                                else
                                    ok = false
                                end
                            end
                        end
                        if ok then colSet[col] = { td = td, this_offset = thisOff, cd = cdRef } end
                    end
                end
            end
        end },
        { ranges = dataRanges, process = function(jb, data, dbase)
            local fmt = is64 and "<I8" or "<I4"
            local first = ((P - dbase % P) % P) + 1
            for i = first, #data - P + 1, P do
                local v = string.unpack(fmt, data, i)
                local info = colSet[v]
                if info then vtables[#vtables + 1] = { loc = dbase + i - 1, col = v, info = info } end
            end
        end },
    }

    U26.startStages(job, stages, function(jb)
        local items, classes = {}, {}
        for _, vt in ipairs(vtables) do
            local vtAddr = vt.loc + P
            local bases = {}
            for _, b in ipairs(U26.readBases(mod, pe, vt.info.cd)) do bases[#bases + 1] = b.name end
            local item = {
                class_name = U26.demangle(vt.info.td.name), raw_name = vt.info.td.name,
                kind = vt.info.td.is_struct and "struct" or "class",
                vtable = U26.hex(vtAddr), vtable_rva = vtAddr - mod.base,
                col = U26.hex(vt.col), this_offset = vt.info.this_offset,
                vfunc_count = U26.countVfuncs(vtAddr, P, maxEntries, execRanges), bases = bases,
            }
            items[#items + 1] = item
            classes[item.class_name] = true
        end
        table.sort(items, function(a, b) return a.vtable_rva < b.vtable_rva end)
        local nClasses = 0
        for _ in pairs(classes) do nClasses = nClasses + 1 end
        serverState.rtti_cache[mod.name:lower()] = items
        jb.progress.current = jb.progress.total
        jobFinish(jb, "done", { result = {
            fields = { module = mod.name, arch = pe.machine_name, class_count = nClasses, vtable_count = #items },
            list_key = "classes", items = items } })
        return true
    end)
end

-- ---------------------------------------------------------------------------
-- job: find_string_refs  (string text or address -> code/data that references it)
-- ---------------------------------------------------------------------------
function U26.utf16le(s)
    local out = {}
    for _, cp in utf8.codes(s) do
        if cp >= 0x10000 then
            cp = cp - 0x10000
            out[#out + 1] = string.pack("<I2I2", 0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF))
        else
            out[#out + 1] = string.pack("<I2", cp)
        end
    end
    return table.concat(out)
end

JOB_STARTERS.find_string_refs = function(job, p)
    local mod, pe, _, err = U26.peFor(p)
    if not mod then return err end
    local is64, P = pe.is64, pe.ptrSize
    local targets, ntargets = {}, 0
    local needle
    if p.address ~= nil and p.address ~= "" then
        local a = U26.addr(p.address)
        if not a then return U26.err("Invalid address", "INVALID_ADDRESS") end
        targets[a], ntargets = true, 1
    elseif type(p.text) == "string" and p.text ~= "" then
        needle = p.wide and U26.utf16le(p.text) or p.text
    else
        return U26.err("Give 'text' (string to look for) or 'address' (of the string)")
    end
    local anyMatch = (p.match == "any")
    local includeData = p.include_data ~= false
    local dataRanges = U26.sectionRanges(pe, mod, false, false)
    local codeRanges = U26.sectionRanges(pe, mod, true, true)
    local hits, seen, packed = {}, {}, {}

    local function addHit(addr, kind, target)
        local key = kind .. addr
        if seen[key] or #hits >= 20000 then return end
        seen[key] = true
        hits[#hits + 1] = { addr = addr, kind = kind, target = target }
    end
    local function packTargets()
        packed = {}
        for t in pairs(targets) do packed[#packed + 1] = { t = t, bytes = is64 and string.pack("<I8", t) or string.pack("<I4", t & 0xFFFFFFFF) } end
    end
    local function scanAbsolute(data, dbase, kind, aligned)
        for _, pk in ipairs(packed) do
            local pos = 1
            while true do
                local s = data:find(pk.bytes, pos, true)
                if not s then break end
                local a = dbase + s - 1
                if not aligned or a % P == 0 then addHit(a, kind, pk.t) end
                pos = s + 1
            end
        end
    end

    local stages = {}
    if needle then
        stages[#stages + 1] = { ranges = dataRanges, carry = #needle, process = function(jb, data, dbase)
            local pos = 1
            while ntargets < 64 do
                local s = data:find(needle, pos, true)
                if not s then break end
                if anyMatch or s == 1 or data:byte(s - 1) == 0 then
                    local a = dbase + s - 1
                    if not targets[a] then targets[a] = true; ntargets = ntargets + 1 end
                end
                pos = s + 1
            end
        end }
    end
    stages[#stages + 1] = { ranges = codeRanges, carry = 7, onStart = packTargets, process = function(jb, data, dbase)
        if is64 then
            local pos, lastStart = 1, #data - 6
            while true do
                local s = data:find(U26.LEA_RIP, pos)
                if not s or s > lastStart then break end
                local tgt = dbase + s - 1 + 7 + string.unpack("<i4", data, s + 3)
                if targets[tgt] then addHit(dbase + s - 1, "rip_lea", tgt) end
                pos = s + 1
            end
        end
        scanAbsolute(data, dbase, "abs_code", false)
    end }
    if includeData then
        stages[#stages + 1] = { ranges = dataRanges, carry = 7, process = function(jb, data, dbase)
            scanAbsolute(data, dbase, "abs_data", true)
        end }
    end

    U26.startStages(job, stages, function(jb)
        table.sort(hits, function(a, b) if a.addr ~= b.addr then return a.addr < b.addr end return a.kind < b.kind end)
        local items = {}
        for i, h in ipairs(hits) do
            local rva = h.addr - mod.base
            local item = { address = U26.hex(h.addr), kind = h.kind, target = U26.hex(h.target), rva = rva, expression = mod.name .. "+" .. U26.hex(rva) }
            local sec = U26.sectionFor(pe, rva)
            if sec then item.section = sec.name end
            local fn = U26.functionAt(mod, pe, rva)
            if fn then
                item.function_start = mod.name .. "+" .. U26.hex(fn.primary.begin_rva)
                item.function_rva = fn.primary.begin_rva
            end
            if h.kind ~= "abs_data" then item.instruction = disassemble(h.addr) or "???" end
            items[i] = item
        end
        local tlist = {}
        for t in pairs(targets) do tlist[#tlist + 1] = t end
        table.sort(tlist)
        for i, t in ipairs(tlist) do tlist[i] = U26.hex(t) end
        jb.progress.current = jb.progress.total
        jobFinish(jb, "done", { result = {
            fields = { module = mod.name, string_addresses = tlist, found = #items, note = is64 and "x64: rip-relative lea + absolute pointers" or "x86: absolute pointers" },
            list_key = "references", items = items } })
        return true
    end)
end

-- ---------------------------------------------------------------------------
-- job: find_code_caves  (runs of padding bytes in executable sections)
-- ---------------------------------------------------------------------------
JOB_STARTERS.find_code_caves = function(job, p)
    local mod, pe, _, err = U26.peFor(p)
    if not mod then return err end
    local byte = tonumber(p.byte or 0xCC)
    if byte ~= 0x00 and byte ~= 0x90 and byte ~= 0xCC then
        return U26.err("byte must be 0x00, 0x90 or 0xCC (padding bytes)")
    end
    local minSize = clampInt(p.min_size or 16, 2, 0x100000)
    local ranges
    if p.sections ~= "all" then
        ranges = U26.sectionRanges(pe, mod, true, true)
    else
        ranges = {}
        for _, sec in ipairs(pe.sections) do
            local size = math.max(sec.vsize, sec.raw_size)
            if size > 0 and not sec.discardable then ranges[#ranges + 1] = { base = mod.base + sec.rva, size = size, name = sec.name } end
        end
    end
    local pat = "[" .. string.char(byte) .. "]+"
    local caves, run = {}, nil

    local function closeRun()
        if run and run.len >= minSize and #caves < 100000 then caves[#caves + 1] = { addr = run.start, size = run.len } end
        run = nil
    end

    local stages = { { ranges = ranges, onDone = closeRun, process = function(jb, data, dbase)
        local pos = 1
        if run then
            if run.nextAddr == dbase then
                local s, e = data:find("^" .. pat)
                if s then
                    run.len, run.nextAddr = run.len + e, dbase + #data
                    if e == #data then return end          -- run continues into the next chunk
                    pos = e + 1
                end
            end
            closeRun()
        end
        while true do
            local s, e = data:find(pat, pos)
            if not s then break end
            if e == #data then
                run = { start = dbase + s - 1, len = e - s + 1, nextAddr = dbase + #data }
                break
            end
            if e - s + 1 >= minSize and #caves < 100000 then caves[#caves + 1] = { addr = dbase + s - 1, size = e - s + 1 } end
            pos = e + 1
        end
    end } }

    U26.startStages(job, stages, function(jb)
        table.sort(caves, function(a, b) if a.size ~= b.size then return a.size > b.size end return a.addr < b.addr end)
        local items = {}
        for i, c in ipairs(caves) do
            local rva = c.addr - mod.base
            local item = { address = U26.hex(c.addr), size = c.size, rva = rva, expression = mod.name .. "+" .. U26.hex(rva) }
            local sec = U26.sectionFor(pe, rva)
            if sec then item.section = sec.name end
            items[i] = item
        end
        jb.progress.current = jb.progress.total
        jobFinish(jb, "done", { result = {
            fields = { module = mod.name, byte = string.format("0x%02X", byte), min_size = minSize, found = #items },
            list_key = "caves", items = items } })
        return true
    end)
end

-- ---------------------------------------------------------------------------
-- job: find_pointer_path  (reverse pointer search: which static [[base]+o1]+o2... reaches an address)
-- CE has no scripted pointer scanner, so every level runs value-between memscans: "which aligned pointers hold a
-- value in [holder - max_offset, holder]". A memscan always walks the whole process, so it is the expensive part.
-- Holders that lie close together share ONE scan over the union of their windows (U26.ppClusters); each result is
-- then matched back to every holder whose window contains its value.
-- ---------------------------------------------------------------------------
U26.PP_MERGE_GAP, U26.PP_MAX_SPAN = 0x10000, 0x1000000

-- frontier entries -> clusters {lo, hi, entries sorted by t}. Windows [t - maxOffset, t] closer than PP_MERGE_GAP are
-- merged while the merged value range stays below PP_MAX_SPAN (a wider range only adds results nobody asked for).
function U26.ppClusters(frontier, maxOffset)
    local order = {}
    for i, e in ipairs(frontier) do order[i] = e end
    table.sort(order, function(a, b) return a.t < b.t end)
    local clusters, cur = {}, nil
    for _, e in ipairs(order) do
        local lo = math.max(1, e.t - maxOffset)
        if cur and lo <= cur.hi + U26.PP_MERGE_GAP and e.t - cur.lo <= U26.PP_MAX_SPAN then
            cur.hi = math.max(cur.hi, e.t)
            cur.entries[#cur.entries + 1] = e
        else
            cur = { lo = lo, hi = e.t, entries = { e } }
            clusters[#clusters + 1] = cur
        end
    end
    return clusters
end

-- index of the first entry (sorted by t) with t >= val
function U26.ppFirstAtOrAbove(entries, val)
    local lo, hi = 1, #entries
    while lo <= hi do
        local mid = (lo + hi) // 2
        if entries[mid].t < val then lo = mid + 1 else hi = mid - 1 end
    end
    return lo
end

JOB_STARTERS.find_pointer_path = function(job, p)
    local target = U26.addr(p.address)
    if not target then return U26.err("Invalid address", "INVALID_ADDRESS") end
    local is64 = targetIs64Bit()
    local P = is64 and 8 or 4
    local maxDepth = clampInt(p.max_depth or 3, 1, 6)
    local maxOffset = clampInt(p.max_offset or 0x400, 0, 0x100000)
    local beam = clampInt(p.max_per_level or 16, 1, 256)
    local perScan = clampInt(p.max_results_per_scan or 2000, 10, 50000)
    local maxFound = clampInt(p.max_results or 100, 1, 1000)
    local protect = p.protection or "+W"
    if p.save_as ~= nil then
        local _, nerr = U26.psName(p.save_as)             -- fail now, not after minutes of scanning
        if nerr then return nerr end
    end
    local mods = U26.listModules()
    local st = { frontier = { { t = target, offs = {}, cost = 0 } }, ci = 1, depth = 1, best = {}, found = {}, scans = 0, searched = 0,
                 truncated = false, seen = { [target] = true } }
    st.clusters = U26.ppClusters(st.frontier, maxOffset)
    local onScan

    local function chainExpression(base, offs)
        local expr = "[" .. base .. "]"
        for i, o in ipairs(offs) do
            expr = expr .. "+" .. U26.hex(o)
            if i < #offs then expr = "[" .. expr .. "]" end
        end
        return expr
    end

    local function finish(j)
        table.sort(st.found, function(a, b)
            if #a.offs ~= #b.offs then return #a.offs < #b.offs end
            return a.cost < b.cost
        end)
        local items, keep = {}, {}
        for i, f in ipairs(st.found) do
            if i > maxFound then break end
            local baseStr = f.module .. "+" .. U26.hex(f.rva)
            local chain = resolveChain(f.base, f.offs)
            local hexOffs = {}
            for k, o in ipairs(f.offs) do hexOffs[k] = U26.hex(o) end
            local verified = (chain.ok == true and chain.final_address == target)
            items[#items + 1] = {
                base = baseStr, base_address = U26.hex(f.base), offsets = f.offs, offsets_hex = hexOffs,
                depth = #f.offs, expression = chainExpression(baseStr, f.offs),
                verified = verified,
            }
            if verified then keep[#keep + 1] = { module = f.module, rva = f.rva, offsets = f.offs, runs = 1 } end
        end
        j.progress = { current = st.scans, total = math.max(st.scans, 1) }
        local fields = { target = U26.hex(target), arch = is64 and "x64" or "x86", max_depth = maxDepth, max_offset = maxOffset,
                         scans = st.scans, holders_searched = st.searched, truncated = st.truncated, found = #items,
                         hint = "After the target restarts, find the same value again and run compare_pointer_paths(name=<set>, target=<new address>); " ..
                                "pass save_as here to keep these chains in a set. (validate_pointer_chains takes the chains inline.)" }
        if p.save_as ~= nil then
            local s, why = U26.psSaveFound(p.save_as, keep, target)
            if s then
                fields.saved_as, fields.set = s.name, U26.psSummary(s)
            else
                fields.save_note = "not saved: " .. why
            end
        end
        jobFinish(j, "done", { result = { fields = fields, list_key = "chains", items = items } })
        return true
    end

    local function launch(j)
        local cl = st.clusters[st.ci]
        local ms = createMemScan()
        j._ms, j._temp, j._scan_done = ms, true, false
        j.phase = "scanning"
        j._after_scan = onScan
        ms.OnScanDone = onScanDone(j)
        ms.firstScan(soValueBetween, is64 and vtQword or vtDword, rtRounded, string.format("%d", cl.lo), string.format("%d", cl.hi),
                     0, USER_MODE_MAX, protect, fsmAligned, tostring(P), false, false, false, false)
    end

    onScan = function(j)
        local cl, ms = st.clusters[st.ci], j._ms
        local es = cl.entries
        local fl = createFoundList(ms)
        fl.initialize()
        local n = fl.getCount()
        local cap = math.min(perScan * #es, 200000)       -- max_results_per_scan stays a per-holder budget
        if n > cap then st.truncated = true end
        for i = 0, math.min(n, cap) - 1 do
            local loc = tonumber(fl.getAddress(i), 16)
            local val = loc and U26.ptr(loc, is64)
            if val then
                local k, m, checked = U26.ppFirstAtOrAbove(es, val), nil, false
                while k <= #es and es[k].t - val <= maxOffset do
                    local entry = es[k]
                    local offs, cost = { entry.t - val }, entry.t - val
                    for _, o in ipairs(entry.offs) do offs[#offs + 1] = o; cost = cost + o end
                    if not checked then m, checked = U26.moduleFor(mods, loc), true end
                    if m then
                        st.found[#st.found + 1] = { module = m.name, rva = loc - m.base, base = loc, offs = offs, cost = cost }
                    elseif st.depth < maxDepth and not st.seen[loc] then
                        local prev = st.best[loc]          -- one holder can serve several targets: keep its cheapest chain
                        if not prev or cost < prev.cost then st.best[loc] = { t = loc, offs = offs, cost = cost } end
                    end
                    k = k + 1
                end
            end
        end
        pcall(function() fl.destroy() end)
        pcall(function() ms.destroy() end)
        j._ms = nil
        st.scans = st.scans + 1
        st.searched = st.searched + #es
        st.ci = st.ci + 1
        if st.ci > #st.clusters then
            local nextc = {}
            for loc, e in pairs(st.best) do nextc[#nextc + 1] = e; st.seen[loc] = true end
            if #st.found >= maxFound or st.depth >= maxDepth or #nextc == 0 then return finish(j) end
            table.sort(nextc, function(a, b)
                if a.cost ~= b.cost then return a.cost < b.cost end
                return a.t < b.t
            end)
            local nxt = {}
            for i = 1, math.min(beam, #nextc) do nxt[i] = nextc[i] end
            st.frontier, st.best, st.ci, st.depth = nxt, {}, 1, st.depth + 1
            st.clusters = U26.ppClusters(nxt, maxOffset)
        end
        j.progress = { current = st.scans, total = st.scans + (#st.clusters - st.ci + 1) }
        launch(j)
    end

    if U26.moduleFor(mods, target) then      -- already static: nothing to search for
        local m = U26.moduleFor(mods, target)
        st.found[1] = { module = m.name, rva = target - m.base, base = target, offs = {}, cost = 0 }
        finish(job)
        return nil
    end
    job.progress = { current = 0, total = 1 }
    launch(job)
end

JOB_KIND_NAMES = JOB_KIND_NAMES .. ", find_pointer_path, rtti_scan, find_string_refs, find_code_caves"

-- ---------------------------------------------------------------------------
-- snapshots: for "unknown value" hunting without running scans
-- ---------------------------------------------------------------------------
function U26.readRegion(addr, size)
    local parts, bad = {}, {}
    local pos = 0
    while pos < size do
        local n = math.min(U26.CHUNK, size - pos)
        local s = U26.rd(addr + pos, n)
        if s then
            parts[#parts + 1] = s
        else
            for sub = 0, n - 1, 4096 do
                local m = math.min(4096, n - sub)
                local ps = U26.rd(addr + pos + sub, m)
                if ps then
                    parts[#parts + 1] = ps
                else
                    parts[#parts + 1] = string.rep("\0", m)
                    bad[#bad + 1] = { pos + sub, m }
                end
            end
        end
        pos = pos + n
    end
    return table.concat(parts), bad
end

function U26.snapSummary(s)
    return { name = s.name, address = U26.hex(s.address), size = s.size, unreadable_bytes = s.bad_bytes, taken = s.taken }
end

function cmd_snapshot_region(params)
    local okProc, perr = requireProcess()
    if not okProc then return perr end
    local addr, size
    if params.module and params.module ~= "" then
        local mod, pe, _, err = U26.peFor(params)
        if not mod then return err end
        local want = tostring(params.section or ".data")
        local sec
        for _, s in ipairs(pe.sections) do if s.name == want then sec = s end end
        if not sec then return U26.err("Section not found: " .. want, "NOT_FOUND") end
        addr, size = mod.base + sec.rva, math.max(sec.vsize, sec.raw_size)
    else
        addr, size = U26.addr(params.address), tonumber(params.size)
    end
    if not addr then return U26.err("Invalid address", "INVALID_ADDRESS") end
    if not size or size < 1 then return U26.err("size must be positive") end
    size = math.floor(size)
    if size > U26.SNAP_MAX_ONE then return U26.err("A snapshot is limited to " .. U26.SNAP_MAX_ONE .. " bytes") end

    serverState.snapshot_seq = serverState.snapshot_seq + 1
    local name = params.name
    if type(name) ~= "string" or name == "" then name = "snap_" .. serverState.snapshot_seq end
    if name == "live" then return U26.err("'live' is reserved for diff_snapshots") end
    local old = serverState.snapshots[name]
    local count, total = 0, serverState.snapshot_bytes - (old and old.size or 0)
    for _ in pairs(serverState.snapshots) do count = count + 1 end
    if not old and count >= U26.SNAP_MAX_COUNT then
        return U26.err("At most " .. U26.SNAP_MAX_COUNT .. " snapshots; delete_snapshot one first", "OUT_OF_RESOURCES")
    end
    if total + size > U26.SNAP_MAX_TOTAL then
        return U26.err("Snapshots would exceed " .. U26.SNAP_MAX_TOTAL .. " bytes in total; delete_snapshot one first", "OUT_OF_RESOURCES")
    end

    local data, bad = U26.readRegion(addr, size)
    local badBytes = 0
    for _, b in ipairs(bad) do badBytes = badBytes + b[2] end
    if badBytes == size then return U26.err("Region is completely unreadable at " .. U26.hex(addr), "INVALID_ADDRESS") end
    serverState.snapshots[name] = { name = name, address = addr, size = size, data = data, bad = bad, bad_bytes = badBytes, taken = os.time() }
    serverState.snapshot_bytes = total + size
    local out = U26.snapSummary(serverState.snapshots[name])
    out.success = true
    return out
end

function cmd_list_snapshots(params)
    local list = {}
    for _, s in pairs(serverState.snapshots) do list[#list + 1] = U26.snapSummary(s) end
    table.sort(list, function(a, b) return a.taken ~= b.taken and a.taken < b.taken or a.name < b.name end)
    return { success = true, count = #list, total_bytes = serverState.snapshot_bytes, snapshots = list }
end

function cmd_delete_snapshot(params)
    if params.all == true then
        local n = 0
        for _ in pairs(serverState.snapshots) do n = n + 1 end
        serverState.snapshots, serverState.snapshot_bytes = {}, 0
        return { success = true, deleted = n }
    end
    local s = serverState.snapshots[params.name]
    if not s then return U26.err("No such snapshot: " .. tostring(params.name), "NOT_FOUND") end
    serverState.snapshot_bytes = serverState.snapshot_bytes - s.size
    serverState.snapshots[params.name] = nil
    return { success = true, deleted = 1 }
end

function U26.decodeUnit(s, unit)
    local fmt = ({ [1] = "<I1", [2] = "<I2", [4] = "<I4", [8] = "<I8" })[unit]
    return (string.unpack(fmt, s))
end

-- names: 2+ snapshot names, optionally "live" (read now). pattern: one char per consecutive pair:
-- C = must have changed, U = must be unchanged, ? = don't care. Default: all C.
function cmd_diff_snapshots(params)
    local names = params.snapshots
    if type(names) ~= "table" or #names < 2 then
        return U26.err("snapshots must list at least two snapshot names (\"live\" reads current memory)")
    end
    local n = #names
    local unit = tonumber(params.unit or 4)
    if unit ~= 1 and unit ~= 2 and unit ~= 4 and unit ~= 8 then return U26.err("unit must be 1, 2, 4 or 8") end
    local pattern = params.pattern or string.rep("C", n - 1)
    if #pattern ~= n - 1 or pattern:find("[^CU?]") then
        return U26.err("pattern needs " .. (n - 1) .. " characters from C (changed), U (unchanged), ? (any)")
    end

    local ref
    for _, nm in ipairs(names) do
        if nm ~= "live" then
            ref = serverState.snapshots[nm]
            if not ref then return U26.err("No such snapshot: " .. tostring(nm), "NOT_FOUND") end
            break
        end
    end
    if not ref then return U26.err("At least one entry must be a real snapshot (it defines address and size)") end
    local snaps = {}
    for i, nm in ipairs(names) do
        local s
        if nm == "live" then
            local okProc, perr = requireProcess()
            if not okProc then return perr end
            local data, bad = U26.readRegion(ref.address, ref.size)
            s = { name = "live", address = ref.address, size = ref.size, data = data, bad = bad }
        else
            s = serverState.snapshots[nm]
            if not s then return U26.err("No such snapshot: " .. tostring(nm), "NOT_FOUND") end
            if s.address ~= ref.address or s.size ~= ref.size then
                return U26.err("Snapshot '" .. nm .. "' covers a different region than '" .. ref.name .. "'")
            end
        end
        snaps[i] = s
    end

    local BLK = 4096
    local badBlocks = {}
    for _, s in ipairs(snaps) do
        for _, b in ipairs(s.bad) do
            for blk = b[1] // BLK, (b[1] + b[2] - 1) // BLK do badBlocks[blk] = true end
        end
    end

    local lo = math.max(0, math.floor(tonumber(params.offset or 0)))
    local hi = ref.size
    if params.length then hi = math.min(hi, lo + math.floor(tonumber(params.length))) end
    lo = lo - lo % unit
    local limit = clampInt(params.limit or 200, 1, 1000)
    local gap = tonumber(params.merge_gap or unit)
    local matches, groups, total = {}, {}, 0
    local pc = {}
    for k = 1, n - 1 do pc[k] = pattern:sub(k, k) end

    local blk = lo // BLK
    while blk * BLK < hi do
        local b0, b1 = math.max(lo, blk * BLK), math.min(hi, (blk + 1) * BLK)
        b1 = b0 + ((b1 - b0) // unit) * unit
        local skip = badBlocks[blk] or b1 <= b0
        if not skip then
            for k = 1, n - 1 do        -- identical block in a 'C' pair: nothing in here can match
                if pc[k] == "C" and snaps[k].data:sub(b0 + 1, b1) == snaps[k + 1].data:sub(b0 + 1, b1) then skip = true; break end
            end
        end
        if not skip then
            for u = b0, b1 - unit, unit do
                local vals = {}
                for k = 1, n do vals[k] = snaps[k].data:sub(u + 1, u + unit) end
                local ok = true
                for k = 1, n - 1 do
                    local same = (vals[k] == vals[k + 1])
                    if (pc[k] == "C" and same) or (pc[k] == "U" and not same) then ok = false; break end
                end
                if ok then
                    total = total + 1
                    local g = groups[#groups]
                    if g and u - (g.offset + g.size) <= gap then
                        g.size, g.units = u + unit - g.offset, g.units + 1
                    elseif #groups < 200 then
                        groups[#groups + 1] = { offset = u, size = unit, units = 1 }
                    end
                    if #matches < limit then
                        local m = { address = U26.hex(ref.address + u), offset = u, old = U26.decodeUnit(vals[1], unit), new = U26.decodeUnit(vals[n], unit) }
                        if unit == 8 and m.old < 0 then m.old = U26.hex(m.old) end
                        if unit == 8 and m.new < 0 then m.new = U26.hex(m.new) end
                        if unit == 4 then
                            m.old_float, m.new_float = (string.unpack("<f", vals[1])), (string.unpack("<f", vals[n]))
                        elseif unit == 8 then
                            m.old_double, m.new_double = (string.unpack("<d", vals[1])), (string.unpack("<d", vals[n]))
                        end
                        if n > 2 then
                            m.values = {}
                            for k = 1, n do m.values[k] = U26.decodeUnit(vals[k], unit) end
                        end
                        matches[#matches + 1] = m
                    end
                end
            end
        end
        blk = blk + 1
    end
    for _, g in ipairs(groups) do g.address = U26.hex(ref.address + g.offset) end
    return {
        success = true, address = U26.hex(ref.address), size = ref.size, unit = unit, pattern = pattern, snapshots = names,
        total_matches = total, returned = #matches, matches = matches, groups = groups,
        skipped_unreadable_blocks = (function() local c = 0 for _ in pairs(badBlocks) do c = c + 1 end return c end)(),
    }
end

-- >>> END UNIT-26 <<<

-- Dispatcher entries (the dispatcher table itself is built in 25_dispatcher)
for name, handler in pairs({
    pe_info = cmd_pe_info,
    pe_imports = cmd_pe_imports,
    pe_exports = cmd_pe_exports,
    pe_tls_callbacks = cmd_pe_tls_callbacks,
    va_to_rva = cmd_va_to_rva,
    rva_to_va = cmd_rva_to_va,
    rebase_address = cmd_rebase_address,
    export_names = cmd_export_names,
    export_structures = cmd_export_structures,
    import_names = cmd_import_names,
    snapshot_region = cmd_snapshot_region,
    list_snapshots = cmd_list_snapshots,
    delete_snapshot = cmd_delete_snapshot,
    diff_snapshots = cmd_diff_snapshots,
}) do commandHandlers[name] = handler end

-- >>> exports
B.U26 = U26
