"""Offline checks of UNIT-26: PE parsing, address translation, RTTI, string refs, code caves, pointer paths,
snapshots and IDA exchange, on synthetic x64/x86 PE images driven through a fake CE API.

Usage: python tests/test_lua_analysis.py [path/to/ce_mcp_bridge.lua] [--real]
  --real  additionally validates the PE/RTTI parsing against real system DLLs loaded in this process
          (exports/imports are cross-checked with GetProcAddress, sections with VirtualQuery).
Set BRIDGE_TEST_DUMP=<file> to write the generated x64 Lua test program for debugging.
"""
import ctypes, ctypes.wintypes as wt, json, struct, sys, os

from lua_harness import run_lua, load, func_end, arg_path, has_flag, finish, compile_check, BRIDGE_LUA


t = load(arg_path(1, BRIDGE_LUA))
compile_check(t)

prefix = t[:t.index("-- Shared helper: scan for MZ PE headers")]
_, j = func_end(t, "function cmd_read_memory(params)")
read_block = t[t.index("-- Byte-table helpers shared by read_memory"):j]
_, j = func_end(t, "function cmd_next_scan(params)")
scan_block = t[t.index("local USER_MODE_MAX"):j]
unit25 = t[t.index("-- >>> BEGIN UNIT-25 Operations"):t.index("-- >>> END UNIT-25 <<<")]
unit26 = t[t.index("-- >>> BEGIN UNIT-26 Analysis"):t.index("-- >>> END UNIT-26 <<<")]
i, j = func_end(t, "function resolveChain(base, offsets)")
resolve_block = t[i:j]
i, j = func_end(t, "function cmd_register_symbol(params)")
register_block = t[i:j]


# --------------------------------------------------------------------------- synthetic PE builder
def build_image(is64, base, other_base):
    P = 8 if is64 else 4
    img = bytearray(0x4000)

    def w(off, b): img[off:off + len(b)] = b
    def u32(off, v): struct.pack_into('<I', img, off, v)
    def ref(rva): return rva if is64 else base + rva      # 4-byte references inside RTTI structures
    def ptr(v): return struct.pack('<Q' if is64 else '<I', v)
    def va(rva): return base + rva

    w(0, b'MZ'); u32(0x3C, 0x80)
    nt = 0x80
    w(nt, b'PE\0\0')
    optsize = 240 if is64 else 224
    struct.pack_into('<HHIIIHH', img, nt + 4, 0x8664 if is64 else 0x14C, 3, 0x5F5E1000, 0, 0, optsize, 0x22)
    opt = nt + 24
    struct.pack_into('<H', img, opt, 0x20B if is64 else 0x10B)
    u32(opt + 16, 0x1000); u32(opt + 20, 0x1000)
    if is64:
        struct.pack_into('<Q', img, opt + 24, base)
    else:
        u32(opt + 24, 0x2000); u32(opt + 28, base)
    u32(opt + 32, 0x1000); u32(opt + 36, 0x200)
    u32(opt + 56, 0x4000); u32(opt + 60, 0x1000)
    struct.pack_into('<HH', img, opt + 68, 3, 0x8160)
    u32(opt + (108 if is64 else 92), 16)
    dirs = opt + (112 if is64 else 96)
    def setdir(i, rva, size): struct.pack_into('<II', img, dirs + i * 8, rva, size)
    setdir(0, 0x2000, 0x110); setdir(1, 0x2200, 0x28); setdir(9, 0x2300, 0x28)
    sec = opt + optsize
    for k, (name, rva, vs, chars) in enumerate([(b'.text', 0x1000, 0x1000, 0x60000020), (b'.rdata', 0x2000, 0x1000, 0x40000040), (b'.data', 0x3000, 0x1000, 0xC0000040)]):
        o = sec + k * 40
        w(o, name.ljust(8, b'\0'))
        struct.pack_into('<IIII', img, o + 8, vs, rva, vs, rva)
        u32(o + 36, chars)

    # ---- .text: ret-filled; string-load instructions; padding runs
    for off in range(0x1000, 0x2000): img[off] = 0xC3
    tgt_hello, tgt_decoy = 0x2800, 0x2810
    def lea(at, rex_modrm, target):
        w(at, bytes(rex_modrm[:2]) + bytes([rex_modrm[2]]) + struct.pack('<i', target - (at + 7)))
    if is64:
        lea(0x1100, (0x48, 0x8D, 0x0D), tgt_hello)
        lea(0x11FC, (0x48, 0x8D, 0x15), tgt_hello)       # crosses a 0x200 chunk border
        lea(0x1600, (0x4C, 0x8D, 0x05), tgt_hello)
        lea(0x1700, (0x48, 0x8D, 0x0D), tgt_decoy)
    else:
        w(0x1100, b'\x68' + struct.pack('<I', va(tgt_hello)))
        w(0x11FC, b'\xB8' + struct.pack('<I', va(tgt_hello)))
        w(0x1600, b'\xBA' + struct.pack('<I', va(tgt_hello)))
        w(0x1700, b'\x68' + struct.pack('<I', va(tgt_decoy)))
    w(0x1300, b'\xCC' * 32)
    w(0x13F0, b'\xCC' * 0x30)                            # crosses the 0x1400 chunk border
    w(0x1500, b'\xCC' * 8)                               # too short
    w(0x1FF0, b'\xCC' * 16)                              # touches the section end

    # ---- .rdata: exports
    u32(0x2000 + 12, 0x2080); u32(0x2000 + 16, 1); u32(0x2000 + 20, 3); u32(0x2000 + 24, 3)
    u32(0x2000 + 28, 0x20A0); u32(0x2000 + 32, 0x20C0); u32(0x2000 + 36, 0x20E0)
    w(0x2080, b'game.exe\0')
    u32(0x20A0, 0x1000); u32(0x20A4, 0x1010); u32(0x20A8, 0x20F0)
    u32(0x20C0, 0x2110); u32(0x20C4, 0x2120); u32(0x20C8, 0x2130)
    struct.pack_into('<HHH', img, 0x20E0, 0, 1, 2)
    w(0x20F0, b'other.dll.Target\0')
    w(0x2110, b'FuncA\0'); w(0x2120, b'FuncB\0'); w(0x2130, b'Fwd\0')
    # ---- imports
    struct.pack_into('<IIIII', img, 0x2200, 0x2260, 0, 0, 0x2240, 0x3100)
    w(0x2240, b'KERNEL32.dll\0')
    ordbit = (1 << (P * 8 - 1)) | 0x10
    w(0x2260, ptr(0x2290) + ptr(0x22B0) + ptr(ordbit) + ptr(0))
    w(0x2290, struct.pack('<H', 0x123) + b'ExitProcess\0')
    w(0x22B0, struct.pack('<H', 0x45) + b'Sleep\0')
    w(0x3100, ptr(other_base + 0x1000) + ptr(other_base + 0x1010) + ptr(other_base + 0x1020) + ptr(0))
    # ---- TLS
    if is64:
        struct.pack_into('<QQQQII', img, 0x2300, va(0x3400), va(0x3440), va(0x3440), va(0x3200), 0, 0)
    else:
        struct.pack_into('<IIIIII', img, 0x2300, va(0x3400), va(0x3440), va(0x3440), va(0x3200), 0, 0)
    w(0x3200, ptr(va(0x1100)) + ptr(va(0x1200)) + ptr(0))
    # ---- strings
    w(0x2800, b'Hello world\0'); w(0x2810, b'decoy\0'); w(0x2820, 'Wide'.encode('utf-16le') + b'\0\0')
    w(0x3500, ptr(va(tgt_hello)))                       # data pointer to the string
    w(0x3600, ptr(0x2B000000))                           # static pointer used by the pointer-path test

    # ---- RTTI
    def td(at, name):
        w(at + 2 * P, name + b'\0')
    td(0x3400, b'.?AVBase@game@@'); td(0x3440, b'.?AVDerived@game@@')
    td_rva = {'Base': 0x3400, 'Derived': 0x3440}
    def bcd(at, name): struct.pack_into('<IIiiiI', img, at, ref(td_rva[name]), 0, 0, -1, 0, 0)
    bcd(0x2420, 'Base'); bcd(0x2460, 'Derived')
    # Base CHD @0x2400, array @0x2410
    struct.pack_into('<IIII', img, 0x2400, 0, 0, 1, ref(0x2410)); u32(0x2410, ref(0x2420))
    # Derived CHD @0x2440, array @0x2450 -> [Derived, Base]
    struct.pack_into('<IIII', img, 0x2440, 0, 0, 2, ref(0x2450)); u32(0x2450, ref(0x2460)); u32(0x2454, ref(0x2420))
    def col(at, name, cdrva):
        if is64: struct.pack_into('<IIIIII', img, at, 1, 0, 0, td_rva[name], cdrva, at)
        else: struct.pack_into('<IIIII', img, at, 0, 0, 0, base + td_rva[name], base + cdrva)
    col(0x2500, 'Base', 0x2400); col(0x2530, 'Derived', 0x2440)
    w(0x2600, ptr(va(0x2500)) + ptr(va(0x1020)) + ptr(va(0x1030)) + ptr(0))
    w(0x2640, ptr(va(0x2530)) + ptr(va(0x1020)) + ptr(va(0x1040)) + ptr(va(0x1050)) + ptr(0))
    return bytes(img)


def page_lines(base, data):
    return "\n".join('PAGE(0x%X, "%s")' % (base + off, data[off:off + 4096].hex()) for off in range(0, len(data), 4096) if any(data[off:off + 4096]))


X64_BASE, X64_OTHER = 0x140000000, 0x7FF800000000
X86_BASE, X86_OTHER = 0x00400000, 0x7C800000
img64 = build_image(True, X64_BASE, X64_OTHER)
img86 = build_image(False, X86_BASE, X86_OTHER)

STUBS = r'''
local _unique = 0
setmetatable(_G, { __index = function(g, name)
  if type(name) == "string" and (name:match("^so%u") or name:match("^vt%u") or name:match("^rt%u") or name:match("^fsm%u")) then
    _unique = _unique + 1; rawset(g, name, _unique); return _unique
  end
end })

PROCESS_PID = 4242
TARGET64 = true
function getOpenedProcessID() return PROCESS_PID end
function targetIs64Bit() return TARGET64 end
MODULES = {}
function enumModules() return MODULES end
function getAddressSafe(s)
  if type(s) == "number" then return s end
  if type(s) ~= "string" then return nil end
  local n = tonumber(s); if n then return math.tointeger(n) or n end
  local function modbase(nm) for _, m in ipairs(MODULES) do if m.Name:lower() == nm:lower() then return m.Address end end end
  local name, off = s:match("^([%w_%.%-]+)%+(.+)$")
  if name then
    local b = modbase(name); local o = tonumber(off) or tonumber("0x" .. off)
    if b and o then return b + o end
  end
  return modbase(s)
end
function getCEVersion() return 7.6 end
function dbk_initialized() return false end
function dbvm_initialized() return false end
function debug_isDebugging() return false end
function getSettings() return { Value = {} } end

-- page-granular fake memory
PAGES = {}
function PAGE(addr, hex)
  PAGES[addr // 4096] = (hex:gsub("%x%x", function(h) return string.char(tonumber(h, 16)) end))
end
function poke(addr, str)
  local pos = 1
  while pos <= #str do
    local idx, off = (addr + pos - 1) // 4096, (addr + pos - 1) % 4096
    local page = PAGES[idx] or string.rep("\0", 4096)
    local n = math.min(4096 - off, #str - pos + 1)
    PAGES[idx] = page:sub(1, off) .. str:sub(pos, pos + n - 1) .. page:sub(off + n + 1)
    pos = pos + n
  end
end
function readBytes(addr, size, asTable)
  local parts = {}
  local pos = 0
  while pos < size do
    local idx, off = (addr + pos) // 4096, (addr + pos) % 4096
    local page = PAGES[idx]
    if not page then return nil end
    local n = math.min(4096 - off, size - pos)
    parts[#parts + 1] = page:sub(off + 1, off + n)
    pos = pos + n
  end
  local s = table.concat(parts)
  local t = {}
  for i = 1, #s, 4096 do
    local chunk = { string.byte(s, i, math.min(i + 4095, #s)) }
    for k = 1, #chunk do t[#t + 1] = chunk[k] end
  end
  return t
end
function readPointer(addr)
  local b = readBytes(addr, TARGET64 and 8 or 4, true)
  if not b then return nil end
  local s = string.char(table.unpack(b))
  return (string.unpack(TARGET64 and "<I8" or "<I4", s))
end
function readInteger(addr)
  local b = readBytes(addr, 4, true); if not b then return nil end
  return (string.unpack("<I4", string.char(table.unpack(b))))
end
function disassemble(addr) return "insn@" .. string.format("%X", addr) end

-- fake memscan / foundlist / timer
SCANS = {}
PTR_MODEL = nil
function createMemScan()
  local ms = { destroyed = false, progress = { TotalAddressesToScan = 0, CurrentlyScanned = 0, ResultsFound = 0 } }
  SCANS[#SCANS + 1] = ms
  function ms.firstScan(...)
    ms.args = { ... }
    ms.progress = { TotalAddressesToScan = 100, CurrentlyScanned = 10, ResultsFound = 0 }
    if PTR_MODEL and ms.args[1] == soValueBetween then
      local lo, hi = tonumber(ms.args[4]), tonumber(ms.args[5])
      local res = {}
      for loc, val in pairs(PTR_MODEL) do if val >= lo and val <= hi then res[#res + 1] = string.format("%X", loc) end end
      table.sort(res)
      ms.planned = res
    end
  end
  function ms.getProgress() return ms.progress end
  function ms.destroy() ms.destroyed = true end
  function ms.complete(results)
    ms.results = results or {}
    ms.completed = true
    ms.progress = { TotalAddressesToScan = 100, CurrentlyScanned = 100, ResultsFound = #ms.results }
    if ms.OnScanDone then ms.OnScanDone(ms) end
  end
  function ms.waitTillDone() ms.complete(ms.results) end
  return ms
end
function createFoundList(ms)
  local fl = {}
  function fl.initialize() end
  function fl.getCount() return #(ms.results or {}) end
  function fl.getAddress(i) return ms.results[i + 1] end
  function fl.destroy() end
  return fl
end
function createTimer() local tm = { Enabled = false, Interval = 0 }; function tm.destroy() end; return tm end

SYMS = {}
function enumRegisteredSymbols() return SYMS end
REGISTERED = {}
function registerSymbol(name, addr, dns) REGISTERED[name] = addr end

STRUCTS = {}
function getStructureCount() return #STRUCTS end
function getStructure(i) return STRUCTS[i + 1] end
'''

HELPERS = r'''
local results = {}
local function eq(name, got, want)
  local ok = (got == want)
  results[#results + 1] = (ok and "PASS  " or "FAIL  ") .. name .. (ok and "" or ("  got=" .. tostring(got) .. " want=" .. tostring(want)))
end
local function completePending()
  for _, ms in ipairs(SCANS) do
    if not ms.completed and not ms.destroyed and ms.planned then ms.complete(ms.planned) end
  end
end
local function runJob(kind, params)
  local r = cmd_start_job({ kind = kind, params = params })
  if not r.success then return r end
  local id = r.job_id
  for _ = 1, 20000 do
    local st = cmd_get_job({ job_id = id })
    if st.state ~= "running" then
      if st.state == "done" then
        local res = cmd_get_job_result({ job_id = id, limit = 1000 })
        res.job = st
        return res
      end
      return st
    end
    completePending()
    if serverState.job_timer then serverState.job_timer.OnTimer() end
  end
  return { success = false, error = "job did not finish" }
end
local function hexes(list, key) local o = {} for i, v in ipairs(list) do o[i] = v[key] end return o end
local function join(t) return table.concat(t, ",") end
'''

TESTS_X64 = r'''
MODULES = {
  { Name = "game.exe",  Address = %(b64)d, Size = 0x4000, Is64Bit = true },
  { Name = "other.dll", Address = %(o64)d, Size = 0x10000, Is64Bit = true },
}
TARGET64 = true
local GB = %(b64)d

-- ===================== PE headers =====================
local r = cmd_pe_info({})
eq("pe_info ok", r.success and r.module == "game.exe" and r.arch == "x64" and r.is_64bit, true)
eq("pe_info entry", r.entry_point_rva == 0x1000 and r.entry_point == string.format("0x%%X", GB + 0x1000), true)
eq("pe_info 3 sections", #r.sections, 3)
eq("pe_info section names", r.sections[1].name .. r.sections[2].name .. r.sections[3].name, ".text.rdata.data")
eq("pe_info section flags", r.sections[1].flags .. r.sections[2].flags .. r.sections[3].flags, "r-xr--rw-")
eq("pe_info not relocated", r.relocated, false)
eq("pe_info size_of_image", r.size_of_image, 0x4000)
local dnames = {}
for _, d in ipairs(r.data_directories) do dnames[#dnames + 1] = d.name end
eq("pe_info data directories", join(dnames), "export,import,tls")
eq("pe_info by module name (case-insens, substring)", cmd_pe_info({ module = "GAME" }).module, "game.exe")
eq("pe_info unknown module", cmd_pe_info({ module = "nope.dll" }).error_code, "NOT_FOUND")
PROCESS_PID = 0
eq("pe_info needs a process", cmd_pe_info({}).error_code, "NO_PROCESS")
PROCESS_PID = 4242

r = cmd_pe_imports({})
eq("imports total", r.total, 3)
eq("imports first (by name + hint)", r.imports[1].name == "ExitProcess" and r.imports[1].hint == 0x123 and r.imports[1].dll == "KERNEL32.dll", true)
eq("imports second", r.imports[2].name, "Sleep")
eq("imports ordinal", r.imports[3].ordinal, 0x10)
eq("imports IAT address", r.imports[1].iat_address, string.format("0x%%X", GB + 0x3100))
eq("imports resolved + module", r.imports[1].resolved == string.format("0x%%X", %(o64)d + 0x1000) and r.imports[1].resolved_module == "other.dll", true)
eq("imports dll summary", r.dlls[1].name == "KERNEL32.dll" and r.dlls[1].count == 3, true)
eq("imports dll filter hit", cmd_pe_imports({ dll = "kernel" }).total, 3)
eq("imports dll filter miss", cmd_pe_imports({ dll = "user32" }).total, 0)
eq("imports pagination", cmd_pe_imports({ offset = 1, limit = 1 }).imports[1].name, "Sleep")

r = cmd_pe_exports({})
eq("exports total", r.total, 3)
eq("exports module name", r.export_name, "game.exe")
eq("exports FuncA", r.exports[1].name == "FuncA" and r.exports[1].rva == 0x1000 and r.exports[1].ordinal == 1, true)
eq("exports forwarder", r.exports[3].name == "Fwd" and r.exports[3].forwarder == "other.dll.Target", true)
eq("exports filter", cmd_pe_exports({ name_contains = "FUNC" }).total, 2)

r = cmd_pe_tls_callbacks({})
eq("tls present", r.has_tls and r.callback_count == 2, true)
eq("tls callback addresses", r.callbacks[1].address .. "/" .. r.callbacks[2].address, string.format("0x%%X/0x%%X", GB + 0x1100, GB + 0x1200))
eq("tls callback section", r.callbacks[1].section, ".text")
eq("tls callback module", r.callbacks[1].module, "game.exe")

-- ===================== address translation =====================
r = cmd_va_to_rva({ address = GB + 0x2808 })
eq("va_to_rva basic", r.found and r.module == "game.exe" and r.rva == 0x2808 and r.section == ".rdata" and r.section_offset == 0x808, true)
eq("va_to_rva expression", r.expression, "game.exe+0x2808")
r = cmd_va_to_rva({ addresses = { GB + 0x1000, 0x1234, "0x" .. string.format("%%X", %(o64)d + 5) }, ida_image_base = "0x400000" })
eq("va_to_rva list", r.count == 3 and r.results[1].found and not r.results[2].found and r.results[3].module == "other.dll", true)
eq("va_to_rva ida address", r.results[1].ida_address, "0x401000")
r = cmd_rva_to_va({ module = "game.exe", rva = 0x2800, ida_image_base = 0x400000 })
eq("rva_to_va", r.address == string.format("0x%%X", GB + 0x2800) and r.in_module and r.ida_address == "0x402800", true)
r = cmd_rva_to_va({ module = "game.exe", rvas = { 0x10, "0x20", 0x99999 } })
eq("rva_to_va list", r.count == 3 and r.results[2].rva == 0x20 and r.results[3].in_module == false, true)
r = cmd_rebase_address({ address = 0x402800, from_base = "0x400000", to_module = "game.exe" })
eq("rebase IDA -> CE", r.to, string.format("0x%%X", GB + 0x2800))
r = cmd_rebase_address({ addresses = { GB + 0x10 }, from_module = "game.exe", to_base = 0x10000 })
eq("rebase CE -> other base", r.results[1].to, "0x10010")
eq("rebase needs bases", cmd_rebase_address({ address = 1 }).error_code, "INVALID_PARAMS")

-- ===================== RTTI job (tiny chunks: exercises chunk borders) =====================
U26.CHUNK = 512
r = runJob("rtti_scan", {})
eq("rtti done", r.success and r.class_count == 2 and r.vtable_count == 2, true)
local by = {}
for _, c in ipairs(r.classes or {}) do by[c.class_name] = c end
eq("rtti names", (by["game::Base"] ~= nil) and (by["game::Derived"] ~= nil), true)
eq("rtti raw name", by["game::Base"].raw_name, ".?AVBase@game@@")
eq("rtti Base vtable rva", by["game::Base"].vtable_rva, 0x2608)
eq("rtti Derived vtable rva", by["game::Derived"].vtable_rva, 0x2648)
eq("rtti Base vfuncs", by["game::Base"].vfunc_count, 2)
eq("rtti Derived vfuncs", by["game::Derived"].vfunc_count, 3)
eq("rtti Derived bases", join(by["game::Derived"].bases), "game::Derived,game::Base")
eq("rtti Base bases", join(by["game::Base"].bases), "game::Base")
eq("rtti kind", by["game::Base"].kind, "class")
eq("rtti cached for export_names", #serverState.rtti_cache["game.exe"], 2)
eq("demangle namespace", U26.demangle(".?AVFoo@Bar@Baz@@"), "Baz::Bar::Foo")
eq("demangle anonymous namespace", U26.demangle(".?AVFoo@?A0x1234abcd@@"), "(anonymous namespace)::Foo")
eq("demangle template kept", U26.demangle(".?AV?$vec@H@std@@"), "?$vec@H@std")

-- export_names: symbols + rtti
SYMS = { { address = GB + 0x1000, symbolname = "MyFunc" }, { address = 0x5, symbolname = "elsewhere" } }
r = cmd_export_names({})
eq("export_names count", r.count, 3)
eq("export_names sorted by rva, symbol first", r.names[1].name == "MyFunc" and r.names[1].kind == "symbol", true)
eq("export_names vtable entry", r.names[2].name, "game::Base::vftable")
eq("export_names ida-safe name", r.names[2].ida_name, "game__Base__vftable")
eq("export_names C declarations", r.c_declarations:find("struct game__Base_vtbl", 1, true) ~= nil and r.c_declarations:find("void *vf2;", 1, true) ~= nil, true)
eq("export_names C bases comment", r.c_declarations:find("bases: game::Derived, game::Base", 1, true) ~= nil, true)
r = cmd_export_names({ format = "idapython", ida_image_base = "0x400000" })
eq("idapython script", r.script:find("NAMES = [", 1, true) ~= nil and r.script:find("(0x2608, \"game__Base__vftable\"", 1, true) ~= nil and r.script:find("idc.set_name", 1, true) ~= nil, true)
eq("export_names only symbols", cmd_export_names({ sources = { "symbols" } }).count, 1)
eq("export_names bad format", cmd_export_names({ format = "xml" }).error_code, "INVALID_PARAMS")
serverState.rtti_cache = {}
r = cmd_export_names({ sources = { "rtti" } })
eq("export_names without cache explains", r.count == 0 and #r.notes == 1, true)

-- import_names
REGISTERED = {}
r = cmd_import_names({ module = "game.exe", names = { { name = "Foo", rva = 0x1010 }, { name = "Bar", address = string.format("0x%%X", GB + 0x1020) }, { name = "bad" } } })
eq("import_names counts", r.registered == 2 and r.failed == 1, true)
eq("import_names registered addresses", REGISTERED["Foo"] == GB + 0x1010 and REGISTERED["Bar"] == GB + 0x1020, true)
r = cmd_import_names({ module = "game.exe", prefix = "ida_", names = { { name = "X", rva = 1 } } })
eq("import_names prefix", REGISTERED["ida_X"], GB + 1)
r = cmd_import_names({ module = "game.exe", ida_image_base = 0x400000, address_is_ida = true, names = { { name = "FromIda", address = 0x402800 } } })
eq("import_names rebases IDA addresses", REGISTERED["FromIda"], GB + 0x2800)
eq("import_names empty", cmd_import_names({ names = {} }).error_code, "INVALID_PARAMS")

-- ===================== string refs =====================
r = runJob("find_string_refs", { text = "Hello world" })
eq("string refs done", r.success, true)
eq("string refs target", r.string_addresses[1], string.format("0x%%X", GB + 0x2800))
local kinds, addrs = {}, {}
for _, it in ipairs(r.references or {}) do kinds[#kinds + 1] = it.kind; addrs[#addrs + 1] = it.address end
eq("string refs kinds", join(kinds), "rip_lea,rip_lea,rip_lea,abs_data")
eq("string refs addresses (incl. one across a chunk border)", join(addrs),
   string.format("0x%%X,0x%%X,0x%%X,0x%%X", GB + 0x1100, GB + 0x11FC, GB + 0x1600, GB + 0x3500))
eq("string refs decoy excluded", #r.references, 4)
eq("string refs instruction text", r.references[1].instruction, "insn@" .. string.format("%%X", GB + 0x1100))
eq("string refs rva/section", r.references[4].section == ".data" and r.references[1].rva == 0x1100, true)
r = runJob("find_string_refs", { text = "world" })
eq("string match=start ignores mid-string hits", #r.string_addresses, 0)
r = runJob("find_string_refs", { text = "world", match = "any" })
eq("string match=any finds mid-string hit", r.string_addresses[1], string.format("0x%%X", GB + 0x2806))
r = runJob("find_string_refs", { text = "Wide", wide = true })
eq("wide string target", r.string_addresses[1], string.format("0x%%X", GB + 0x2820))
r = runJob("find_string_refs", { address = string.format("0x%%X", GB + 0x2800), include_data = false })
eq("by address, no data refs", r.found, 3)
eq("string refs need text or address", cmd_start_job({ kind = "find_string_refs", params = {} }).error_code, "INVALID_PARAMS")

-- ===================== code caves =====================
r = runJob("find_code_caves", {})
local sizes, caddr = {}, {}
for _, c in ipairs(r.caves or {}) do sizes[#sizes + 1] = c.size; caddr[#caddr + 1] = c.address end
eq("caves sizes (sorted desc, incl. chunk-border and section-end runs)", join(sizes), "48,32,16")
eq("cave addresses", join(caddr), string.format("0x%%X,0x%%X,0x%%X", GB + 0x13F0, GB + 0x1300, GB + 0x1FF0))
eq("cave section", r.caves[1].section, ".text")
r = runJob("find_code_caves", { min_size = 8 })
eq("min_size 8 includes the short run", r.found, 4)
r = runJob("find_code_caves", { min_size = 40 })
eq("min_size 40", r.found, 1)
eq("cave byte validated", cmd_start_job({ kind = "find_code_caves", params = { byte = 0x41 } }).error_code, "INVALID_PARAMS")
r = runJob("find_code_caves", { byte = 0x90 })
eq("no 0x90 caves", r.found, 0)
U26.CHUNK = 0x10000

-- ===================== pointer path =====================
local HEAP_T = 0x2A000100          -- the address we want a stable path to
PTR_MODEL = {
  [0x2B000040] = 0x2A000000,       -- heap pointer to the object holding HEAP_T (offset 0x100)
  [GB + 0x3600] = 0x2B000000,      -- static pointer to the heap block (offset 0x40 to the holder)
  [0x2C000000] = 0x2A0000F0,       -- decoy: another heap pointer to the object (offset 0x10), no static parent
  [0x2D000000] = 0x2A000010,       -- decoy: too far away (offset 0xF0 + ...)
}
local function putPtr(loc, val) poke(loc, string.pack("<I8", val)) end
for loc, val in pairs(PTR_MODEL) do putPtr(loc, val) end
r = runJob("find_pointer_path", { address = HEAP_T, max_depth = 3, max_offset = 0x200 })
eq("pointer path done", r.success, true)
eq("pointer path found a chain", r.found >= 1, true)
local c = r.chains and r.chains[1]
eq("chain base", c and c.base, "game.exe+0x3600")
eq("chain offsets (outermost first)", c and (c.offsets[1] .. "," .. c.offsets[2]), "64,256")
eq("chain verified by resolveChain", c and c.verified, true)
eq("chain expression", c and c.expression, "[[game.exe+0x3600]+0x40]+0x100")
eq("chain depth", c and c.depth, 2)
eq("scans counted", r.scans >= 2, true)
r = runJob("find_pointer_path", { address = HEAP_T, max_depth = 1, max_offset = 0x200 })
eq("depth 1 finds nothing", r.found, 0)
r = runJob("find_pointer_path", { address = HEAP_T, max_depth = 3, max_offset = 0x20 })
eq("too-small max_offset finds nothing", r.found, 0)
r = runJob("find_pointer_path", { address = GB + 0x3600 })
eq("already-static target answers immediately", r.found == 1 and r.chains[1].base == "game.exe+0x3600" and #r.chains[1].offsets == 0, true)
eq("pointer path bad address", cmd_start_job({ kind = "find_pointer_path", params = { address = "zzz" } }).error_code, "INVALID_ADDRESS")
-- scan parameters used
local lastMs = SCANS[#SCANS]
PTR_MODEL = nil

-- ===================== snapshots =====================
for i = 0, 3 do PAGE(0x9000 + i * 4096, string.rep("00", 4096)) end
local function put32(a, v) poke(a, string.pack("<I4", v)) end
local function putf(a, v) poke(a, string.pack("<f", v)) end
put32(0x9010, 1); put32(0x9020, 5); put32(0x9030, 9); putf(0x9040, 1.5)
r = cmd_snapshot_region({ address = 0x9000, size = 8192, name = "A" })
eq("snapshot A", r.success and r.name == "A" and r.size == 8192, true)
put32(0x9010, 2); put32(0x9020, 6); putf(0x9040, 2.5)
cmd_snapshot_region({ address = 0x9000, size = 8192, name = "B" })
put32(0x9020, 7)
cmd_snapshot_region({ address = 0x9000, size = 8192, name = "C" })
r = cmd_diff_snapshots({ snapshots = { "A", "B" } })
eq("diff A->B finds 3 changed dwords", r.total_matches, 3)
eq("diff match values", r.matches[1].offset == 0x10 and r.matches[1].old == 1 and r.matches[1].new == 2, true)
eq("diff float view", r.matches[3].old_float == 1.5 and r.matches[3].new_float == 2.5, true)
r = cmd_diff_snapshots({ snapshots = { "A", "B", "C" }, pattern = "CU" })
eq("diff CU (changed then stable)", r.total_matches == 2 and r.matches[1].offset == 0x10 and r.matches[2].offset == 0x40, true)
eq("diff CU carries all values", join(r.matches[1].values), "1,2,2")
r = cmd_diff_snapshots({ snapshots = { "A", "B", "C" }, pattern = "CC" })
eq("diff CC (changed twice)", r.total_matches == 1 and r.matches[1].offset == 0x20, true)
r = cmd_diff_snapshots({ snapshots = { "A", "B", "C" }, pattern = "UU" })
eq("diff UU (never changed) is large", r.total_matches > 2000, true)
r = cmd_diff_snapshots({ snapshots = { "A", "B" }, merge_gap = 16 })
eq("diff groups merge neighbours", #r.groups == 2 and r.groups[1].offset == 0x10 and r.groups[1].units == 2, true)
r = cmd_diff_snapshots({ snapshots = { "A", "B" }, unit = 1 })
eq("diff unit=1 counts changed bytes", r.total_matches >= 3, true)
r = cmd_diff_snapshots({ snapshots = { "A", "B" }, limit = 1 })
eq("diff limit", r.returned == 1 and r.total_matches == 3, true)
r = cmd_diff_snapshots({ snapshots = { "A", "B" }, offset = 0x30, length = 0x20 })
eq("diff sub-range", r.total_matches, 1)
put32(0x9030, 99)
r = cmd_diff_snapshots({ snapshots = { "C", "live" } })
eq("diff against live memory", r.total_matches == 1 and r.matches[1].offset == 0x30 and r.matches[1].new == 99, true)
eq("diff bad pattern", cmd_diff_snapshots({ snapshots = { "A", "B" }, pattern = "X" }).error_code, "INVALID_PARAMS")
eq("diff unknown snapshot", cmd_diff_snapshots({ snapshots = { "A", "Z" } }).error_code, "NOT_FOUND")
eq("diff bad unit", cmd_diff_snapshots({ snapshots = { "A", "B" }, unit = 3 }).error_code, "INVALID_PARAMS")
eq("diff needs a snapshot", cmd_diff_snapshots({ snapshots = { "live", "live" } }).error_code, "INVALID_PARAMS")
r = cmd_list_snapshots({})
eq("list_snapshots", r.count == 3 and r.total_bytes == 3 * 8192, true)
-- unreadable pages
PAGES[0xB000 // 4096] = nil
r = cmd_snapshot_region({ address = 0xA000, size = 0x3000, name = "gap" })
eq("snapshot with an unreadable page", r.success and r.unreadable_bytes == 0x1000, true)
cmd_snapshot_region({ address = 0xA000, size = 0x3000, name = "gap2" })
r = cmd_diff_snapshots({ snapshots = { "gap", "gap2" }, pattern = "U" })
eq("diff skips unreadable blocks", r.skipped_unreadable_blocks >= 1, true)
eq("totally unreadable snapshot refused", cmd_snapshot_region({ address = 0xB000, size = 0x1000 }).error_code, "INVALID_ADDRESS")
-- section snapshot + limits
r = cmd_snapshot_region({ module = "game.exe", section = ".data", name = "dataSec" })
eq("snapshot of a module section", r.success and r.size == 0x1000 and r.address == string.format("0x%%X", GB + 0x3000), true)
eq("unknown section", cmd_snapshot_region({ module = "game.exe", section = ".nope" }).error_code, "NOT_FOUND")
eq("delete snapshot", cmd_delete_snapshot({ name = "dataSec" }).deleted, 1)
eq("delete missing", cmd_delete_snapshot({ name = "dataSec" }).error_code, "NOT_FOUND")
local saveMax = U26.SNAP_MAX_TOTAL
U26.SNAP_MAX_TOTAL = serverState.snapshot_bytes + 100
eq("total snapshot budget enforced", cmd_snapshot_region({ address = 0x9000, size = 4096, name = "big" }).error_code, "OUT_OF_RESOURCES")
U26.SNAP_MAX_TOTAL = saveMax
eq("overwriting a snapshot reuses its budget", cmd_snapshot_region({ address = 0x9000, size = 8192, name = "A" }).success, true)
eq("reserved name", cmd_snapshot_region({ address = 0x9000, size = 16, name = "live" }).error_code, "INVALID_PARAMS")
eq("delete all", cmd_delete_snapshot({ all = true }).deleted >= 3 and serverState.snapshot_bytes == 0, true)

-- ===================== CE structures -> C =====================
local function el(name, off, vt, size) return { Name = name, Offset = off, Vartype = vt, Bytesize = size } end
local els = { el("id", 0, vtDword, 4), el("hp", 8, vtSingle, 4), el("name", 0x10, vtString, 8) }
STRUCTS = { { Name = "Player", Size = 0x20, Count = 3, getElement = function(i) return els[i + 1] end } }
r = cmd_export_structures({})
eq("export_structures count", r.count, 1)
eq("export_structures C text", r.c_declarations:find("struct Player {", 1, true) ~= nil and r.c_declarations:find("unsigned int id;", 1, true) ~= nil
   and r.c_declarations:find("float hp;", 1, true) ~= nil and r.c_declarations:find("unsigned char name[8];", 1, true) ~= nil, true)
eq("export_structures padding", r.c_declarations:find("_pad1[4]", 1, true) ~= nil and r.c_declarations:find("_pad3[8]", 1, true) ~= nil, true)
eq("export_structures name filter", cmd_export_structures({ name = "Nope" }).count, 0)

return table.concat(results, "\n")
''' % {"b64": X64_BASE, "o64": X64_OTHER}

TESTS_X86 = r'''
MODULES = {
  { Name = "old.exe",   Address = %(b86)d, Size = 0x4000, Is64Bit = false },
  { Name = "other.dll", Address = %(o86)d, Size = 0x10000, Is64Bit = false },
}
TARGET64 = false
local GB = %(b86)d
local r = cmd_pe_info({})
eq("x86 pe_info", r.success and r.arch == "x86" and r.is_64bit == false and r.preferred_image_base == string.format("0x%%X", GB), true)
r = cmd_pe_imports({})
eq("x86 imports", r.total == 3 and r.imports[1].name == "ExitProcess" and r.imports[3].ordinal == 0x10, true)
eq("x86 imports resolved", r.imports[1].resolved_module, "other.dll")
r = cmd_pe_exports({})
eq("x86 exports", r.total == 3 and r.exports[3].forwarder == "other.dll.Target", true)
r = cmd_pe_tls_callbacks({})
eq("x86 tls", r.callback_count == 2 and r.callbacks[2].address == string.format("0x%%X", GB + 0x1200), true)
U26.CHUNK = 512
r = runJob("rtti_scan", {})
local by = {}
for _, c in ipairs(r.classes or {}) do by[c.class_name] = c end
eq("x86 rtti classes", r.class_count == 2 and by["game::Derived"] ~= nil, true)
eq("x86 rtti vtable rva", by["game::Base"].vtable_rva == 0x2604 and by["game::Derived"].vtable_rva == 0x2644, true)
eq("x86 rtti vfuncs", by["game::Base"].vfunc_count == 2 and by["game::Derived"].vfunc_count == 3, true)
eq("x86 rtti bases", join(by["game::Derived"].bases), "game::Derived,game::Base")
r = runJob("find_string_refs", { text = "Hello world" })
local addrs = {}
for _, it in ipairs(r.references or {}) do addrs[#addrs + 1] = it.kind .. "@" .. it.rva end
eq("x86 string refs (imm32 operands + data pointer)", join(addrs), "abs_code@4353,abs_code@4605,abs_code@5633,abs_data@13568")
r = runJob("find_code_caves", {})
eq("x86 caves", r.found, 3)
U26.CHUNK = 0x10000
return table.concat(results, "\n")
''' % {"b86": X86_BASE, "o86": X86_OTHER}


def make_program(images_and_body):
    return images_and_body


common = STUBS + "\n" + prefix + "\n" + read_block + "\n" + scan_block + "\n" + unit25 + "\n" + unit26 + "\n" + resolve_block + "\n" + register_block + "\n"
x64_prog = common + page_lines(X64_BASE, img64) + "\n" + HELPERS + TESTS_X64
if os.environ.get("BRIDGE_TEST_DUMP"):
    open(os.environ["BRIDGE_TEST_DUMP"], "w", encoding="utf-8").write(x64_prog)
ok, msg = run_lua(x64_prog, "x64")
print("--- synthetic x64 module")
print(msg)
x86_prog = common + page_lines(X86_BASE, img86) + "\n" + HELPERS + TESTS_X86
ok2, msg2 = run_lua(x86_prog, "x86")
print("--- synthetic x86 module")
print(msg2)
allmsg = msg + "\n" + msg2
passed = sum(1 for l in allmsg.splitlines() if l.startswith("PASS"))
failed = sum(1 for l in allmsg.splitlines() if l.startswith("FAIL"))
print("LUA EXEC", "OK" if ok and ok2 else "ERROR")
print("%d passed, %d failed" % (passed, failed))

# --------------------------------------------------------------------------- real DLL validation
if has_flag("--real"):
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.LoadLibraryW.restype = ctypes.c_void_p
    k32.LoadLibraryW.argtypes = [wt.LPCWSTR]
    k32.GetProcAddress.restype = ctypes.c_void_p
    k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.GetCurrentProcess.restype = ctypes.c_void_p

    class MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p), ("AllocationProtect", wt.DWORD),
                    ("PartitionId", wt.WORD), ("RegionSize", ctypes.c_size_t), ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]
    k32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]

    def read_image(base, size):
        lines = []
        for off in range(0, size, 4096):
            buf = ctypes.create_string_buffer(4096)
            n = ctypes.c_size_t()
            if k32.ReadProcessMemory(k32.GetCurrentProcess(), base + off, buf, 4096, ctypes.byref(n)) and n.value == 4096:
                lines.append('PAGE(0x%X, "%s")' % (base + off, buf.raw.hex()))
        return "\n".join(lines)

    def real_check(dllname, want_rtti=False):
        hmod = k32.LoadLibraryW(dllname)
        if not hmod:
            print("cannot load", dllname); return
        hdr = ctypes.string_at(hmod, 0x400)
        nt = struct.unpack_from('<I', hdr, 0x3C)[0]
        soi = struct.unpack_from('<I', hdr, nt + 24 + 56)[0]
        lua = common + read_image(hmod, soi) + """
MODULES = { { Name = %s, Address = %d, Size = %d, Is64Bit = true } }
TARGET64 = true
""" % (json.dumps(dllname), hmod, soi) + HELPERS + """
local out = {}
out.info = cmd_pe_info({})
out.exports = cmd_pe_exports({ limit = 10000 })
out.imports = cmd_pe_imports({ limit = 10000 })
out.tls = cmd_pe_tls_callbacks({})
""" + ("""
U26.CHUNK = 0x10000
local rt = runJob("rtti_scan", {})
out.rtti = rt
""" if want_rtti else "") + """
return json.encode(out)
"""
        okr, text = run_lua(lua, "real", ascii_only=False)
        if not okr:
            print("LUA ERROR on", dllname, text[:400]); return
        data = json.loads(text)
        info, exps, imps = data["info"], data["exports"], data["imports"]
        print("--- real DLL %s  base=0x%X size=0x%X sections=%s" % (dllname, hmod, soi, [s["name"] for s in info["sections"]]))
        bad = 0
        # sections: protection of the live pages must agree with the parsed flags
        for s in info["sections"]:
            mbi = MBI()
            k32.VirtualQuery(hmod + s["rva"], ctypes.byref(mbi), ctypes.sizeof(mbi))
            exec_live = bool(mbi.Protect & 0xF0)
            write_live = bool(mbi.Protect & (0x04 | 0x08 | 0x40 | 0x80))
            # .didat (delay-load IAT) is made read-only by the loader after binding, so only its exec bit is comparable
            if exec_live != (s["flags"][2] == "x") or (s["name"] != ".didat" and write_live != (s["flags"][1] == "w")):
                bad += 1; print("  section flag mismatch", s["name"], s["flags"], hex(mbi.Protect))
        print("  sections checked: %d, flag mismatches: %d" % (len(info["sections"]), bad))
        assert info["size_of_image"] == soi
        # exports: every non-forwarded named export must equal GetProcAddress
        checked = mism = skipped_shim = 0
        for e in exps["exports"]:
            if e.get("name") and "forwarder" not in e:
                addr = k32.GetProcAddress(hmod, e["name"].encode())
                if addr is None or not (hmod <= addr < hmod + soi):
                    skipped_shim += 1          # redirected by Windows app-compat shims (lands in apphelp.dll etc.)
                    continue
                checked += 1
                if addr != hmod + e["rva"]:
                    mism += 1
                    if mism <= 3: print("  export mismatch", e["name"], hex(addr or 0), hex(hmod + e["rva"]))
        print("  exports: total=%d checked=%d mismatches=%d (skipped %d shimmed by app-compat)" % (exps["total"], checked, mism, skipped_shim))
        # imports: IAT value must equal GetProcAddress of the imported function
        icheck = imism = 0
        for e in imps["imports"]:
            if e.get("name") and e.get("resolved"):
                dll = k32.LoadLibraryW(e["dll"])
                if not dll: continue
                addr = k32.GetProcAddress(dll, e["name"].encode())
                icheck += 1
                if addr != int(e["resolved"], 16):
                    imism += 1
                    if imism <= 3: print("  import mismatch", e["dll"], e["name"], hex(addr or 0), e["resolved"])
        print("  imports: total=%d checked=%d mismatches=%d dlls=%d" % (imps["total"], icheck, imism, len(imps["dlls"])))
        res = {"exports_ok": checked > 0 and mism == 0, "imports_ok": icheck > 0 and imism <= max(1, icheck // 50), "sections_ok": bad == 0}
        if want_rtti and "rtti" in data:
            rt = data["rtti"]
            print("  rtti: success=%s classes=%s vtables=%s" % (rt.get("success"), rt.get("class_count"), rt.get("vtable_count")))
            cls = rt.get("classes", [])
            sane = all(c["vfunc_count"] >= 0 and c["bases"] and c["bases"][0] == c["class_name"] for c in cls)
            for c in cls[:6]:
                print("   ", c["class_name"], "vt+%s" % hex(c["vtable_rva"]), "vfuncs=%d" % c["vfunc_count"], "bases=%s" % c["bases"][:3])
            res["rtti_ok"] = rt.get("success") and len(cls) > 0 and sane
        print("  RESULT", res)
        return res

    real = [real_check("user32.dll")]
    for cand in ("msvcp140.dll", "msvcp140_1.dll", "vcruntime140.dll"):
        if os.path.exists(os.path.join(os.environ["WINDIR"], "System32", cand)):
            real.append(real_check(cand, want_rtti=True))
            break
    allok = all(all(r.values()) for r in real if r)
    print("REAL DLL VALIDATION", "OK" if allok else "FAILED")

finish()
