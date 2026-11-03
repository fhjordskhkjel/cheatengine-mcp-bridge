-- Offline unit tests for the bridge's pure-Lua JSON codec.
-- Run: lua MCP_Server/test_json_codec.lua   (Lua 5.3 or 5.4; from repo root or MCP_Server/)
local here = (arg and arg[0] and arg[0]:match("^(.*)[/\\]")) or "."

local function loadCodec()
    local f = assert(io.open(here .. "/ce_mcp_bridge.lua", "r"))
    local src = f:read("*a"); f:close()
    local slice = src:match("(local json = %(function%(%).-\nend%)%(%))")
    assert(slice, "could not find JSON codec slice")
    return assert(load(slice .. "\nreturn json"))()
end
local json = loadCodec()

local pass, fail = 0, 0
local function check(name, cond, got)
    if cond then
        pass = pass + 1
    else
        fail = fail + 1
        print("FAIL: " .. name .. (got ~= nil and ("  (got: " .. tostring(got) .. ")") or ""))
    end
end
local function enc(v) return json.encode(v) end
local function dec(s) return json.decode(s) end

-- ---------------------------------------------------------------- numbers
check("x64 pointer exact",      enc(0x7FF612345678) == "140694844102264", enc(0x7FF612345678))
check("qword exact",            enc(0x123456789ABCDEF0) == "1311768467463790320", enc(0x123456789ABCDEF0))
check("2^53+1 exact",           enc(9007199254740993) == "9007199254740993", enc(9007199254740993))
check("negative int (signed qword)", enc(-1) == "-1", enc(-1))
check("min int64",              enc(math.mininteger) == "-9223372036854775808", enc(math.mininteger))
check("simple float",           enc(1.5) == "1.5", enc(1.5))
check("integral float",         enc(100.0) == "100", enc(100.0))
check("float 0.1 short form",   enc(0.1) == "0.1", enc(0.1))
check("double round-trips",     tonumber(enc(1/3)) == 1/3, enc(1/3))
check("float32-ish round-trips", tonumber(enc(87.30000305175781)) == 87.30000305175781, enc(87.30000305175781))
check("NaN -> null",            enc(0/0) == "null", enc(0/0))
check("inf -> null",            enc(math.huge) == "null", enc(math.huge))
check("decode int stays int",   math.type(dec("140694844102264")) == "integer")
check("decode int exact",       dec("140694844102264") == 0x7FF612345678)
check("decode negative float",  dec("-2.5e3") == -2500.0)

-- ---------------------------------------------------------------- strings (decode)
check("decode \\u00e9 -> UTF-8", dec('"\\u00e9"') == "\195\169", dec('"\\u00e9"'))
check("decode CJK",             dec('"\\u65e5\\u672c"') == "\230\151\165\230\156\172")
check("decode surrogate pair",  dec('"\\ud83d\\ude00"') == "\240\159\152\128")
check("lone high surrogate -> U+FFFD", dec('"\\ud83dx"') == "\239\191\189x", dec('"\\ud83dx"'))
check("lone low surrogate -> U+FFFD",  dec('"\\ude00"') == "\239\191\189")
check("escaped backslash then u0041 stays literal", dec('"C:\\\\u0041dir"') == "C:\\u0041dir", dec('"C:\\\\u0041dir"'))
check("windows path",           dec('"C:\\\\Users\\\\x\\\\a.CT"') == "C:\\Users\\x\\a.CT")
check("standard escapes",       dec('"a\\n\\t\\r\\b\\f\\/\\"b"') == "a\n\t\r\b\f/\"b")
check("raw UTF-8 passes through", dec('"\230\151\165"') == "\230\151\165")
check("bad escape errors",      not pcall(dec, '"\\q"'))
check("unterminated errors",    not pcall(dec, '"abc'))
check("truncated \\u errors",   not pcall(dec, '"\\u12"'))

-- ---------------------------------------------------------------- strings (encode)
check("encode ascii",           enc("abc") == '"abc"')
check("encode control chars",   enc("a\nb\0c") == '"a\\nb\\u0000c"', enc("a\nb\0c"))
check("encode quote/backslash", enc('a"b\\c') == '"a\\"b\\\\c"', enc('a"b\\c'))
check("encode valid UTF-8 raw", enc("\195\169\230\151\165") == '"\195\169\230\151\165"')
check("encode emoji raw",       enc("\240\159\152\128") == '"\240\159\152\128"')
check("invalid byte -> \\u00XX", enc("\255\254A") == '"\\u00ff\\u00feA"', enc("\255\254A"))
check("ANSI e-acute -> \\u00e9", enc("caf\233") == '"caf\\u00e9"', enc("caf\233"))
check("truncated seq escaped",  enc("\230\151") == '"\\u00e6\\u0097"', enc("\230\151"))
check("encoded surrogate rejected", enc("\237\160\128") == '"\\u00ed\\u00a0\\u0080"', enc("\237\160\128"))
check("overlong rejected",      enc("\192\175") == '"\\u00c0\\u00af"', enc("\192\175"))
check("mixed valid/invalid",    enc("\195\169\255") == '"\195\169\\u00ff"', enc("\195\169\255"))

-- ---------------------------------------------------------------- tables
check("empty -> []",            enc({}) == "[]")
check("array",                  enc({1, 2, 3}) == "[1,2,3]")
check("array holes -> null",    enc({1, nil, 3}) == "[1,null,3]", enc({1, nil, 3}))
check("trailing nil dropped",   enc({1, 2, nil}) == "[1,2]", enc({1, 2, nil}))
check("mixed keys -> object keeps all", (function()
    local s = enc({1, 2, x = "k"})
    return s:sub(1, 1) == "{" and s:find('"x":"k"', 1, true) and s:find('"1":1', 1, true) and s:find('"2":2', 1, true)
end)(), enc({1, 2, x = "k"}))
check("zero-based -> object keeps [0]", (function()
    local s = enc({[0] = "a", [1] = "b"})
    return s:find('"0":"a"', 1, true) ~= nil
end)(), enc({[0] = "a", [1] = "b"}))
check("very sparse -> object",  enc({[1000] = 1}) == '{"1000":1}', enc({[1000] = 1}))
check("object",                 enc({a = 1}) == '{"a":1}')
check("nested",                 enc({a = {b = {1, "x"}}}) == '{"a":{"b":[1,"x"]}}')
check("circular errors", (function()
    local t = {}; t.self = t
    return not pcall(enc, t)
end)())
check("functions -> null",      enc({f = print}) == '{"f":null}')

-- ---------------------------------------------------------------- round trip
local req = '{"jsonrpc":"2.0","method":"write_string","params":{"address":"0x7FF612345678","value":"\\u65e5\\u672c \\u00e9","addr_int":140694844102264,"bytes":[144,144,195]},"id":1730000000123}'
local r = dec(req)
check("rt method",   r.method == "write_string")
check("rt value",    r.params.value == "\230\151\165\230\156\172 \195\169")
check("rt addr int", r.params.addr_int == 0x7FF612345678)
check("rt bytes",    #r.params.bytes == 3 and r.params.bytes[3] == 195)
check("rt id",       r.id == 1730000000123 and enc(r.id) == "1730000000123")
check("rt re-encode decodes", dec(enc(r)).params.value == r.params.value)
check("null in array",  (function() local a = dec("[1,null,3]"); return a[1] == 1 and a[2] == nil and a[3] == 3 end)())
check("whitespace",     dec(' { "a" : [ 1 , 2 ] } ').a[2] == 2)
check("empty input errors", not pcall(dec, "   "))

print(string.format("%d passed, %d failed", pass, fail))
if fail > 0 then os.exit(1) end
