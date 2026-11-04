-- ============================================================================
-- Cheat Engine MCP Bridge :: 01_json
-- Pure-Lua JSON codec (wire format)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

-- ============================================================================
-- JSON LIBRARY (Pure Lua - Complete Implementation)
-- ============================================================================
-- Wire-format rules (both directions are UTF-8 JSON):
--   * Lua integers are emitted with %d so 64-bit values (pointers, qwords,
--     handles) survive exactly; floats use the shortest of %.14g / %.17g that
--     round-trips.
--   * \uXXXX escapes (incl. surrogate pairs) decode to UTF-8; lone surrogates
--     become U+FFFD.
--   * Strings are byte strings in CE. Bytes that are not part of a valid UTF-8
--     sequence are emitted as \u00XX (Latin-1 mapping) so the response is
--     always valid UTF-8 and the original byte value stays recoverable.
--   * A table is an array iff all keys are positive integers (holes -> null);
--     anything else is an object with stringified keys. {} encodes as [].
-- Wrapped in a function so the codec costs one chunk-level local, not ~20
-- (Cheat Engine refuses chunks with more than 200 locals).
local json = (function()
  local json = {}
  local encode
  local floor = math.floor

  local escape_char_map = {
    ["\\"] = "\\\\", ["\""] = "\\\"", ["\b"] = "\\b", ["\f"] = "\\f",
    ["\n"] = "\\n", ["\r"] = "\\r", ["\t"] = "\\t",
  }
  local function escape_char(c)
    return escape_char_map[c] or string.format("\\u%04x", c:byte())
  end

  -- Length of the valid UTF-8 sequence starting at s[i] (a byte >= 0x80), or nil.
  local function utf8_seq_len(s, i)
    local c = s:byte(i)
    local n
    if c >= 0xC2 and c <= 0xDF then n = 2
    elseif c >= 0xE0 and c <= 0xEF then n = 3
    elseif c >= 0xF0 and c <= 0xF4 then n = 4
    else return nil end
    for k = 1, n - 1 do
      local cc = s:byte(i + k)
      if not cc or cc < 0x80 or cc > 0xBF then return nil end
    end
    local c2 = s:byte(i + 1)
    if (c == 0xE0 and c2 < 0xA0)       -- overlong 3-byte
      or (c == 0xED and c2 > 0x9F)     -- UTF-16 surrogates
      or (c == 0xF0 and c2 < 0x90)     -- overlong 4-byte
      or (c == 0xF4 and c2 > 0x8F) then -- > U+10FFFF
      return nil
    end
    return n
  end

  -- Replace bytes that are not valid UTF-8 with \u00XX. Input must already be
  -- JSON-escaped (escapes are ASCII, so they are never touched here).
  local function sanitize_utf8(s)
    local j = s:find("[\128-\255]")
    if not j then return s end
    local out, start = {}, 1
    while j do
      local n = utf8_seq_len(s, j)
      if n then
        j = j + n
      else
        out[#out + 1] = s:sub(start, j - 1)
        out[#out + 1] = string.format("\\u%04x", s:byte(j))
        j = j + 1
        start = j
      end
      j = s:find("[\128-\255]", j)
    end
    out[#out + 1] = s:sub(start)
    return table.concat(out)
  end

  local function encode_string(val)
    return '"' .. sanitize_utf8((val:gsub('[%z\1-\31\\"]', escape_char))) .. '"'
  end

  local function encode_number(val)
    if val ~= val or val == math.huge or val == -math.huge then return "null" end
    if math.type and math.type(val) == "integer" then
      return string.format("%d", val)
    end
    local s = string.format("%.14g", val)
    if tonumber(s) ~= val then s = string.format("%.17g", val) end
    return s
  end

  -- Returns true, maxIndex when every key is a positive integer and the table
  -- is not absurdly sparse; false otherwise.
  local function array_extent(t)
    local n, max = 0, 0
    for k in pairs(t) do
      if type(k) ~= "number" or k < 1 or k ~= floor(k) then return false end
      n = n + 1
      if k > max then max = k end
    end
    if max > n * 2 + 16 then return false end
    return true, max
  end

  -- Sentinel that encodes as JSON null. Use it where a nil would otherwise
  -- vanish, e.g. a trailing nil in an array (Lua cannot store its slot).
  json.null = setmetatable({}, { __tostring = function() return "json.null" end })

  local function encode_table(val, stack)
    if val == json.null then return "null" end
    stack = stack or {}
    if stack[val] then error("circular reference") end
    stack[val] = true
    local res = {}
    local isArray, max = array_extent(val)
    if isArray then
      for i = 1, max do res[i] = encode(val[i], stack) end
      stack[val] = nil
      return "[" .. table.concat(res, ",") .. "]"
    end
    for k, v in pairs(val) do
      local key = type(k) == "string" and k or tostring(k)
      res[#res + 1] = encode_string(key) .. ":" .. encode(v, stack)
    end
    stack[val] = nil
    return "{" .. table.concat(res, ",") .. "}"
  end

  local type_func_map = {
    ["nil"] = function() return "null" end,
    ["table"] = encode_table,
    ["string"] = encode_string,
    ["number"] = encode_number,
    ["boolean"] = tostring,
    ["function"] = function() return "null" end,
    ["userdata"] = function() return "null" end,
  }
  encode = function(val, stack)
    local f = type_func_map[type(val)]
    if f then return f(val, stack) end
    error("unexpected type '" .. type(val) .. "'")
  end
  json.encode = function(val) return encode(val) end

  -- ---------------------------------------------------------------- decoder
  local function decode_error(str, pos, msg)
    error(string.format("JSON parse error at byte %d: %s", pos, msg), 0)
  end

  local function codepoint_to_utf8(n)
    if n <= 0x7F then return string.char(n)
    elseif n <= 0x7FF then
      return string.char(0xC0 + floor(n / 0x40), 0x80 + n % 0x40)
    elseif n <= 0xFFFF then
      return string.char(0xE0 + floor(n / 0x1000), 0x80 + floor(n / 0x40) % 0x40, 0x80 + n % 0x40)
    else
      return string.char(0xF0 + floor(n / 0x40000), 0x80 + floor(n / 0x1000) % 0x40,
                         0x80 + floor(n / 0x40) % 0x40, 0x80 + n % 0x40)
    end
  end

  local unescape_map = {
    ['"'] = '"', ["\\"] = "\\", ["/"] = "/",
    b = "\b", f = "\f", n = "\n", r = "\r", t = "\t",
  }

  local function decode_scanwhite(str, pos) return str:find("%S", pos) or #str + 1 end
  local decode

  -- Single pass so an escaped backslash followed by "u0041" stays literal.
  local function decode_string(str, pos)
    if str:sub(pos, pos) ~= '"' then decode_error(str, pos, "expected string") end
    local buf, i = {}, pos + 1
    while true do
      local j = str:find('["\\]', i)
      if not j then decode_error(str, pos, "unterminated string") end
      buf[#buf + 1] = str:sub(i, j - 1)
      if str:sub(j, j) == '"' then return table.concat(buf), j + 1 end
      local esc = str:sub(j + 1, j + 1)
      if esc == "u" then
        local hex = str:match("^%x%x%x%x", j + 2)
        if not hex then decode_error(str, j, "invalid \\u escape") end
        local cp = tonumber(hex, 16)
        i = j + 6
        if cp >= 0xD800 and cp <= 0xDBFF then
          local lo = str:match("^\\u(%x%x%x%x)", i)
          local lcp = lo and tonumber(lo, 16)
          if lcp and lcp >= 0xDC00 and lcp <= 0xDFFF then
            cp = 0x10000 + (cp - 0xD800) * 0x400 + (lcp - 0xDC00)
            i = i + 6
          else
            cp = 0xFFFD
          end
        elseif cp >= 0xDC00 and cp <= 0xDFFF then
          cp = 0xFFFD
        end
        buf[#buf + 1] = codepoint_to_utf8(cp)
      else
        local c = unescape_map[esc]
        if not c then decode_error(str, j, "invalid escape '\\" .. esc .. "'") end
        buf[#buf + 1] = c
        i = j + 2
      end
    end
  end

  local function decode_number(str, pos)
    local numstr = str:match("^-?%d+%.?%d*[eE]?[+-]?%d*", pos)
    local val = numstr and tonumber(numstr)
    if not val then decode_error(str, pos, "invalid number") end
    return val, pos + #numstr
  end

  local function decode_literal(str, pos)
    local word = str:match("^%a+", pos)
    if word == "true" then return true, pos + 4 end
    if word == "false" then return false, pos + 5 end
    if word == "null" then return nil, pos + 4 end
    decode_error(str, pos, "invalid literal")
  end

  local function decode_array(str, pos)
    pos = decode_scanwhite(str, pos + 1)
    local arr, n = {}, 0
    if str:sub(pos, pos) == "]" then return arr, pos + 1 end
    while true do
      local val
      val, pos = decode(str, pos)
      n = n + 1
      arr[n] = val
      pos = decode_scanwhite(str, pos)
      local c = str:sub(pos, pos)
      if c == "]" then return arr, pos + 1 end
      if c ~= "," then decode_error(str, pos, "expected ']' or ','") end
      pos = decode_scanwhite(str, pos + 1)
    end
  end

  local function decode_object(str, pos)
    pos = decode_scanwhite(str, pos + 1)
    local obj = {}
    if str:sub(pos, pos) == "}" then return obj, pos + 1 end
    while true do
      local key
      key, pos = decode_string(str, pos)
      pos = decode_scanwhite(str, pos)
      if str:sub(pos, pos) ~= ":" then decode_error(str, pos, "expected ':'") end
      pos = decode_scanwhite(str, pos + 1)
      local val
      val, pos = decode(str, pos)
      obj[key] = val
      pos = decode_scanwhite(str, pos)
      local c = str:sub(pos, pos)
      if c == "}" then return obj, pos + 1 end
      if c ~= "," then decode_error(str, pos, "expected '}' or ','") end
      pos = decode_scanwhite(str, pos + 1)
    end
  end

  local char_func_map = { ['"'] = decode_string, ["{"] = decode_object, ["["] = decode_array }
  setmetatable(char_func_map, { __index = function(t, c)
    if c:match("%d") or c == "-" then return decode_number end
    return decode_literal
  end })

  decode = function(str, pos)
    pos = decode_scanwhite(str, pos or 1)
    if pos > #str then decode_error(str, pos, "unexpected end of input") end
    return char_func_map[str:sub(pos, pos)](str, pos)
  end
  json.decode = function(str)
    if type(str) ~= "string" then error("JSON parse error: input is not a string", 0) end
    local val = decode(str, 1)
    return val
  end

  return json
end)()

-- >>> exports
B.json = json
