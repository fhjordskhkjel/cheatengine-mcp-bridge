-- ============================================================================
-- Cheat Engine MCP Bridge :: 14_structures_table
-- Structures (UNIT-19) and cheat table records (UNIT-18)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local serverState = B.serverState

-- ============================================================================
-- COMMAND DISPATCHER
-- ============================================================================

-- >>> BEGIN UNIT-19 Structure Management <<<

serverState.structures = serverState.structures or {}
serverState.structure_next_id = serverState.structure_next_id or 1

local vartypeMap = {
    byte      = vtByte,
    word      = vtWord,
    dword     = vtDword,
    qword     = vtQword,
    float     = vtSingle,
    single    = vtSingle,
    double    = vtDouble,
    string    = vtString,
    aob       = vtByteArray,
    bytearray = vtByteArray,
    pointer   = vtPointer,
}

-- Constant reverse map; hoisted so it is not reallocated on every call.
local vtypeNames = {
    [vtByte]      = "byte",
    [vtWord]      = "word",
    [vtDword]     = "dword",
    [vtQword]     = "qword",
    [vtSingle]    = "float",
    [vtDouble]    = "double",
    [vtString]    = "string",
    [vtByteArray] = "aob",
    [vtPointer]   = "pointer",
}

local function vtypeToString(vt)
    return vtypeNames[vt] or tostring(vt)
end

-- Hoisted so it is not re-created on every export call.
local function xmlEscape(s)
    s = tostring(s)
    s = s:gsub("&", "&amp;")
    s = s:gsub("<", "&lt;")
    s = s:gsub(">", "&gt;")
    s = s:gsub('"', "&quot;")
    s = s:gsub("'", "&apos;")
    return s
end

-- Returns structure object on success, or nil + error-result table on failure.
local function resolveStructure(params)
    local sid = params.structure_id
    if not sid then
        return nil, { success = false, error = "structure_id is required", error_code = "INVALID_PARAMS" }
    end
    local structure = serverState.structures[sid]
    if not structure then
        return nil, { success = false, error = "Unknown structure_id: " .. tostring(sid), error_code = "NOT_FOUND" }
    end
    return structure, nil
end

-- Reads element properties via pcall-guarded property access.
local function readElementProps(el)
    local name, offset, vt, size
    pcall(function() name   = el.Name    end)
    pcall(function() offset = el.Offset  end)
    pcall(function() vt     = el.Vartype end)
    pcall(function() size   = el.Bytesize end)
    return name or "", offset or 0, vt, size or 0
end

function cmd_create_structure(params)
    local name = params.name
    if not name or name == "" then
        return { success = false, error = "name is required", error_code = "INVALID_PARAMS" }
    end

    local ok, structure = pcall(createStructure, name)
    if not ok or not structure then
        return { success = false, error = "createStructure failed: " .. tostring(structure), error_code = "CE_API_UNAVAILABLE" }
    end

    local ok2, err2 = pcall(function() structure.addToGlobalStructureList() end)
    if not ok2 then
        return { success = false, error = "addToGlobalStructureList failed: " .. tostring(err2), error_code = "CE_API_UNAVAILABLE" }
    end

    local id = serverState.structure_next_id
    serverState.structure_next_id = serverState.structure_next_id + 1
    serverState.structures[id] = structure

    return { success = true, structure_id = id }
end

function cmd_get_structure_by_name(params)
    local name = params.name
    if not name or name == "" then
        return { success = false, error = "name is required", error_code = "INVALID_PARAMS" }
    end

    local ok, count = pcall(getStructureCount)
    if not ok then
        return { success = false, error = "getStructureCount failed: " .. tostring(count), error_code = "CE_API_UNAVAILABLE" }
    end

    for i = 0, count - 1 do
        local ok2, s = pcall(getStructure, i)
        if ok2 and s then
            local ok3, sname = pcall(function() return s.Name end)
            if ok3 and sname == name then
                local sid = nil
                for id, stored in pairs(serverState.structures) do
                    local ok4, sn = pcall(function() return stored.Name end)
                    if ok4 and sn == name then sid = id; break end
                end
                if not sid then
                    sid = serverState.structure_next_id
                    serverState.structure_next_id = serverState.structure_next_id + 1
                    serverState.structures[sid] = s
                end
                local ok5, sz  = pcall(function() return s.Size end)
                local ok6, cnt = pcall(function() return s.Count end)
                return {
                    success       = true,
                    structure_id  = sid,
                    name          = name,
                    element_count = ok6 and cnt or 0,
                    size          = ok5 and sz  or 0,
                }
            end
        end
    end

    return { success = false, error = "Structure not found: " .. name, error_code = "NOT_FOUND" }
end

function cmd_add_element_to_structure(params)
    local ename  = params.name
    local offset = params.offset
    local etype  = params.type

    local structure, err = resolveStructure(params)
    if not structure then return err end

    if not ename or offset == nil or not etype then
        return { success = false, error = "name, offset, type are required", error_code = "INVALID_PARAMS" }
    end

    local vt = vartypeMap[string.lower(tostring(etype))]
    if not vt then
        return { success = false, error = "Unknown type: " .. tostring(etype), error_code = "INVALID_PARAMS" }
    end

    local ok, element = pcall(function() return structure.addElement() end)
    if not ok or not element then
        return { success = false, error = "addElement failed: " .. tostring(element), error_code = "CE_API_UNAVAILABLE" }
    end

    local ok2, err2 = pcall(function()
        element.Name    = ename
        element.Offset  = offset
        element.Vartype = vt
    end)
    if not ok2 then
        return { success = false, error = "Setting element properties failed: " .. tostring(err2), error_code = "CE_API_UNAVAILABLE" }
    end

    local ok3, cnt = pcall(function() return structure.Count end)
    local idx = (ok3 and cnt) and (cnt - 1) or nil

    return { success = true, element_index = idx }
end

function cmd_get_structure_elements(params)
    local structure, err = resolveStructure(params)
    if not structure then return err end

    local ok, cnt = pcall(function() return structure.Count end)
    if not ok then
        return { success = false, error = "Failed to read structure count: " .. tostring(cnt), error_code = "CE_API_UNAVAILABLE" }
    end

    local elements = {}
    for i = 0, cnt - 1 do
        local ok2, el = pcall(function() return structure.getElement(i) end)
        if ok2 and el then
            local elName, elOffset, elVt, elSize = readElementProps(el)
            elements[#elements + 1] = {
                name   = elName,
                offset = elOffset,
                type   = vtypeToString(elVt),
                size   = elSize,
            }
        end
    end

    return { success = true, structure_id = params.structure_id, elements = elements }
end

function cmd_export_structure_to_xml(params)
    local structure, err = resolveStructure(params)
    if not structure then return err end

    local ok, sname = pcall(function() return structure.Name end)
    if not ok then sname = "Unknown" end
    local ok2, sz  = pcall(function() return structure.Size end)
    if not ok2 then sz = 0 end
    local ok3, cnt = pcall(function() return structure.Count end)
    if not ok3 then cnt = 0 end

    local lines = {}
    lines[#lines + 1] = '<?xml version="1.0" encoding="utf-8"?>'
    lines[#lines + 1] = string.format('<Structure Name="%s" Size="%d">', xmlEscape(sname), sz)

    for i = 0, cnt - 1 do
        local ok4, el = pcall(function() return structure.getElement(i) end)
        if ok4 and el then
            local elName, elOffset, elVt, elSize = readElementProps(el)
            lines[#lines + 1] = string.format(
                '  <Element Name="%s" Offset="%d" Type="%s" Size="%d"/>',
                xmlEscape(elName), elOffset, xmlEscape(vtypeToString(elVt)), elSize
            )
        end
    end

    lines[#lines + 1] = '</Structure>'

    return { success = true, xml = table.concat(lines, "\n") }
end

function cmd_delete_structure(params)
    local structure, err = resolveStructure(params)
    if not structure then return err end

    pcall(function() structure.removeFromGlobalStructureList() end)
    pcall(function() structure.destroy() end)

    serverState.structures[params.structure_id] = nil
    return { success = true }
end
-- >>> BEGIN UNIT-18 Cheat Table Records <<<

local UNIT18_TYPE_MAP = {
    byte      = "vtByte",
    word      = "vtWord",
    dword     = "vtDword",
    qword     = "vtQword",
    float     = "vtSingle",
    single    = "vtSingle",
    double    = "vtDouble",
    string    = "vtString",
    bytearray = "vtByteArray",
    aob       = "vtByteArray",
}

-- Returns (al, nil) on success or (nil, error-response-table) on failure.
local function unit18_get_al()
    local ok, al = pcall(getAddressList)
    if not ok or not al then
        return nil, { success = false, error = "Cannot get AddressList", error_code = "CE_API_UNAVAILABLE" }
    end
    return al, nil
end

-- Returns (rec, nil) on success or (nil, error-response-table) when not found.
local function unit18_get_rec_by_id(al, id)
    local ok, rec = pcall(function() return al:getMemoryRecordByID(id) end)
    if not ok or not rec then
        return nil, { success = false, error = "Memory record not found", error_code = "NOT_FOUND" }
    end
    return rec, nil
end

-- Validates a table-file path: non-empty string, no directory traversal.
local function unit18_check_filename(filename)
    if type(filename) ~= "string" or filename == "" then
        return { success = false, error = "filename required", error_code = "INVALID_PARAMS" }
    end
    if filename:find("%.%.") then
        return { success = false, error = "Path traversal not allowed", error_code = "INVALID_PARAMS" }
    end
end

local function unit18_rec_to_table(rec)
    if not rec then return nil end

    local function prop(name)
        local ok, v = pcall(function() return rec[name] end)
        return ok and v or nil
    end

    local offsetCount = prop("OffsetCount") or 0
    local offsets = {}
    for i = 0, offsetCount - 1 do
        local ok, off = pcall(function() return rec.Offset[i] end)
        table.insert(offsets, ok and off or nil)
    end

    return {
        id          = prop("ID"),
        description = prop("Description") or "",
        address     = prop("Address")     or "",
        type        = prop("VarType")     or "",
        value       = prop("Value")       or "",
        offsets     = offsets,
        enabled     = prop("Active")      or false,
    }
end

function cmd_load_table(params)
    local filename = params.filename
    local err = unit18_check_filename(filename)
    if err then return err end

    local ok, cerr = pcall(loadTable, filename, params.merge or false)
    if not ok then
        return { success = false, error = tostring(cerr), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_save_table(params)
    local filename = params.filename
    local err = unit18_check_filename(filename)
    if err then return err end

    local ok, cerr = pcall(saveTable, filename, params.protect or false)
    if not ok then
        return { success = false, error = tostring(cerr), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_get_address_list(params)
    local offset = params.offset or 0
    local limit  = params.limit  or 100

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local okC, count = pcall(function() return al.Count end)
    if not okC then count = 0 end

    local records = {}
    local returned = 0
    for i = offset, math.min(offset + limit - 1, count - 1) do
        local okR, rec = pcall(function() return al[i] end)
        if okR and rec then
            table.insert(records, unit18_rec_to_table(rec))
            returned = returned + 1
        end
    end

    return {
        success  = true,
        total    = count,
        offset   = offset,
        limit    = limit,
        returned = returned,
        records  = records,
    }
end

function cmd_get_memory_record(params)
    local id   = params.id
    local desc = params.description

    if id == nil and desc == nil then
        return { success = false, error = "id or description required", error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec
    if id ~= nil then
        local ok
        ok, rec = pcall(function() return al:getMemoryRecordByID(id) end)
        if not ok then rec = nil end
    else
        local ok
        ok, rec = pcall(function() return al:getMemoryRecordByDescription(desc) end)
        if not ok then rec = nil end
    end

    if not rec then
        return { success = false, error = "Memory record not found", error_code = "NOT_FOUND" }
    end

    return { success = true, record = unit18_rec_to_table(rec) }
end

function cmd_create_memory_record(params)
    local description = params.description
    local address     = params.address
    local typeStr     = string.lower(params.type or "dword")

    if type(description) ~= "string" or description == "" then
        return { success = false, error = "description required", error_code = "INVALID_PARAMS" }
    end
    if type(address) ~= "string" or address == "" then
        return { success = false, error = "address required", error_code = "INVALID_PARAMS" }
    end

    local vtName = UNIT18_TYPE_MAP[typeStr]
    if not vtName then
        return { success = false, error = "Unknown type: " .. typeStr, error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local okC, rec = pcall(function() return al:createMemoryRecord() end)
    if not okC or not rec then
        return { success = false, error = tostring(rec), error_code = "INTERNAL_ERROR" }
    end

    -- Helper: set a property, rolling back the record on failure.
    local function set_prop(name, val)
        local ok = pcall(function() rec[name] = val end)
        if not ok then
            pcall(function() rec:delete() end)
            return { success = false, error = "Failed to set " .. name, error_code = "INTERNAL_ERROR" }
        end
    end

    local perr = set_prop("Description", description)
    if perr then return perr end

    perr = set_prop("Address", address)
    if perr then return perr end

    -- VarType accepts the string constant name; fall back to the global numeric value.
    if not pcall(function() rec.VarType = vtName end) then
        pcall(function() rec.VarType = _G[vtName] end)
    end

    local okId, recId = pcall(function() return rec.ID end)
    if not okId then recId = nil end

    return { success = true, id = recId, record = unit18_rec_to_table(rec) }
end

function cmd_delete_memory_record(params)
    local id = params.id
    if id == nil then
        return { success = false, error = "id required", error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec, rerr = unit18_get_rec_by_id(al, id)
    if not rec then return rerr end

    local ok, cerr = pcall(function() rec:delete() end)
    if not ok then
        return { success = false, error = tostring(cerr), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

function cmd_get_memory_record_value(params)
    local id = params.id
    if id == nil then
        return { success = false, error = "id required", error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec, rerr = unit18_get_rec_by_id(al, id)
    if not rec then return rerr end

    local ok, value = pcall(function() return rec.Value end)
    if not ok then
        return { success = false, error = tostring(value), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, value = tostring(value or "") }
end

function cmd_set_memory_record_value(params)
    local id    = params.id
    local value = params.value
    if id == nil then
        return { success = false, error = "id required", error_code = "INVALID_PARAMS" }
    end
    if value == nil then
        return { success = false, error = "value required", error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec, rerr = unit18_get_rec_by_id(al, id)
    if not rec then return rerr end

    local ok, cerr = pcall(function() rec.Value = tostring(value) end)
    if not ok then
        return { success = false, error = tostring(cerr), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

-- >>> END UNIT-19 <<<

-- >>> END UNIT-18 <<<

-- >>> exports
B.vartypeMap = vartypeMap
B.vtypeNames = vtypeNames
B.vtypeToString = vtypeToString
B.xmlEscape = xmlEscape
B.resolveStructure = resolveStructure
B.readElementProps = readElementProps
B.UNIT18_TYPE_MAP = UNIT18_TYPE_MAP
B.unit18_get_al = unit18_get_al
B.unit18_get_rec_by_id = unit18_get_rec_by_id
B.unit18_check_filename = unit18_check_filename
B.unit18_rec_to_table = unit18_rec_to_table
