-- ============================================================================
-- Cheat Engine MCP Bridge :: 18_memory_ops
-- Memory operations (UNIT-14)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local toHex = B.toHex
local sanitizeFilename = B.sanitizeFilename

-- >>> BEGIN UNIT-14 Memory Operations <<<
-- ============================================================================
-- COMMAND HANDLERS - MEMORY OPERATIONS (Unit 14)
-- ============================================================================

-- sanitizeFilename() is shared with UNIT-20a (defined above).

function cmd_copy_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

    local src = params.source
    local size = params.size
    local dest = params.dest  -- may be nil
    local method = params.method or 0

    if not src then return { success = false, error = "Missing source address", error_code = "INVALID_PARAMS" } end
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size", error_code = "INVALID_PARAMS" } end

    if type(src) == "string" then src = getAddressSafe(src) end
    if not src then return { success = false, error = "Invalid source address", error_code = "INVALID_ADDRESS" } end

    local destAddr = nil
    if dest ~= nil then
        if type(dest) == "string" then destAddr = getAddressSafe(dest)
        else destAddr = dest end
        if not destAddr then return { success = false, error = "Invalid dest address", error_code = "INVALID_ADDRESS" } end
    end

    local ok, result = pcall(copyMemory, src, size, destAddr, method)
    if not ok or not result then
        return { success = false, error = "copyMemory failed: " .. tostring(result), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, dest_address = toHex(result), size = size }
end

function cmd_compare_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

    local addr1 = params.addr1
    local addr2 = params.addr2
    local size = params.size
    local method = params.method or 0

    if not addr1 then return { success = false, error = "Missing addr1", error_code = "INVALID_PARAMS" } end
    if not addr2 then return { success = false, error = "Missing addr2", error_code = "INVALID_PARAMS" } end
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size", error_code = "INVALID_PARAMS" } end

    if type(addr1) == "string" then addr1 = getAddressSafe(addr1) end
    if type(addr2) == "string" then addr2 = getAddressSafe(addr2) end
    if not addr1 then return { success = false, error = "Invalid addr1", error_code = "INVALID_ADDRESS" } end
    if not addr2 then return { success = false, error = "Invalid addr2", error_code = "INVALID_ADDRESS" } end

    local ok, r1, r2 = pcall(compareMemory, addr1, addr2, size, method)
    if not ok then
        return { success = false, error = "compareMemory failed: " .. tostring(r1), error_code = "INTERNAL_ERROR" }
    end

    if r1 == true then
        return { success = true, equal = true, first_diff = -1 }
    else
        return { success = true, equal = false, first_diff = r2 or -1 }
    end
end

function cmd_write_region_to_file(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

    local addr = params.address
    local size = params.size
    local filename = params.filename

    local sanitized, err = sanitizeFilename(filename)
    if not sanitized then return { success = false, error = err, error_code = "INVALID_PARAMS" } end

    if not addr then return { success = false, error = "Missing address", error_code = "INVALID_PARAMS" } end
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size", error_code = "INVALID_PARAMS" } end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    local ok, bytes_written = pcall(writeRegionToFile, sanitized, addr, size)
    if not ok then
        return { success = false, error = "writeRegionToFile failed: " .. tostring(bytes_written), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, bytes_written = bytes_written or 0, filename = sanitized }
end

function cmd_read_region_from_file(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

    local filename = params.filename
    local destination = params.destination

    local sanitized, err = sanitizeFilename(filename)
    if not sanitized then return { success = false, error = err, error_code = "INVALID_PARAMS" } end

    if not destination then return { success = false, error = "Missing destination address", error_code = "INVALID_PARAMS" } end

    if type(destination) == "string" then destination = getAddressSafe(destination) end
    if not destination then return { success = false, error = "Invalid destination address", error_code = "INVALID_ADDRESS" } end

    local ok, bytes_read = pcall(readRegionFromFile, sanitized, destination)
    if not ok then
        return { success = false, error = "readRegionFromFile failed: " .. tostring(bytes_read), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, bytes_read = bytes_read or 0 }
end

function cmd_md5_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

    local addr = params.address
    local size = params.size

    if not addr then return { success = false, error = "Missing address", error_code = "INVALID_PARAMS" } end
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size", error_code = "INVALID_PARAMS" } end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    local ok, result = pcall(md5memory, addr, size)
    if not ok or not result then
        return { success = false, error = "md5memory failed: " .. tostring(result), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, md5 = tostring(result) }
end

function cmd_md5_file(params)
    local filename = params.filename

    local sanitized, err = sanitizeFilename(filename)
    if not sanitized then return { success = false, error = err, error_code = "INVALID_PARAMS" } end

    local ok, result = pcall(md5file, sanitized)
    if not ok or not result then
        return { success = false, error = "md5file failed: " .. tostring(result), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, md5 = tostring(result) }
end

function cmd_create_section(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

    local size = params.size
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size", error_code = "INVALID_PARAMS" } end

    local ok, handle = pcall(createSection, size)
    if not ok or not handle then
        return { success = false, error = "createSection failed: " .. tostring(handle), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, handle = toHex(handle) }
end

function cmd_map_view_of_section(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

    local handle = params.handle
    local address = params.address  -- optional preferred base

    if not handle then return { success = false, error = "Missing handle", error_code = "INVALID_PARAMS" } end

    if type(handle) == "string" then handle = tonumber(handle, 16) end
    if not handle then return { success = false, error = "Invalid handle", error_code = "INVALID_PARAMS" } end

    local prefAddr = nil
    if address ~= nil then
        if type(address) == "string" then prefAddr = getAddressSafe(address)
        else prefAddr = address end
        if not prefAddr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end
    end

    local ok, mapped
    if prefAddr then
        ok, mapped = pcall(mapViewOfSection, handle, prefAddr)
    else
        ok, mapped = pcall(mapViewOfSection, handle)
    end

    if not ok or not mapped then
        return { success = false, error = "mapViewOfSection failed: " .. tostring(mapped), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, mapped_address = toHex(mapped) }
end

-- >>> END UNIT-14 <<<
