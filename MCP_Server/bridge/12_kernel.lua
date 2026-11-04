-- ============================================================================
-- Cheat Engine MCP Bridge :: 12_kernel
-- Kernel mode / DBK / DBVM extensions (UNIT-21)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local toHex = B.toHex
local mappedMemoryMDL = B.mappedMemoryMDL

-- >>> BEGIN UNIT-21 Kernel DBVM <<<
-- ============================================================================
-- COMMAND HANDLERS - KERNEL MODE / DBVM EXTENSIONS (Unit 21)
-- Requires DBK kernel driver and/or DBVM hypervisor to be loaded.
-- ============================================================================

-- MDL handles for active mapMemory() calls, keyed by mapped-address hex string.

local function dbkNotLoadedError()
    return {
        success = false,
        error = "Kernel driver (DBK) or hypervisor (DBVM) not loaded",
        error_code = "DBK_NOT_LOADED"
    }
end

function cmd_dbk_get_cr0(params)
    local ok, result = pcall(dbk_getCR0)
    if not ok then return dbkNotLoadedError() end
    return { success = true, cr0 = toHex(result) }
end

function cmd_dbk_get_cr3(params)
    local ok, result = pcall(dbk_getCR3)
    if not ok then return dbkNotLoadedError() end
    return { success = true, cr3 = toHex(result) }
end

function cmd_dbk_get_cr4(params)
    local ok, result = pcall(dbk_getCR4)
    if not ok then return dbkNotLoadedError() end
    return { success = true, cr4 = toHex(result) }
end

function cmd_read_process_memory_cr3(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local cr3_str  = params.cr3
    local addr_str = params.address
    local size     = tonumber(params.size)

    if not cr3_str or not addr_str or not size or size <= 0 then
        return { success = false, error = "Parameters cr3, address and size are required", error_code = "INVALID_PARAMS" }
    end

    local cr3  = type(cr3_str)  == "string" and getAddressSafe(cr3_str)  or cr3_str
    local addr = type(addr_str) == "string" and getAddressSafe(addr_str) or addr_str
    if not cr3 or not addr then
        return { success = false, error = "Invalid cr3 or address value", error_code = "INVALID_ADDRESS" }
    end

    local ok, byteTable = pcall(readProcessMemoryCR3, cr3, addr, size)
    if not ok then return dbkNotLoadedError() end
    if not byteTable then
        return { success = false, error = "Read failed — page may be paged out or invalid", error_code = "INVALID_ADDRESS" }
    end

    return { success = true, bytes = byteTable, size = #byteTable }
end

function cmd_write_process_memory_cr3(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local cr3_str  = params.cr3
    local addr_str = params.address
    local bytes    = params.bytes

    if not cr3_str or not addr_str or not bytes or type(bytes) ~= "table" then
        return { success = false, error = "Parameters cr3, address and bytes (list) are required", error_code = "INVALID_PARAMS" }
    end

    local cr3  = type(cr3_str)  == "string" and getAddressSafe(cr3_str)  or cr3_str
    local addr = type(addr_str) == "string" and getAddressSafe(addr_str) or addr_str
    if not cr3 or not addr then
        return { success = false, error = "Invalid cr3 or address value", error_code = "INVALID_ADDRESS" }
    end

    local ok = pcall(writeProcessMemoryCR3, cr3, addr, bytes)
    if not ok then return dbkNotLoadedError() end

    return { success = true, bytes_written = #bytes }
end

function cmd_map_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local addr_str = params.address
    local size     = tonumber(params.size)

    if not addr_str or not size or size <= 0 then
        return { success = false, error = "Parameters address and size are required", error_code = "INVALID_PARAMS" }
    end

    local addr = type(addr_str) == "string" and getAddressSafe(addr_str) or addr_str
    if not addr then
        return { success = false, error = "Invalid address value", error_code = "INVALID_ADDRESS" }
    end

    local ok, mappedAddr, mdl = pcall(mapMemory, addr, size)
    if not ok then return dbkNotLoadedError() end
    if not mappedAddr then
        return { success = false, error = "mapMemory failed — address may be invalid or DBK not loaded", error_code = "INTERNAL_ERROR" }
    end

    local key = toHex(mappedAddr)
    mappedMemoryMDL[key] = mdl  -- retain MDL so unmap_memory can release it

    return { success = true, mapped_address = key }
end

function cmd_unmap_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local addr_str = params.mapped_address
    if not addr_str then
        return { success = false, error = "Parameter mapped_address is required", error_code = "INVALID_PARAMS" }
    end

    local addr = type(addr_str) == "string" and getAddressSafe(addr_str) or addr_str
    if not addr then
        return { success = false, error = "Invalid mapped_address value", error_code = "INVALID_ADDRESS" }
    end

    local key = toHex(addr)
    local ok  = pcall(unmapMemory, addr, mappedMemoryMDL[key])
    if not ok then return dbkNotLoadedError() end

    mappedMemoryMDL[key] = nil

    return { success = true }
end

function cmd_dbk_writes_ignore_write_protection(params)
    local enable = params.enable
    if type(enable) ~= "boolean" then
        return { success = false, error = "Parameter enable (boolean) is required", error_code = "INVALID_PARAMS" }
    end

    local ok = pcall(dbk_writesIgnoreWriteProtection, enable)
    if not ok then return dbkNotLoadedError() end

    return { success = true }
end

function cmd_get_physical_address_cr3(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local cr3_str = params.cr3
    local va_str  = params.virtual_address

    if not cr3_str or not va_str then
        return { success = false, error = "Parameters cr3 and virtual_address are required", error_code = "INVALID_PARAMS" }
    end

    local cr3 = type(cr3_str) == "string" and getAddressSafe(cr3_str) or cr3_str
    local va  = type(va_str)  == "string" and getAddressSafe(va_str)  or va_str
    if not cr3 or not va then
        return { success = false, error = "Invalid cr3 or virtual_address value", error_code = "INVALID_ADDRESS" }
    end

    local ok, phys = pcall(getPhysicalAddressCR3, cr3, va)
    if not ok then return dbkNotLoadedError() end
    if not phys then
        return { success = false, error = "Address not paged — virtual address may not be mapped in this CR3", error_code = "INVALID_ADDRESS" }
    end

    return { success = true, physical_address = toHex(phys) }
end

-- >>> END UNIT-21 <<<

-- >>> exports
B.dbkNotLoadedError = dbkNotLoadedError
