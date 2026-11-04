-- ============================================================================
-- Cheat Engine MCP Bridge :: 09_analysis_tools
-- High-level analysis tools (structures, threads, signatures, pointer chains)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local toHex = B.toHex
local paginate = B.paginate
local serverState = B.serverState

-- ============================================================================
-- COMMAND HANDLERS - HIGH-LEVEL ANALYSIS TOOLS
-- ============================================================================

-- Dissect Structure: Uses CE's Structure.autoGuess to map memory into typed fields
function cmd_dissect_structure(params)
    local address = params.address
    local size = params.size or 256
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end
    
    -- Create a temporary structure and use autoGuess
    local ok, struct = pcall(createStructure, "MCP_TempStruct")
    if not ok or not struct then
        return { success = false, error = "Failed to create structure", error_code = "INTERNAL_ERROR" }
    end
    
    -- Use the Structure class autoGuess method
    pcall(function() struct:autoGuess(address, 0, size) end)
    
    local elements = {}
    local count = struct.Count or 0
    
    for i = 0, count - 1 do
        local elem = struct.Element[i]
        if elem then
            local val = nil
            -- Try to get current value
            pcall(function() val = elem:getValue(address) end)
            
            table.insert(elements, {
                offset = elem.Offset,
                hex_offset = string.format("+0x%X", elem.Offset),
                name = elem.Name or "",
                vartype = elem.Vartype,
                bytesize = elem.Bytesize,
                current_value = val
            })
        end
    end
    
    -- Cleanup - don't add to global list
    pcall(function() struct:removeFromGlobalStructureList() end)
    
    return {
        success = true,
        base_address = toHex(address),
        size_analyzed = size,
        element_count = #elements,
        elements = elements
    }
end

-- Get Thread List: Returns all threads in the attached process
function cmd_get_thread_list(params)
    local list = createStringlist()
    getThreadlist(list)

    local allThreads = {}
    for i = 0, list.Count - 1 do
        local idHex = list[i]
        allThreads[#allThreads + 1] = { id_hex = idHex, id_int = tonumber(idHex, 16) }
    end
    list.destroy()

    local limit, offset, page, total = paginate(params, allThreads, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, threads = page }
end

-- AutoAssemble: Execute an AutoAssembler script
function cmd_auto_assemble(params)
    local script = params.script or params.code
    local disable = params.disable or false
    
    if not script then return { success = false, error = "No script provided", error_code = "INVALID_PARAMS" } end
    
    local success, disableInfo = autoAssemble(script)
    
    if success then
        serverState.aa_last = { script = script, info = disableInfo }     -- picked up by the patch journal (UNIT-31)
        local result = {
            success = true,
            executed = true
        }
        -- If disable info is returned, include symbol addresses
        if disableInfo and disableInfo.symbols then
            result.symbols = {}
            for name, addr in pairs(disableInfo.symbols) do
                result.symbols[name] = toHex(addr)
            end
        end
        return result
    else
        return {
            success = false,
            error = "AutoAssemble failed: " .. tostring(disableInfo),
            error_code = "INTERNAL_ERROR"
        }
    end
end

-- Enum Memory Regions Full: Uses CE's native enumMemoryRegions for accurate data
function cmd_enum_memory_regions_full(params)
    local ok, regions = pcall(enumMemoryRegions)
    if not ok or not regions then
        return { success = false, error = "enumMemoryRegions failed", error_code = "INTERNAL_ERROR" }
    end

    local allRegions = {}
    for i, r in ipairs(regions) do
        local prot = r.Protect or 0
        local state = r.State or 0
        local protStr
        if     prot == 0x10 then protStr = "X"
        elseif prot == 0x20 then protStr = "RX"
        elseif prot == 0x40 then protStr = "RWX"
        elseif prot == 0x80 then protStr = "WX"
        elseif prot == 0x02 then protStr = "R"
        elseif prot == 0x04 then protStr = "RW"
        elseif prot == 0x08 then protStr = "W"
        else                     protStr = string.format("0x%X", prot)
        end

        allRegions[#allRegions + 1] = {
            base             = toHex(r.BaseAddress or 0),
            allocation_base  = toHex(r.AllocationBase or 0),
            size             = r.RegionSize or 0,
            state            = state,
            protect          = prot,
            protect_string   = protStr,
            type             = r.Type or 0,
            is_committed     = state == 0x1000,
            is_reserved      = state == 0x2000,
            is_free          = state == 0x10000
        }
    end

    local limit, offset, page, total = paginate(params, allRegions, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, regions = page }
end

-- Read Pointer Chain: Follow a chain of pointers to resolve dynamic addresses
function cmd_read_pointer_chain(params)
    local offsets = params.offsets or {}
    local r = resolveChain(params.base, offsets)
    if not r.ok then
        return { success = false, error = r.error, partial_chain = r.chain, failed_at_address = r.failed_at, error_code = "INVALID_ADDRESS" }
    end
    return {
        success = true,
        base = r.base,
        offsets = offsets,
        final_address = r.final_address_hex,
        final_value = r.final_value,
        chain = r.chain
    }
end

-- Get RTTI Class Name: Uses C++ RTTI to identify object types
function cmd_get_rtti_classname(params)
    local address = params.address
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end
    
    local className = getRTTIClassName(address)
    
    if className then
        return {
            success = true,
            address = toHex(address),
            class_name = className,
            found = true
        }
    else
        return {
            success = true,
            address = toHex(address),
            class_name = nil,
            found = false,
            note = "No RTTI information found at this address"
        }
    end
end

-- Get Address Info: Converts raw address to symbolic name (module+offset)
function cmd_get_address_info(params)
    local address = params.address
    local includeModules = params.include_modules ~= false  -- default true
    local includeSymbols = params.include_symbols ~= false  -- default true
    local includeSections = params.include_sections or false  -- default false
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end
    
    local symbolicName = getNameFromAddress(address, includeModules, includeSymbols, includeSections)
    
    -- inModule() may fail or return nil in anti-cheat environments, so we check symbolicName too
    local isInModule = false
    local okInMod, inModResult = pcall(inModule, address)
    if okInMod and inModResult then
        isInModule = true
    elseif symbolicName and symbolicName:match("%+") then
        -- symbolicName contains "+" like "L2.exe+1000" which means it's in a module
        isInModule = true
    end
    
    -- Ensure symbolic_name has 0x prefix if it's just a hex address
    if symbolicName and symbolicName:match("^%x+$") then
        symbolicName = "0x" .. symbolicName
    end
    
    return {
        success = true,
        address = toHex(address),
        symbolic_name = symbolicName or toHex(address),
        is_in_module = isInModule,
        options_used = {
            include_modules = includeModules,
            include_symbols = includeSymbols,
            include_sections = includeSections
        }
    }
end

-- Checksum Memory: Calculate MD5 hash of a memory region
function cmd_checksum_memory(params)
    local address = params.address
    local size = params.size or 256
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end
    
    local ok, hash = pcall(md5memory, address, size)
    
    if ok and hash then
        return {
            success = true,
            address = toHex(address),
            size = size,
            md5_hash = hash
        }
    else
        return {
            success = false,
            address = toHex(address),
            size = size,
            error = "Failed to calculate MD5: " .. tostring(hash),
            error_code = "INTERNAL_ERROR"
        }
    end
end

-- Generate Signature: Creates a unique AOB pattern for an address (for re-acquisition)
function cmd_generate_signature(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end
    
    -- getUniqueAOB(address) returns: AOBString, Offset
    -- It scans for a unique byte pattern that identifies this location
    local ok, signature, offset = pcall(getUniqueAOB, addr)
    
    if not ok then
        return {
            success = false,
            address = toHex(addr),
            error = "getUniqueAOB failed: " .. tostring(signature),
            error_code = "INTERNAL_ERROR"
        }
    end
    
    if not signature or signature == "" then
        return {
            success = false,
            address = toHex(addr),
            error = "Could not generate unique signature - pattern not unique enough",
            error_code = "NOT_FOUND"
        }
    end
    
    -- Calculate signature length (count bytes, wildcards count as 1)
    local byteCount = 0
    for _ in signature:gmatch("%S+") do
        byteCount = byteCount + 1
    end
    
    return {
        success = true,
        address = toHex(addr),
        signature = signature,
        offset_from_start = offset or 0,
        byte_count = byteCount,
        usage_hint = string.format("aob_scan('%s') then add offset %d to reach target", signature, offset or 0)
    }
end
