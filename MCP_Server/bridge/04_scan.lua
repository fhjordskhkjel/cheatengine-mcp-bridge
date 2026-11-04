-- ============================================================================
-- Cheat Engine MCP Bridge :: 04_scan
-- Value / AOB scanning, next scan, memory writes
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local serverState = B.serverState
local toHex = B.toHex

-- ============================================================================
-- COMMAND HANDLERS - PATTERN SCANNING
-- ============================================================================

function cmd_aob_scan(params)
    local pattern = params.pattern
    local protection = params.protection or "+X"
    local limit = params.limit or 100
    
    if not pattern then return { success = false, error = "No pattern provided", error_code = "INVALID_PARAMS" } end
    
    local results = AOBScan(pattern, protection)
    if not results then return { success = true, count = 0, addresses = {} } end
    
    local addresses = {}
    for i = 0, math.min(results.Count - 1, limit - 1) do
        local addrStr = results.getString(i)
        local addr = tonumber(addrStr, 16)
        table.insert(addresses, { 
            address = "0x" .. addrStr, 
            value = addr 
        })
    end
    results.destroy()
    
    return { success = true, count = #addresses, pattern = pattern, addresses = addresses }
end

local USER_MODE_MAX = 0x7FFFFFFFFFFFFFFF

-- An async scan job owns the shared memscan until it finishes.
local function scanBusyError()
    if serverState.scan_job_id then
        return { success = false, error = "Scan job " .. serverState.scan_job_id .. " is still running; poll get_job or cancel_job first.", error_code = "BUSY" }
    end
    return nil
end

-- Validates scan_all parameters. Shared by cmd_scan_all and the scan_all job so both
-- behave identically. Returns args table, or nil + error reply.
local function prepareFirstScan(params)
    local vtype = params.type or "dword"

    local scanOpt = resolveScanOption(params.scan_option or "exact")
    if not scanOpt then
        return nil, { success = false, error = "Unknown scan_option '" .. tostring(params.scan_option) .. "'. Valid: " .. SCAN_OPTION_NAMES, error_code = "INVALID_PARAMS" }
    end
    if scanOpt ~= soExactValue and scanOpt ~= soUnknownValue and scanOpt ~= soValueBetween
       and scanOpt ~= soBiggerThan and scanOpt ~= soSmallerThan then
        return nil, { success = false, error = "scan_option '" .. tostring(params.scan_option) .. "' is only valid for next_scan. First scan supports: exact, unknown, between, bigger, smaller", error_code = "INVALID_PARAMS" }
    end

    local input1, input2, inputErr = resolveScanInputs(scanOpt, params.value, params.value2)
    if inputErr then
        return nil, { success = false, error = inputErr, error_code = "INVALID_PARAMS" }
    end

    local varType = vtDword
    if vtype == "byte" then varType = vtByte
    elseif vtype == "word" then varType = vtWord
    elseif vtype == "qword" then varType = vtQword
    elseif vtype == "float" then varType = vtSingle
    elseif vtype == "double" then varType = vtDouble
    elseif vtype == "string" then varType = vtString end

    -- Use specific protection flags if provided (defaults to +W-C from Python)
    return { scanOpt = scanOpt, varType = varType, input1 = input1, input2 = input2,
             protect = params.protection or "+W-C" }
end

-- Makes a finished first-scan memscan the active scan session; returns the result count.
local function commitFirstScan(ms, scanOpt)
    local fl = createFoundList(ms)
    fl.initialize()
    local count = fl.getCount()

    if serverState.scan_foundlist then
        pcall(function() serverState.scan_foundlist.destroy() end)
        serverState.scan_foundlist = nil
    end
    if serverState.scan_memscan then
        pcall(function() serverState.scan_memscan.destroy() end)
        serverState.scan_memscan = nil
    end

    serverState.scan_memscan = ms
    serverState.scan_foundlist = fl
    serverState.scan_is_unknown_first = (scanOpt == soUnknownValue)

    -- unknown-initial-value scans report 0 via the foundlist; see resolveScanResultCount()
    if scanOpt == soUnknownValue then
        count = resolveScanResultCount(ms, count)
    end
    return count
end

function cmd_scan_all(params)
    local busy = scanBusyError()
    if busy then return busy end
    local args, err = prepareFirstScan(params)
    if err then return err end

    local ms = createMemScan()

    -- CRITICAL: Limit scan to User Mode space (0x7FFFFFFFFFFFFFFF) to prevent BSODs in Kernel/Guard regions
    ms.firstScan(args.scanOpt, args.varType, rtRounded, args.input1, args.input2, 0, USER_MODE_MAX, args.protect, fsmNotAligned, "1", false, false, false, false)
    ms.waitTillDone()

    return { success = true, count = commitFirstScan(ms, args.scanOpt) }
end

function cmd_get_scan_results(params)
    local busy = scanBusyError()
    if busy then return busy end
    -- limit: preferred param; max: backward-compat alias
    local limit = params.limit or params.max or 100
    limit = math.max(1, math.min(limit, 10000))
    local offset = math.max(0, params.offset or 0)

    if not serverState.scan_foundlist then
        return { success = false, error = "No scan results. Run scan_all first.", error_code = "NOT_FOUND" }
    end

    local fl = serverState.scan_foundlist
    local total = fl.getCount()
    local results = {}

    -- NOTE: unknown-initial-value scans are not individually enumerable via the
    -- foundlist (see resolveScanResultCount()); report the scanned-address total
    -- and signal it so an empty result list isn't mistaken for a scan failure.
    if serverState.scan_is_unknown_first then
        local ms = serverState.scan_memscan
        if ms then
            total = resolveScanResultCount(ms, total)
        end
        return {
            success = true,
            total = total,
            offset = offset,
            limit = limit,
            returned = 0,
            results = results,
            enumerable = false,
            unknown_initial_value = true,
            note = UNKNOWN_SCAN_NOTE
        }
    end

    local endIdx = math.min(offset + limit, total) - 1

    for i = offset, endIdx do
        -- IMPORTANT: Ensure address has 0x prefix for consistency with all other commands
        local addrStr = fl.getAddress(i)
        if addrStr and not addrStr:match("^0x") and not addrStr:match("^0X") then
            addrStr = "0x" .. addrStr
        end
        table.insert(results, {
            address = addrStr,
            value = fl.getValue(i)
        })
    end

    return { success = true, total = total, offset = offset, limit = limit, returned = #results, results = results }
end

-- ============================================================================
-- COMMAND HANDLERS - NEXT SCAN & WRITE MEMORY (Added by MCP Enhancement)
-- ============================================================================

-- Validates next_scan parameters (shared with the next_scan job).
local function prepareNextScan(params)
    -- scan_option is the v12 name; scan_type is kept as a backward-compat alias
    local scanType = params.scan_option or params.scan_type or "exact"

    if not serverState.scan_memscan then
        return nil, { success = false, error = "No previous scan. Run scan_all first.", error_code = "NOT_FOUND" }
    end

    local scanOpt = resolveScanOption(scanType)
    if not scanOpt then
        return nil, { success = false, error = "Unknown scan_option '" .. tostring(scanType) .. "'. Valid: " .. SCAN_OPTION_NAMES, error_code = "INVALID_PARAMS" }
    end
    if scanOpt == soUnknownValue then
        return nil, { success = false, error = "scan_option 'unknown' is only valid for scan_all", error_code = "INVALID_PARAMS" }
    end

    local input1, input2, inputErr = resolveScanInputs(scanOpt, params.value, params.value2)
    if inputErr then
        return nil, { success = false, error = inputErr, error_code = "INVALID_PARAMS" }
    end

    return { ms = serverState.scan_memscan, scanOpt = scanOpt, input1 = input1, input2 = input2 }
end

-- Replaces the foundlist with the results of the finished next scan; returns the count.
local function commitNextScan(ms)
    if serverState.scan_foundlist then
        serverState.scan_foundlist.destroy()
    end
    local fl = createFoundList(ms)
    fl.initialize()
    serverState.scan_foundlist = fl
    serverState.scan_is_unknown_first = false
    return fl.getCount()
end

function cmd_next_scan(params)
    local busy = scanBusyError()
    if busy then return busy end
    local args, err = prepareNextScan(params)
    if err then return err end

    args.ms.nextScan(args.scanOpt, rtRounded, args.input1, args.input2, false, false, false, false, false)
    args.ms.waitTillDone()

    return { success = true, count = commitNextScan(args.ms) }
end

function cmd_write_integer(params)
    local addr = params.address
    local value = params.value
    local vtype = params.type or "dword"

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    if vtype == "byte" then
        if type(value) ~= "number" or value < 0 or value > 0xFF then
            return { success = false, error = "Value too large for type", error_code = "INVALID_PARAMS" }
        end
    elseif vtype == "word" or vtype == "2bytes" then
        if type(value) ~= "number" or value < 0 or value > 0xFFFF then
            return { success = false, error = "Value too large for type", error_code = "INVALID_PARAMS" }
        end
    elseif vtype == "dword" or vtype == "4bytes" then
        if type(value) ~= "number" or value < 0 or value > 0xFFFFFFFF then
            return { success = false, error = "Value too large for type", error_code = "INVALID_PARAMS" }
        end
    end

    local ok, err
    if vtype == "byte" then
        ok, err = pcall(writeByte, addr, value)
    elseif vtype == "word" or vtype == "2bytes" then
        ok, err = pcall(writeSmallInteger, addr, value)
    elseif vtype == "dword" or vtype == "4bytes" then
        ok, err = pcall(writeInteger, addr, value)
    elseif vtype == "qword" or vtype == "8bytes" then
        ok, err = pcall(writeQword, addr, value)
    elseif vtype == "float" then
        ok, err = pcall(writeFloat, addr, value)
    elseif vtype == "double" then
        ok, err = pcall(writeDouble, addr, value)
    else
        return { success = false, error = "Unknown type: " .. tostring(vtype), error_code = "INVALID_PARAMS" }
    end

    if not ok then
        return { success = false, error = "Write failed: " .. tostring(err), address = toHex(addr), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, address = toHex(addr), value = value, type = vtype }
end

function cmd_write_memory(params)
    local addr = params.address
    local bytes = params.bytes
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end
    if not bytes or #bytes == 0 then return { success = false, error = "No bytes provided", error_code = "INVALID_PARAMS" } end
    
    local ok, err = pcall(writeBytes, addr, bytes)
    
    if not ok then
        return { success = false, error = "Write failed: " .. tostring(err), address = toHex(addr), error_code = "INTERNAL_ERROR" }
    end
    
    return { success = true, address = toHex(addr), bytes_written = #bytes }
end

function cmd_write_string(params)
    local addr = params.address
    local str = params.value or params.string
    local wide = params.wide or false
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end
    if not str then return { success = false, error = "No string provided", error_code = "INVALID_PARAMS" } end
    
    local ok, err = pcall(writeString, addr, str, wide)
    
    if not ok then
        return { success = false, error = "Write failed: " .. tostring(err), address = toHex(addr), error_code = "INTERNAL_ERROR" }
    end
    
    return { success = true, address = toHex(addr), length = #str, wide = wide }
end

-- >>> exports
B.USER_MODE_MAX = USER_MODE_MAX
B.scanBusyError = scanBusyError
B.prepareFirstScan = prepareFirstScan
B.commitFirstScan = commitFirstScan
B.prepareNextScan = prepareNextScan
B.commitNextScan = commitNextScan
