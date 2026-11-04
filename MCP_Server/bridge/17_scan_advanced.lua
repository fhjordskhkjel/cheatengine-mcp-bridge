-- ============================================================================
-- Cheat Engine MCP Bridge :: 17_scan_advanced
-- Advanced scanning (UNIT-15)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local serverState = B.serverState
local requireProcess = B.requireProcess

-- >>> BEGIN UNIT-15 Advanced Scanning <<<
-- ============================================================================
-- UNIT 15: Advanced Scanning (module-scoped, unique, persistent)
-- ============================================================================

-- Persistent scan state (Unit 15)
serverState.persistent_scans = serverState.persistent_scans or {}

-- Helper: NO_PROCESS guard used by all Unit-15 commands

-- Helper: map human-readable var-type string to CE constant
local function resolveVarType(vtype)
    local t = (vtype or "dword"):lower()
    if t == "byte"   then return vtByte
    elseif t == "word"   then return vtWord
    elseif t == "dword"  then return vtDword
    elseif t == "qword"  then return vtQword
    elseif t == "float"  then return vtSingle
    elseif t == "double" then return vtDouble
    elseif t == "string" then return vtString
    else return vtDword
    end
end

-- resolveScanOption / resolveScanInputs live in the HELPER FUNCTIONS section at the top of this file (global, so every cmd_* handler shares one mapping).

function cmd_aob_scan_unique(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local pattern    = params.pattern
    local protection = params.protection or "+X"

    if not pattern then
        return { success = false, error = "No pattern provided", error_code = "INVALID_PARAMS" }
    end

    -- AOBScan lets us count matches; AOBScanUnique returns first-found (non-deterministic on multiple hits)
    local results
    local scanOk, scanMsg = pcall(function()
        results = AOBScan(pattern, protection)
    end)
    if not scanOk then
        return { success = false, error = "AOBScan failed: " .. tostring(scanMsg), error_code = "INTERNAL_ERROR" }
    end

    local count = results and results.Count or 0
    if count ~= 1 then
        if results then pcall(function() results.destroy() end) end
        return {
            success    = false,
            error      = "Pattern matched " .. tostring(count) .. " times (expected 1)",
            error_code = "INVALID_PARAMS",
            count      = count
        }
    end

    local addrStr = results.getString(0)
    local addr    = tonumber(addrStr, 16)
    pcall(function() results.destroy() end)

    return {
        success = true,
        address = "0x" .. (addrStr or "0"),
        value   = addr
    }
end

function cmd_aob_scan_module(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local pattern     = params.pattern
    local module_name = params.module_name
    local protection  = params.protection or "+X"

    if not pattern     then return { success = false, error = "No pattern provided",     error_code = "INVALID_PARAMS" } end
    if not module_name then return { success = false, error = "No module_name provided", error_code = "INVALID_PARAMS" } end

    local modBase, modSize
    local modBaseOk = pcall(function() modBase = getAddress(module_name) end)
    if not modBaseOk or not modBase or modBase == 0 then
        return { success = false, error = "Module not found: " .. tostring(module_name), error_code = "INVALID_PARAMS" }
    end

    local modSizeOk = pcall(function() modSize = getModuleSize(module_name) end)
    if not modSizeOk or not modSize or modSize == 0 then
        return { success = false, error = "Cannot get module size for: " .. tostring(module_name), error_code = "INVALID_PARAMS" }
    end

    local modEnd = modBase + modSize

    local results
    local scanOk, scanMsg = pcall(function() results = AOBScan(pattern, protection) end)
    if not scanOk then
        return { success = false, error = "AOBScan failed: " .. tostring(scanMsg), error_code = "INTERNAL_ERROR" }
    end

    local addresses = {}
    if results and results.Count > 0 then
        for i = 0, results.Count - 1 do
            local addrStr = results.getString(i)
            local addr    = tonumber(addrStr, 16)
            if addr and addr >= modBase and addr < modEnd then
                table.insert(addresses, "0x" .. addrStr)
            end
        end
    end
    if results then pcall(function() results.destroy() end) end

    return {
        success     = true,
        count       = #addresses,
        module_name = module_name,
        pattern     = pattern,
        addresses   = addresses
    }
end

function cmd_aob_scan_module_unique(params)
    -- requireProcess() is also called inside cmd_aob_scan_module; early-exit here gives a cleaner error path
    local ok, err = requireProcess()
    if not ok then return err end

    local r = cmd_aob_scan_module(params)
    if not r.success then return r end

    local count = r.count or 0
    if count ~= 1 then
        return {
            success    = false,
            error      = "Pattern matched " .. tostring(count) .. " times in module (expected 1)",
            error_code = "INVALID_PARAMS",
            count      = count
        }
    end

    return {
        success = true,
        address = r.addresses[1],
        module_name = params.module_name
    }
end

function cmd_pointer_rescan(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local value               = params.value
    local previous_results_file = params.previous_results_file

    if not value then
        return { success = false, error = "No value provided", error_code = "INVALID_PARAMS" }
    end

    local rescanOk, rescanMsg = pcall(function()
        if previous_results_file then
            pointerRescan(value, previous_results_file)
        else
            pointerRescan(value)
        end
    end)

    if not rescanOk then
        return {
            success    = false,
            error      = "pointerRescan failed: " .. tostring(rescanMsg),
            error_code = "INTERNAL_ERROR",
            note       = "A prior pointer scan must exist in CE before calling pointer_rescan"
        }
    end

    return { success = true, result_count = -1, note = "Pointer rescan complete. Check CE Pointer Scanner window for results." }
end

function cmd_create_persistent_scan(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local name = params.name
    if not name or name == "" then
        return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" }
    end

    local existing = serverState.persistent_scans[name]
    if existing then
        if existing.fl then pcall(function() existing.fl.destroy() end) end
        pcall(function() existing.ms.destroy() end)
        serverState.persistent_scans[name] = nil
    end

    local ms
    local msOk, msMsg = pcall(function() ms = createMemScan() end)
    if not msOk or not ms then
        return { success = false, error = "createMemScan failed: " .. tostring(msMsg), error_code = "INTERNAL_ERROR" }
    end

    serverState.persistent_scans[name] = {
        ms            = ms,
        fl            = nil,
        has_scan      = false,
        unknown_first = false
    }

    return { success = true, scan_name = name }
end

function cmd_persistent_scan_first_scan(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local name        = params.name
    local value       = params.value
    local vtype       = params.type or "dword"
    local scan_option = params.scan_option or "exact"

    if not name then return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" } end

    local entry = serverState.persistent_scans[name]
    if not entry then
        return { success = false, error = "Scan '" .. name .. "' not found. Call create_persistent_scan first.", error_code = "INVALID_PARAMS" }
    end

    local ms      = entry.ms
    local varType = resolveVarType(vtype)
    local scanOpt = resolveScanOption(scan_option)
    if not scanOpt then
        return { success = false, error = "Unknown scan_option '" .. tostring(scan_option) .. "'. Valid: " .. SCAN_OPTION_NAMES, error_code = "INVALID_PARAMS" }
    end
    if scanOpt ~= soExactValue and scanOpt ~= soUnknownValue and scanOpt ~= soValueBetween
       and scanOpt ~= soBiggerThan and scanOpt ~= soSmallerThan then
        return { success = false, error = "scan_option '" .. tostring(scan_option) .. "' is only valid for next_scan. First scan supports: exact, unknown, between, bigger, smaller", error_code = "INVALID_PARAMS" }
    end

    local input1, input2, inputErr = resolveScanInputs(scanOpt, value, params.value2)
    if inputErr then
        return { success = false, error = inputErr, error_code = "INVALID_PARAMS" }
    end

    local fsOk, fsMsg = pcall(function()
        ms.firstScan(scanOpt, varType, rtRounded, input1, input2,
                     0, 0x7FFFFFFFFFFFFFFF, "+W-C", fsmNotAligned, "1",
                     false, false, false, false)
        ms.waitTillDone()
    end)
    if not fsOk then
        return { success = false, error = "firstScan failed: " .. tostring(fsMsg), error_code = "INTERNAL_ERROR" }
    end

    if entry.fl then pcall(function() entry.fl.destroy() end) end
    local fl
    local flOk, flMsg = pcall(function()
        fl = createFoundList(ms)
        fl.initialize()
    end)
    if not flOk then
        return { success = false, error = "createFoundList failed: " .. tostring(flMsg), error_code = "INTERNAL_ERROR" }
    end

    entry.fl            = fl
    entry.has_scan      = true
    entry.unknown_first = (scanOpt == soUnknownValue)

    local count = fl.getCount()
    -- unknown-initial-value scans report 0 via the foundlist; see resolveScanResultCount()
    if scanOpt == soUnknownValue then
        count = resolveScanResultCount(ms, count)
    end

    return { success = true, scan_name = name, count = count }
end

function cmd_persistent_scan_next_scan(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local name        = params.name
    local value       = params.value
    local scan_option = params.scan_option or "exact"

    if not name then return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" } end

    local entry = serverState.persistent_scans[name]
    if not entry then
        return { success = false, error = "Scan '" .. name .. "' not found.", error_code = "INVALID_PARAMS" }
    end
    if not entry.has_scan then
        return { success = false, error = "No first scan done for '" .. name .. "'. Call persistent_scan_first_scan first.", error_code = "INVALID_PARAMS" }
    end

    local ms      = entry.ms
    local scanOpt = resolveScanOption(scan_option)
    if not scanOpt then
        return { success = false, error = "Unknown scan_option '" .. tostring(scan_option) .. "'. Valid: " .. SCAN_OPTION_NAMES, error_code = "INVALID_PARAMS" }
    end
    if scanOpt == soUnknownValue then
        return { success = false, error = "scan_option 'unknown' is only valid for first_scan", error_code = "INVALID_PARAMS" }
    end

    local input1, input2, inputErr = resolveScanInputs(scanOpt, value, params.value2)
    if inputErr then
        return { success = false, error = inputErr, error_code = "INVALID_PARAMS" }
    end

    local nsOk, nsMsg = pcall(function()
        ms.nextScan(scanOpt, rtRounded, input1, input2, false, false, false, false, false)
        ms.waitTillDone()
    end)
    if not nsOk then
        return { success = false, error = "nextScan failed: " .. tostring(nsMsg), error_code = "INTERNAL_ERROR" }
    end

    if entry.fl then pcall(function() entry.fl.destroy() end) end
    local fl
    local flOk, flMsg = pcall(function()
        fl = createFoundList(ms)
        fl.initialize()
    end)
    if not flOk then
        return { success = false, error = "createFoundList failed: " .. tostring(flMsg), error_code = "INTERNAL_ERROR" }
    end

    entry.fl = fl
    entry.unknown_first = false

    return { success = true, scan_name = name, count = fl.getCount() }
end

function cmd_persistent_scan_get_results(params)
    local name   = params.name
    local offset = params.offset or 0
    local limit  = params.limit  or 100

    if not name then return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" } end

    local entry = serverState.persistent_scans[name]
    if not entry then
        return { success = false, error = "Scan '" .. name .. "' not found.", error_code = "INVALID_PARAMS" }
    end
    if not entry.fl then
        return { success = false, error = "No results for '" .. name .. "'. Run first_scan first.", error_code = "INVALID_PARAMS" }
    end

    local fl      = entry.fl
    local total   = fl.getCount()
    local results = {}

    -- NOTE: unknown-initial-value scans are not individually enumerable via the
    -- foundlist (see resolveScanResultCount()); report the scanned-address total
    -- and signal it so an empty result list isn't mistaken for a scan failure.
    if entry.unknown_first then
        total = resolveScanResultCount(entry.ms, total)
        return {
            success              = true,
            scan_name            = name,
            total                = total,
            offset               = offset,
            limit                = limit,
            returned             = 0,
            results              = results,
            enumerable           = false,
            unknown_initial_value = true,
            note = UNKNOWN_SCAN_NOTE
        }
    end

    local stop = math.min(offset + limit - 1, total - 1)
    for i = offset, stop do
        local addrStr = fl.getAddress(i)
        if addrStr and not addrStr:match("^0[xX]") then
            addrStr = "0x" .. addrStr
        end
        table.insert(results, {
            address = addrStr,
            value   = fl.getValue(i)
        })
    end

    return {
        success   = true,
        scan_name = name,
        total     = total,
        offset    = offset,
        limit     = limit,
        results   = results
    }
end

function cmd_persistent_scan_destroy(params)
    local name = params.name
    if not name then return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" } end

    local entry = serverState.persistent_scans[name]
    if not entry then
        return { success = false, error = "Scan '" .. name .. "' not found.", error_code = "INVALID_PARAMS" }
    end

    if entry.fl then pcall(function() entry.fl.destroy() end) end
    pcall(function() entry.ms.destroy() end)
    serverState.persistent_scans[name] = nil

    return { success = true, scan_name = name, destroyed = true }
end

-- >>> END UNIT-15 <<<

-- >>> exports
B.resolveVarType = resolveVarType
