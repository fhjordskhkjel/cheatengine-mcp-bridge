-- ============================================================================
-- Cheat Engine MCP Bridge :: 19_asm_symbols_context
-- Assembly & compilation (UNIT-13), symbols (UNIT-12), debug context + thread BPs (UNIT-11)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local serverState = B.serverState
local toHex = B.toHex
local captureRegisters = B.captureRegisters
local parseMaxHits = B.parseMaxHits
local handleBreakpointHit = B.handleBreakpointHit
local requireProcess = B.requireProcess

-- >>> BEGIN UNIT-13 Assembly & Compilation <<<
-- ============================================================================
-- ASSEMBLY & COMPILATION TOOLS (Unit 13)
-- ============================================================================

-- Helper: check process is attached (for tools that need a target process address)
-- >>> BEGIN UNIT-12 Symbol Management <<<
function cmd_register_symbol(params)
    local name = params.name
    local address = params.address
    local do_not_save = params.do_not_save
    if do_not_save == nil then do_not_save = false end
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "Parameter 'name' must be a non-empty string", error_code = "INVALID_PARAMS" }
    end
    if type(address) ~= "string" and type(address) ~= "number" then
        return { success = false, error = "Parameter 'address' must be a string or integer", error_code = "INVALID_PARAMS" }
    end
    local resolvedAddr = address
    if type(address) == "string" then
        resolvedAddr = getAddressSafe(address)
    end
    if not resolvedAddr or resolvedAddr == 0 then
        return { success = false, error = "Invalid address: " .. tostring(address), error_code = "INVALID_ADDRESS" }
    end
    local ok, err = pcall(registerSymbol, name, resolvedAddr, do_not_save)
    if not ok then
        return { success = false, error = "registerSymbol failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, name = name, address = toHex(resolvedAddr) }
end

function cmd_unregister_symbol(params)
    local name = params.name
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "Parameter 'name' must be a non-empty string", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(unregisterSymbol, name)
    if not ok then
        return { success = false, error = "unregisterSymbol failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_enum_registered_symbols(params)
    local ok, result = pcall(enumRegisteredSymbols)
    if not ok then
        return { success = false, error = "enumRegisteredSymbols failed: " .. tostring(result), error_code = "INTERNAL_ERROR" }
    end
    local symbols = {}
    if result and type(result) == "table" then
        for i = 1, #result do
            local sym = result[i]
            if sym then
                local addrVal = sym.address or 0
                local modName = sym.module or sym.modulename or ""
                table.insert(symbols, {
                    name    = sym.symbolname or sym.name or "",
                    address = toHex(addrVal),
                    module  = tostring(modName)
                })
            end
        end
    end
    return { success = true, count = #symbols, symbols = symbols }
end

function cmd_delete_all_registered_symbols(params)
    -- Count before deleting (CE returns no count from deleteAllRegisteredSymbols)
    local countOk, symResult = pcall(enumRegisteredSymbols)
    local deletedCount = 0
    if countOk and symResult and type(symResult) == "table" then
        deletedCount = #symResult
    end
    local ok, err = pcall(deleteAllRegisteredSymbols)
    if not ok then
        return { success = false, error = "deleteAllRegisteredSymbols failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, deleted_count = deletedCount }
end

function cmd_enable_windows_symbols(params)
    local ok, err = pcall(enableWindowsSymbols)
    if not ok then
        return { success = false, error = "enableWindowsSymbols failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_enable_kernel_symbols(params)
    local ok, err = pcall(enableKernelSymbols)
    if not ok then
        local errMsg = tostring(err)
        if errMsg:lower():find("dbk") or errMsg:lower():find("kernel") or errMsg:lower():find("driver") then
            return { success = false, error = "Kernel driver not loaded", error_code = "DBK_NOT_LOADED" }
        end
        return { success = false, error = "enableKernelSymbols failed: " .. errMsg, error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_get_symbol_info(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    local name = params.name
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "Parameter 'name' must be a non-empty string", error_code = "INVALID_PARAMS" }
    end
    local ok, info = pcall(getSymbolInfo, name)
    if not ok then
        return { success = false, error = "getSymbolInfo failed: " .. tostring(info), error_code = "INTERNAL_ERROR" }
    end
    if not info then
        return { success = false, error = "Symbol not found: " .. name, error_code = "NOT_FOUND" }
    end
    local addrVal = info.address or 0
    local modName = info.modulename or info.module or ""
    return {
        success = true,
        name    = info.searchkey or info.name or name,
        address = toHex(addrVal),
        module  = tostring(modName),
        size    = info.size or 0
    }
end

function cmd_get_module_size(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    local module_name = params.module_name
    if type(module_name) ~= "string" or module_name == "" then
        return { success = false, error = "Parameter 'module_name' must be a non-empty string", error_code = "INVALID_PARAMS" }
    end
    local ok, sz = pcall(getModuleSize, module_name)
    if not ok then
        return { success = false, error = "getModuleSize failed: " .. tostring(sz), error_code = "INTERNAL_ERROR" }
    end
    if not sz then
        return { success = false, error = "Module not found: " .. module_name, error_code = "NOT_FOUND" }
    end
    return { success = true, size = sz }
end

function cmd_load_new_symbols(params)
    local ok, err = pcall(loadNewSymbols)
    if not ok then
        return { success = false, error = "loadNewSymbols failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_reinitialize_symbol_handler(params)
    local ok, err = pcall(reinitializeSymbolhandler)
    if not ok then
        return { success = false, error = "reinitializeSymbolhandler failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end
-- >>> END UNIT-12 <<<
-- >>> BEGIN UNIT-11 Context + ThreadBPs <<<
-- ============================================================================
-- UNIT-11: DEBUG CONTEXT INSPECTION + PER-THREAD BREAKPOINTS
-- ============================================================================

local function u11_guard()
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return false, { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    return true, nil
end

function cmd_assemble_instruction(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local line = params.line
    local address = params.address
    local preference = params.preference or 0
    local skipRangeCheck = params.skip_range_check or false

    if not line or line == "" then
        return { success = false, error = "No instruction line provided", error_code = "INVALID_PARAMS" }
    end

    if type(address) == "string" then address = getAddressSafe(address) end
    if address == nil and params.address ~= nil then
        return { success = false, error = "Invalid address: " .. tostring(params.address), error_code = "INVALID_ADDRESS" }
    end

    -- assemble() accepts nil address; it skips relative-offset resolution in that case
    local asmOk, result = pcall(assemble, line, address, preference, skipRangeCheck)

    if not asmOk then
        return { success = false, error = "assemble() raised error: " .. tostring(result), error_code = "INTERNAL_ERROR" }
    end

    if not result then
        return { success = false, error = "assemble() returned nil (invalid instruction or address)", error_code = "INVALID_PARAMS" }
    end

    local bytes = {}
    for i = 1, #result do bytes[i] = result[i] end

    return { success = true, bytes = bytes, size = #bytes }
end

function cmd_auto_assemble_check(params)
    local script = params.script
    local enable = params.enable
    if enable == nil then enable = true end
    local targetSelf = params.target_self or false

    if not script or script == "" then
        return { success = false, error = "No script provided", error_code = "INVALID_PARAMS" }
    end

    local checkOk, valid, errMsg = pcall(autoAssembleCheck, script, enable, targetSelf)

    if not checkOk then
        return { success = false, valid = false, errors = { tostring(valid) }, error = "autoAssembleCheck raised: " .. tostring(valid), error_code = "INTERNAL_ERROR" }
    end

    if valid then
        return { success = true, valid = true, errors = {} }
    end

    local errors = {}
    if errMsg then table.insert(errors, tostring(errMsg)) end
    return { success = true, valid = false, errors = errors }
end

function cmd_compile_c_code(params)
    -- No NO_PROCESS guard: pure compilation without an address doesn't require a target process
    local source = params.source
    local address = params.address
    local targetSelf = params.target_self or false
    local kernelMode = params.kernelmode or false

    if not source or source == "" then
        return { success = false, error = "No source code provided", error_code = "INVALID_PARAMS" }
    end

    if type(compile) ~= "function" then
        return { success = false, error = "TCC compiler not available", error_code = "CE_API_UNAVAILABLE" }
    end

    if type(address) == "string" then address = getAddressSafe(address) end
    if address == nil and params.address ~= nil then
        return { success = false, error = "Invalid address: " .. tostring(params.address), error_code = "INVALID_ADDRESS" }
    end

    local compOk, symbols, errMsg = pcall(compile, source, address, targetSelf, kernelMode, false)

    if not compOk then
        return { success = false, symbols = {}, errors = { tostring(symbols) }, error = "compile raised: " .. tostring(symbols), error_code = "INTERNAL_ERROR" }
    end

    if not symbols then
        local errors = {}
        if errMsg then table.insert(errors, tostring(errMsg)) end
        return { success = false, symbols = {}, errors = errors, error = "Compilation failed" .. (errMsg and (": " .. tostring(errMsg)) or ""), error_code = "INVALID_PARAMS" }
    end

    local symResult = {}
    for name, addr in pairs(symbols) do
        symResult[tostring(name)] = toHex(addr)
    end

    return { success = true, symbols = symResult, errors = {} }
end

function cmd_compile_cs_code(params)
    local source = params.source
    local references = params.references or {}
    local coreAssembly = params.core_assembly

    if not source or source == "" then
        return { success = false, error = "No source code provided", error_code = "INVALID_PARAMS" }
    end

    if type(compileCS) ~= "function" then
        return { success = false, error = ".NET runtime or compileCS not available", error_code = "CE_API_UNAVAILABLE" }
    end

    -- compileCS(text, references, coreAssembly OPTIONAL) — pass coreAssembly only when provided
    local csOk, result = pcall(compileCS, source, references, coreAssembly)

    if not csOk then
        return { success = false, assembly_handle = nil, error = tostring(result), error_code = "INTERNAL_ERROR" }
    end

    if not result then
        return { success = false, assembly_handle = nil, error = "compileCS returned nil", error_code = "INTERNAL_ERROR" }
    end

    return { success = true, assembly_handle = tostring(result) }
end

function cmd_generate_api_hook_script(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local address = params.address
    local targetAddress = params.target_address
    local codeToExecute = params.code_to_execute or ""

    if not address then return { success = false, error = "No address provided", error_code = "INVALID_PARAMS" } end
    if not targetAddress then return { success = false, error = "No target_address provided", error_code = "INVALID_PARAMS" } end

    if type(address) == "string" then address = getAddressSafe(address) end
    if type(targetAddress) == "string" then targetAddress = getAddressSafe(targetAddress) end

    if not address then return { success = false, error = "Invalid address: " .. tostring(params.address), error_code = "INVALID_ADDRESS" } end
    if not targetAddress then return { success = false, error = "Invalid target_address: " .. tostring(params.target_address), error_code = "INVALID_ADDRESS" } end

    -- CE signature: generateAPIHookScript(address, addresstojumpto, addresstogetnewcalladdress OPT, ext OPT, targetself OPT)
    -- code_to_execute maps to ext (4th param); 3rd param (new-call-address) is unused here
    local ext = codeToExecute ~= "" and codeToExecute or nil
    local genOk, result = pcall(generateAPIHookScript, address, targetAddress, nil, ext)

    if not genOk then
        return { success = false, error = "generateAPIHookScript failed: " .. tostring(result), error_code = "INTERNAL_ERROR" }
    end

    if not result then
        return { success = false, error = "generateAPIHookScript returned nil", error_code = "INTERNAL_ERROR" }
    end

    return { success = true, script = tostring(result) }
end

function cmd_generate_code_injection_script(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local address = params.address
    if not address then return { success = false, error = "No address provided", error_code = "INVALID_PARAMS" } end

    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address: " .. tostring(params.address), error_code = "INVALID_ADDRESS" } end

    -- generateCodeInjectionScript(script: TStrings, address, farjmp) mutates TStrings in-place
    local sl = createStringlist()
    local genOk, genErr = pcall(generateCodeInjectionScript, sl, address)

    if not genOk then
        sl.destroy()
        return { success = false, error = "generateCodeInjectionScript failed: " .. tostring(genErr), error_code = "INTERNAL_ERROR" }
    end

    local script = sl.Text
    sl.destroy()

    if not script or script == "" then
        return { success = false, error = "generateCodeInjectionScript produced empty script", error_code = "INTERNAL_ERROR" }
    end

    return { success = true, script = script }
end

-- >>> END UNIT-13 <<<

-- All settable register names shared between get and set handlers
local U11_REG_NAMES = {
    "RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","RIP",
    "R8","R9","R10","R11","R12","R13","R14","R15",
    "EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP","EIP",
    "EFLAGS"
}

function cmd_debug_get_context(params)
    local extraRegs = params.extra_regs == true

    local ok, err = u11_guard()
    if not ok then return err end

    local callOk, callErr = pcall(debug_getContext, extraRegs)
    if not callOk then
        return { success = false, error = "debug_getContext failed: " .. tostring(callErr), error_code = "INTERNAL_ERROR" }
    end

    -- captureRegisters() reads the same CE globals that debug_getContext just populated
    local regs = captureRegisters()
    local arch  = regs.arch
    regs.arch   = nil  -- arch is returned at top level, not inside registers

    local result = { success = true, arch = arch, registers = regs }

    if extraRegs then
        local extra = {}
        local is64  = arch == "x64"
        -- XMM0-15 (0-7 on 32-bit): each pointer is a CE-local address of 16 raw bytes
        local maxXmm = is64 and 15 or 7
        for i = 0, maxXmm do
            local xmmOk, xmmPtr = pcall(debug_getXMMPointer, i)
            if xmmOk and xmmPtr then
                local rawBytes = readBytes(xmmPtr, 16, true)
                if rawBytes then
                    local parts = {}
                    for _, b in ipairs(rawBytes) do
                        parts[#parts + 1] = string.format("%02X", b)
                    end
                    extra["xmm" .. i] = table.concat(parts)
                end
            end
        end
        -- FP0-FP7 are globals populated by debug_getContext(true)
        local fpVars = { FP0, FP1, FP2, FP3, FP4, FP5, FP6, FP7 }
        for i, v in ipairs(fpVars) do
            if v ~= nil then extra["fp" .. (i - 1)] = tostring(v) end
        end
        result.extra = extra
    end

    return result
end

function cmd_debug_set_context(params)
    local registers = params.registers
    if type(registers) ~= "table" then
        return { success = false, error = "registers must be an object/dict", error_code = "INVALID_PARAMS" }
    end

    local ok, err = u11_guard()
    if not ok then return err end

    for _, name in ipairs(U11_REG_NAMES) do
        local val = registers[name]
        if val ~= nil then
            local numVal
            if type(val) == "string" then
                numVal = tonumber(val, 16) or tonumber(val)
            elseif type(val) == "number" then
                numVal = val
            end
            if numVal then _G[name] = numVal end
        end
    end

    local setOk, setErr = pcall(debug_setContext)
    if not setOk then
        return { success = false, error = "debug_setContext failed: " .. tostring(setErr), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

function cmd_debug_get_xmm_pointer(params)
    local xmmNr = params.xmm_nr or 0

    local ok, err = u11_guard()
    if not ok then return err end

    local ptrOk, ptr = pcall(debug_getXMMPointer, xmmNr)
    if not ptrOk then
        return { success = false, error = "debug_getXMMPointer failed: " .. tostring(ptr), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, xmm_nr = xmmNr, pointer = toHex(ptr) }
end

function cmd_debug_set_last_branch_recording(params)
    local enable = params.enable == true

    local ok, err = u11_guard()
    if not ok then return err end

    -- LBR only works under kernel-mode debugger (interface == 3)
    local iface = debug_getCurrentDebuggerInterface and debug_getCurrentDebuggerInterface() or nil
    if iface ~= 3 then
        return {
            success            = false,
            error              = "LBR requires kernel debugger",
            error_code         = "CE_API_UNAVAILABLE",
            debugger_interface = iface
        }
    end

    local lbrOk, lbrErr = pcall(debug_setLastBranchRecording, enable)
    if not lbrOk then
        return { success = false, error = "debug_setLastBranchRecording failed: " .. tostring(lbrErr), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, enabled = enable }
end

function cmd_debug_get_last_branch_record(params)
    local index = params.index or 0

    local ok, err = u11_guard()
    if not ok then return err end

    local recOk, record = pcall(debug_getLastBranchRecord, index)
    if not recOk then
        return { success = false, error = "debug_getLastBranchRecord failed: " .. tostring(record), error_code = "INTERNAL_ERROR" }
    end

    if type(record) ~= "table" then
        return { success = false, error = "Unexpected return from debug_getLastBranchRecord: " .. tostring(record), error_code = "INTERNAL_ERROR" }
    end

    return {
        success = true,
        index   = index,
        from    = record.from and toHex(record.from) or nil,
        to      = record.to   and toHex(record.to)   or nil,
    }
end

function cmd_debug_set_breakpoint_for_thread(params)
    local threadId = params.thread_id
    local addr     = params.address
    local size     = params.size    or 1
    local trigger  = params.trigger or "execute"
    local maxHits  = parseMaxHits(params.max_hits)

    if not threadId then return { success = false, error = "thread_id is required", error_code = "INVALID_PARAMS" } end

    local ok, err = u11_guard()
    if not ok then return err end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_PARAMS" } end

    local bpTrigger
    if trigger == "write" then
        bpTrigger = bptWrite
    elseif trigger == "read" or trigger == "access" then
        bpTrigger = bptAccess
    else
        bpTrigger = bptExecute
    end

    local bpHandle = "thread_" .. tostring(threadId) .. "_" .. toHex(addr)
    serverState.breakpoint_hits[bpHandle] = {}

    local setOk, setErr = pcall(debug_setBreakpointForThread, threadId, addr, size, bpTrigger, bpmDebugRegister, function()
        return handleBreakpointHit(bpHandle, addr, function()
            return {
                handle    = bpHandle,
                thread_id = threadId,
                address   = toHex(addr),
                timestamp = os.time(),
                registers = captureRegisters(),
            }
        end)
    end)

    if not setOk then
        serverState.breakpoint_hits[bpHandle] = nil
        return { success = false, error = "debug_setBreakpointForThread failed: " .. tostring(setErr), error_code = "INTERNAL_ERROR" }
    end

    serverState.breakpoints[bpHandle] = { address = addr, type = "thread_bp", thread_id = threadId, max_hits = maxHits }

    return {
        success   = true,
        bp_handle = bpHandle,
        thread_id = threadId,
        address   = toHex(addr),
        trigger   = trigger,
        size      = size,
        max_hits  = maxHits,
    }
end

function cmd_debug_remove_breakpoint_for_thread(params)
    local threadId = params.thread_id
    local addr     = params.address

    if not threadId then return { success = false, error = "thread_id is required", error_code = "INVALID_PARAMS" } end

    local ok, err = u11_guard()
    if not ok then return err end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_PARAMS" } end

    -- CE has no dedicated per-thread remove; debug_removeBreakpoint by address is the supported path
    local remOk, remErr = pcall(debug_removeBreakpoint, addr)
    if not remOk then
        return { success = false, error = "debug_removeBreakpoint failed: " .. tostring(remErr), error_code = "INTERNAL_ERROR" }
    end

    local bpHandle = "thread_" .. tostring(threadId) .. "_" .. toHex(addr)
    serverState.breakpoints[bpHandle]     = nil
    serverState.breakpoint_hits[bpHandle] = nil

    return { success = true, thread_id = threadId, address = toHex(addr) }
end

-- >>> END UNIT-11 <<<

-- >>> exports
B.u11_guard = u11_guard
B.U11_REG_NAMES = U11_REG_NAMES
