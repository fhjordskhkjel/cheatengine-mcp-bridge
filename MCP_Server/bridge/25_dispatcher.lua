-- ============================================================================
-- Cheat Engine MCP Bridge :: 25_dispatcher
-- Command dispatcher, JSON-RPC processing, pipe server, start/stop
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local PIPE_NAME = B.PIPE_NAME
local VERSION = B.VERSION
local serverState = B.serverState
local log = B.log
local cleanupZombieState = B.cleanupZombieState
local json = B.json
local SHELL_ALLOWED = B.SHELL_ALLOWED

-- ============================================================================
-- COMMAND DISPATCHER
-- ============================================================================

local commandHandlers = {
    -- Process & Modules
    get_process_info = cmd_get_process_info,
    enum_modules = cmd_enum_modules,
    get_symbol_address = cmd_get_symbol_address,

    -- >>> BEGIN UNIT-07 Process Lifecycle <<<
    open_process = cmd_open_process,
    get_process_list = cmd_get_process_list,
    get_processid_from_name = cmd_get_processid_from_name,
    get_foreground_process = cmd_get_foreground_process,
    create_process = cmd_create_process,
    get_opened_process_id = cmd_get_opened_process_id,
    get_opened_process_handle = cmd_get_opened_process_handle,
    -- >>> END UNIT-07 <<<
    
    -- >>> BEGIN UNIT-27 dispatcher entries <<<
    get_halted_state = cmd_get_halted_state,
    -- >>> END UNIT-27 <<<

    -- Memory Read
    read_memory = cmd_read_memory,
    read_bytes = cmd_read_memory,  -- Alias
    read_integer = cmd_read_integer,
    read_string = cmd_read_string,
    read_pointer = cmd_read_pointer,
    
    -- Pattern Scanning
    aob_scan = cmd_aob_scan,
    pattern_scan = cmd_aob_scan,  -- Alias
    scan_all = cmd_scan_all,
    next_scan = cmd_next_scan,
    write_integer = cmd_write_integer,
    write_memory = cmd_write_memory,
    write_string = cmd_write_string,
    get_scan_results = cmd_get_scan_results,
    search_string = cmd_search_string,
    
    -- Disassembly & Analysis
    disassemble = cmd_disassemble,
    get_instruction_info = cmd_get_instruction_info,
    find_function_boundaries = cmd_find_function_boundaries,
    analyze_function = cmd_analyze_function,
    
    -- Reference Finding
    find_references = cmd_find_references,
    find_call_references = cmd_find_call_references,
    
    -- Breakpoints
    set_breakpoint = cmd_set_breakpoint,
    set_execution_breakpoint = cmd_set_breakpoint,  -- Alias
    set_data_breakpoint = cmd_set_data_breakpoint,
    set_write_breakpoint = cmd_set_data_breakpoint,  -- Alias
    remove_breakpoint = cmd_remove_breakpoint,
    get_breakpoint_hits = cmd_get_breakpoint_hits,
    list_breakpoints = cmd_list_breakpoints,
    clear_all_breakpoints = cmd_clear_all_breakpoints,
    
    -- Memory Regions
    get_memory_regions = cmd_get_memory_regions,
    enum_memory_regions_full = cmd_enum_memory_regions_full,  -- More accurate, uses native API
    
    -- Lua Evaluation
    evaluate_lua = cmd_evaluate_lua,

    -- Threading & Synchronization (Unit-22)
    create_thread           = cmd_create_thread,
    get_global_variable     = cmd_get_global_variable,
    set_global_variable     = cmd_set_global_variable,
    queue_to_main_thread    = cmd_queue_to_main_thread,
    check_synchronize       = cmd_check_synchronize,
    in_main_thread          = cmd_in_main_thread,
    
    -- High-Level Analysis Tools
    dissect_structure = cmd_dissect_structure,
    get_thread_list = cmd_get_thread_list,
    auto_assemble = cmd_auto_assemble,
    read_pointer_chain = cmd_read_pointer_chain,
    analyze_pointer_access = cmd_analyze_pointer_access,
    validate_pointer_chains = cmd_validate_pointer_chains,
    get_rtti_classname = cmd_get_rtti_classname,
    get_address_info = cmd_get_address_info,
    checksum_memory = cmd_checksum_memory,
    generate_signature = cmd_generate_signature,
    
    -- DBVM Hypervisor Tools (Safe Dynamic Tracing - Ring -1)
    get_physical_address = cmd_get_physical_address,
    start_dbvm_watch = cmd_start_dbvm_watch,
    poll_dbvm_watch = cmd_poll_dbvm_watch,  -- Poll logs without stopping watch
    stop_dbvm_watch = cmd_stop_dbvm_watch,
    -- Semantic aliases for ease of use
    find_what_writes_safe = cmd_start_dbvm_watch,  -- Alias: start watching for writes
    find_what_accesses_safe = cmd_start_dbvm_watch,  -- Alias: start watching for accesses
    get_watch_results = cmd_stop_dbvm_watch,  -- Alias: retrieve results and stop
    
    -- Utility
    ping = cmd_ping,

    -- Debug Output & Multimedia (Unit 23)
    output_debug_string = cmd_output_debug_string,
    speak_text = cmd_speak_text,
    play_sound = cmd_play_sound,
    beep = cmd_beep,
    set_progress_state = cmd_set_progress_state,
    set_progress_value = cmd_set_progress_value,
    -- Unit-21: Kernel Mode / DBVM Extensions
    dbk_get_cr0 = cmd_dbk_get_cr0,
    dbk_get_cr3 = cmd_dbk_get_cr3,
    dbk_get_cr4 = cmd_dbk_get_cr4,
    read_process_memory_cr3 = cmd_read_process_memory_cr3,
    write_process_memory_cr3 = cmd_write_process_memory_cr3,
    map_memory = cmd_map_memory,
    unmap_memory = cmd_unmap_memory,
    dbk_writes_ignore_write_protection = cmd_dbk_writes_ignore_write_protection,
    get_physical_address_cr3 = cmd_get_physical_address_cr3,

    -- Shell Execution (UNIT-20b) - Security gate enforced on Python side
    run_command = cmd_run_command,
    shell_execute = cmd_shell_execute,
    file_exists = cmd_file_exists,
    delete_file = cmd_delete_file,
    get_file_list = cmd_get_file_list,
    get_directory_list = cmd_get_directory_list,
    get_temp_folder = cmd_get_temp_folder,
    get_file_version = cmd_get_file_version,
    read_clipboard = cmd_read_clipboard,
    write_clipboard = cmd_write_clipboard,

    -- >>> BEGIN UNIT-19 dispatcher entries <<<
    create_structure           = cmd_create_structure,
    get_structure_by_name      = cmd_get_structure_by_name,
    add_element_to_structure   = cmd_add_element_to_structure,
    get_structure_elements     = cmd_get_structure_elements,
    export_structure_to_xml    = cmd_export_structure_to_xml,
    delete_structure           = cmd_delete_structure,
    -- >>> END UNIT-19 <<<
    -- >>> BEGIN UNIT-18 dispatcher entries <<<
    load_table               = cmd_load_table,
    save_table               = cmd_save_table,
    get_address_list         = cmd_get_address_list,
    get_memory_record        = cmd_get_memory_record,
    create_memory_record     = cmd_create_memory_record,
    delete_memory_record     = cmd_delete_memory_record,
    get_memory_record_value  = cmd_get_memory_record_value,
    set_memory_record_value  = cmd_set_memory_record_value,
    -- >>> END UNIT-18 <<<
    -- Input Automation (Unit-17) — system-wide, no process guard required
    get_pixel = cmd_get_pixel,
    get_mouse_pos = cmd_get_mouse_pos,
    set_mouse_pos = cmd_set_mouse_pos,
    is_key_pressed = cmd_is_key_pressed,
    key_down = cmd_key_down,
    key_up = cmd_key_up,
    do_key_press = cmd_do_key_press,
    get_screen_info = cmd_get_screen_info,

    -- Window / GUI (Unit-16)
    find_window             = cmd_find_window,
    get_window_caption      = cmd_get_window_caption,
    get_window_class_name   = cmd_get_window_class_name,
    get_window_process_id   = cmd_get_window_process_id,
    send_window_message     = cmd_send_window_message,
    show_message            = cmd_show_message,
    input_query             = cmd_input_query,
    show_selection_list     = cmd_show_selection_list,
    -- Unit 15: Advanced Scanning
    aob_scan_unique           = cmd_aob_scan_unique,
    aob_scan_module           = cmd_aob_scan_module,
    aob_scan_module_unique    = cmd_aob_scan_module_unique,
    pointer_rescan            = cmd_pointer_rescan,
    create_persistent_scan    = cmd_create_persistent_scan,
    persistent_scan_first_scan    = cmd_persistent_scan_first_scan,
    persistent_scan_next_scan     = cmd_persistent_scan_next_scan,
    persistent_scan_get_results   = cmd_persistent_scan_get_results,
    persistent_scan_destroy       = cmd_persistent_scan_destroy,
    -- Memory Operations (Unit 14)
    copy_memory = cmd_copy_memory,
    compare_memory = cmd_compare_memory,
    write_region_to_file = cmd_write_region_to_file,
    read_region_from_file = cmd_read_region_from_file,
    md5_memory = cmd_md5_memory,
    md5_file = cmd_md5_file,
    create_section = cmd_create_section,
    map_view_of_section = cmd_map_view_of_section,
    -- Assembly & Compilation (Unit 13)
    assemble_instruction = cmd_assemble_instruction,
    auto_assemble_check = cmd_auto_assemble_check,
    compile_c_code = cmd_compile_c_code,
    compile_cs_code = cmd_compile_cs_code,
    generate_api_hook_script = cmd_generate_api_hook_script,
    generate_code_injection_script = cmd_generate_code_injection_script,
    -- >>> BEGIN UNIT-12 dispatcher entries <<<
    register_symbol                = cmd_register_symbol,
    unregister_symbol              = cmd_unregister_symbol,
    enum_registered_symbols        = cmd_enum_registered_symbols,
    delete_all_registered_symbols  = cmd_delete_all_registered_symbols,
    enable_windows_symbols         = cmd_enable_windows_symbols,
    enable_kernel_symbols          = cmd_enable_kernel_symbols,
    get_symbol_info                = cmd_get_symbol_info,
    get_module_size                = cmd_get_module_size,
    load_new_symbols               = cmd_load_new_symbols,
    reinitialize_symbol_handler    = cmd_reinitialize_symbol_handler,
    -- >>> END UNIT-12 <<<
    -- Unit-11: Debug Context + Per-Thread Breakpoints
    debug_get_context                  = cmd_debug_get_context,
    debug_set_context                  = cmd_debug_set_context,
    debug_get_xmm_pointer              = cmd_debug_get_xmm_pointer,
    debug_set_last_branch_recording    = cmd_debug_set_last_branch_recording,
    debug_get_last_branch_record       = cmd_debug_get_last_branch_record,
    debug_set_breakpoint_for_thread    = cmd_debug_set_breakpoint_for_thread,
    debug_remove_breakpoint_for_thread = cmd_debug_remove_breakpoint_for_thread,
    -- Debugger Control (Unit 10)
    debug_process                      = cmd_debug_process,
    debug_is_debugging                 = cmd_debug_is_debugging,
    debug_get_current_debugger_interface = cmd_debug_get_current_debugger_interface,
    debug_break_thread                 = cmd_debug_break_thread,
    debug_continue                     = cmd_debug_continue,
    debug_detach                       = cmd_debug_detach,
    pause_process                      = cmd_pause_process,
    unpause_process                    = cmd_unpause_process,
    -- Code Injection & Execution (Unit-09)
    inject_dll            = cmd_inject_dll,
    inject_dotnet_dll     = cmd_inject_dotnet_dll,
    execute_code          = cmd_execute_code,
    execute_code_ex       = cmd_execute_code_ex,
    execute_method        = cmd_execute_method,
    execute_code_local    = cmd_execute_code_local,
    execute_code_local_ex = cmd_execute_code_local_ex,
    -- >>> BEGIN UNIT-08 dispatcher entries <<<
    allocate_memory        = cmd_allocate_memory,
    free_memory            = cmd_free_memory,
    allocate_shared_memory = cmd_allocate_shared_memory,
    get_memory_protection  = cmd_get_memory_protection,
    set_memory_protection  = cmd_set_memory_protection,
    full_access            = cmd_full_access,
    allocate_kernel_memory = cmd_allocate_kernel_memory,
    -- >>> END UNIT-08 <<<
}

-- ============================================================================
-- MAIN COMMAND PROCESSOR
-- ============================================================================

-- Frames larger than this are rejected in both directions (matches
-- MAX_RESPONSE_SIZE_BYTES in mcp_cheatengine.py and the TCP relay).
local MAX_FRAME_BYTES = 32 * 1024 * 1024

-- JSON-RPC error codes used by the bridge. -32001 is server-defined and
-- maps to error_code OUT_OF_RESOURCES on the Python side.
local function rpcError(code, message, id)
    return json.encode({ jsonrpc = "2.0", error = { code = code, message = message }, id = id })
end

local function executeCommand(jsonRequest)
    local ok, request = pcall(json.decode, jsonRequest)
    if not ok or type(request) ~= "table" then
        return rpcError(-32700, "Parse error: " .. (ok and "request is not a JSON object" or tostring(request)))
    end

    local method = request.method
    local params = request.params or {}
    local id = request.id

    local handler = commandHandlers[method]
    if not handler then
        return rpcError(-32601, "Method not found: " .. tostring(method), id)
    end

    local t0 = os.clock()
    local ok2, result = pcall(handler, params)
    local stats = serverState.stats
    stats.requests = stats.requests + 1
    stats.last_method = method
    stats.last_ms = math.floor((os.clock() - t0) * 1000)
    if stats.last_ms > (stats.slowest_ms or 0) then
        stats.slowest_ms, stats.slowest_method = stats.last_ms, method
    end
    if not ok2 then
        stats.errors = stats.errors + 1
        stats.last_error = tostring(result)
        return rpcError(-32603, "Internal error: " .. tostring(result), id)
    end

    local ok3, encoded = pcall(json.encode, { jsonrpc = "2.0", result = result, id = id })
    if not ok3 then
        return rpcError(-32603, "Internal error: could not encode result of " .. tostring(method) .. ": " .. tostring(encoded), id)
    end
    if #encoded >= MAX_FRAME_BYTES then
        return rpcError(-32001, string.format(
            "Response too large (%d bytes, max %d). Request less data (offset/limit/size/max_results).",
            #encoded, MAX_FRAME_BYTES - 1), id)
    end
    return encoded
end

-- ============================================================================
-- THREAD-BASED PIPE SERVER (NON-BLOCKING GUI)
-- ============================================================================
-- Replaces v10 Timer architecture to prevent GUI Freezes.
-- I/O happens in Worker Thread. Execution happens in Main Thread.

-- Write one length-prefixed frame (4-byte little-endian length + body).
-- Returns false if the pipe rejected the write (client gone).
local function writeFrame(pipe, payload)
    local n = #payload
    local header = { n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256 }
    if not pipe.writeBytes(header) then return false end
    if n > 0 and not pipe.writeString(payload) then return false end
    return true
end

-- Serve one request on a connected pipe (worker thread). Returns true to keep
-- the connection, false to drop it. Every request that is read gets exactly
-- one response frame unless the pipe itself is broken: the client must never
-- be left waiting for a reply that will not come.
local function serveOneRequest(thread, pipe)
    local lenBytes = pipe.readBytes(4)
    if not lenBytes or #lenBytes ~= 4 then return false end   -- disconnected or broken

    local len = lenBytes[1] + (lenBytes[2] * 256) + (lenBytes[3] * 65536) + (lenBytes[4] * 16777216)
    if len == 0 or len >= MAX_FRAME_BYTES then
        -- The body was not consumed, so the stream cannot be resynchronised:
        -- report the problem, then drop the connection.
        writeFrame(pipe, rpcError(-32600, string.format("Invalid request frame length %d (max %d)", len, MAX_FRAME_BYTES - 1)))
        return false
    end

    local payload = pipe.readString(len)
    if not payload or #payload ~= len then return false end    -- short read: stream is broken

    -- CRITICAL: execute on the main thread; all CE API calls must run there.
    local response
    thread.synchronize(function()
        response = executeCommand(payload)
    end)
    if not response then response = rpcError(-32603, "Internal error: no response produced") end

    return writeFrame(pipe, response)
end

local function PipeWorker(thread)
    log("Worker Thread Started - Waiting for connection...")
    
    while not thread.Terminated do
        -- Create Pipe Instance per connection attempt
        -- Increased buffer size to 256KB for better throughput
        local pipe = createPipe(PIPE_NAME, 262144, 262144)  -- 256 KB buffers (was 64 KB)
        if not pipe then
            log("Fatal: Failed to create pipe")
            return
        end
        
        -- Store reference so we can destroy it from main thread (stopServer) to break blocking calls
        serverState.workerPipe = pipe
        
        -- timeout for blocking operations (connect/read)
        -- We DO NOT set pipe.Timeout because it auto-disconnects on timeout.
        -- We rely on blocking reads and pipe.destroy() from stopServer to break the block.
        -- pipe.Timeout = 0 (Default, Infinite)
        
        -- Wait for client (Blocking, but in thread so GUI is fine)
        -- LuaPipeServer uses acceptConnection().
        -- note: acceptConnection might not return a boolean, so we check pipe.Connected afterwards.
        
        -- log("Thread: Calling acceptConnection()...")
        pcall(function()
            pipe.acceptConnection()
        end)
        
        if pipe.Connected and not thread.Terminated then
            log("Client Connected")
            serverState.connected = true
            
            while not thread.Terminated and pipe.Connected do
                -- pcall so an unexpected error drops this connection instead
                -- of killing the worker thread (which would leave the bridge
                -- dead until the script is reloaded).
                local ok, keep = pcall(serveOneRequest, thread, pipe)
                if not ok then
                    log("Request loop error (dropping connection): " .. tostring(keep))
                    break
                end
                if not keep then break end
            end
            
            serverState.connected = false
            log("Client Disconnected")
        else
            -- Debug: acceptConnection returned but pipe not valid
            -- This usually happens on termination or weird state
            if not thread.Terminated then
                -- log("Thread: Helper log - connection attempt invalid")
            end
        end
        
        -- Clean up pipe
        serverState.workerPipe = nil
        pcall(function() pipe.destroy() end)
        
        -- Brief sleep before recreating pipe to accept new connection
        if not thread.Terminated then sleep(50) end
    end
    
    log("Worker Thread Terminated")
end

-- ============================================================================
-- MAIN CONTROL
-- ============================================================================

function StopMCPBridge()
    if serverState.workerThread then
        log("Stopping Server (Terminating Thread)...")
        serverState.workerThread.terminate()
        
        -- Force destroy the pipe if it's currently blocking on acceptConnection or read
        if serverState.workerPipe then
            pcall(function() serverState.workerPipe.destroy() end)
            serverState.workerPipe = nil
        end
        
        serverState.workerThread = nil
        serverState.running = false
    end
    
    if serverState.timer then
        serverState.timer.destroy()
        serverState.timer = nil
    end
    
    -- CRITICAL: Cleanup all zombie resources (breakpoints, DBVM watches, scans)
    cleanupZombieState()
    
    log("Server Stopped")
end

function StartMCPBridge()
    StopMCPBridge()  -- This now also calls cleanupZombieState()
    
    -- Update Global State
    log("Starting MCP Bridge v" .. VERSION)
    
    serverState.running = true
    serverState.connected = false
    
    -- Create the Worker Thread
    serverState.workerThread = createThread(PipeWorker)
    
    log("===========================================")
    log("MCP Server Listening on: " .. PIPE_NAME)
    log("Architecture: Threaded I/O + Synchronized Execution")
    log("Cleanup: Zombie Prevention Active")
    log("Shell tools (run_command/shell_execute): " .. (SHELL_ALLOWED and "ENABLED via CE_MCP_ALLOW_SHELL" or "disabled"))
    log("===========================================")
end

-- >>> exports
B.commandHandlers = commandHandlers
B.MAX_FRAME_BYTES = MAX_FRAME_BYTES
B.rpcError = rpcError
B.executeCommand = executeCommand
B.writeFrame = writeFrame
B.serveOneRequest = serveOneRequest
B.PipeWorker = PipeWorker
