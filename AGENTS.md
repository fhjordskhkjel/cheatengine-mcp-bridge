# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What this project is

A three-tier bridge that lets AI agents (via MCP) drive Cheat Engine to inspect and manipulate a running Windows process. See `README.md` for user-facing docs. Current wire/app version: `12.2.0` (see `CHANGELOG.md`). The bridge exposes **214 MCP tools** covering memory, process lifecycle, code injection, symbol management, assembly/compilation, GUI automation, input, cheat tables, and kernel-mode operations.

## Commands

```bash
# Install Python deps (Windows only — uses pywin32)
pip install -r MCP_Server/requirements.txt

# Offline test suite (no CE needed; runs in CI on Linux + Windows)
pip install -r MCP_Server/requirements-dev.txt
python -m pytest

# The behaviour suites on their own (they load the real bridge modules into Lua 5.3; see MCP_Server/tests/behaviour/README.md)
python MCP_Server/tests/behaviour/run_all.py        # add --real (real-DLL oracles) and/or --mutation (do the tests catch breakages?)

# Live smoke test of the newer features (requires CE running with the bridge loaded; spawns and attaches its own throwaway target)
python MCP_Server/tests/behaviour/live_smoke.py

# Integration test suite (requires: CE running, ce_mcp_bridge.lua loaded, a process attached)
python MCP_Server/test_mcp.py
```

Loading the Lua side in Cheat Engine: `File -> Execute Script -> open MCP_Server/ce_mcp_bridge.lua -> Execute`. Some CE builds expose this through `Table -> Show Cheat Table Lua Script`; in that case execute `dofile([[C:\path\to\cheatengine-mcp-bridge\MCP_Server\ce_mcp_bridge.lua]])` instead of pasting the full bridge. Success log: `[MCP v12.2.0] MCP Server Listening on: CE_MCP_Bridge_v99`. Copy the whole `MCP_Server` folder: the loader needs `bridge/` next to it. If CE runs the script as text without its file name, set `CE_MCP_BRIDGE_DIR = [[C:\path\to\MCP_Server]]` first. Re-executing the script stops the running instance first (worker thread, breakpoints, watches, mappings), so reloading is safe.

There is **no build step and no linter**. The offline suite in `MCP_Server/tests/` needs no CE: it loads the whole bridge into Lua 5.3 via `lupa` with stubbed CE APIs (`tests/ce_stub.lua`) to exercise handlers and pipe framing, drives the Python client and TCP relay against fake bridges, runs the MCP server over real stdio, and checks Python/Lua drift (command names, pipe name, frame limit, duplicate locals, this file vs `AGENTS.md`). The standalone Lua tests (`test_json_codec.lua`, `test_pointer_parse.lua`) also run under plain `lua5.3`/`lua5.4`. `.github/workflows/offline-tests.yml` runs all of it, plus real named-pipe tests on Windows. `test_mcp.py` is the separate end-to-end script that talks to the live Named Pipe; running a "single test" means editing the `all_tests` dict in `test_mcp.py:main` or commenting out sections.

The MCP server is normally spawned by the AI client over stdio, but can be launched directly with `python MCP_Server/mcp_cheatengine.py` for debugging (it blocks waiting for stdio JSON-RPC).

## Architecture

Three processes, two IPC layers:

```
AI client ──(MCP / JSON-RPC over stdio)──▶ mcp_cheatengine.py
                                                  │
                                                  ▼ (length-prefixed JSON-RPC)
                                         \\.\pipe\CE_MCP_Bridge_v99
                                                  │
                                                  ▼
                                          ce_mcp_bridge.lua (inside Cheat Engine)
                                                  │
                                                  ▼ (CE Lua API / DBVM)
                                            Target process memory
```

### Python side — `MCP_Server/mcp_cheatengine.py`

Thin `FastMCP` wrapper. Every tool is a one-liner registered with `@tool("<toolset>")` that calls `ce_client.send_command("<method>", {...})` and formats the result. `CEBridgeClient.send_command` writes a 4-byte little-endian length prefix + UTF-8 JSON-RPC body to the Named Pipe, reads the same framing back, caps frames at 32 MB (same limit in the Lua bridge and `ce_tcp_relay.py`), and reconnects automatically. **Retry rule:** a request is resent only if it provably never reached CE (connect failure, stale connection, failed write). Once it is on the wire, a lost connection or a `CE_MCP_TIMEOUT` is reported and *not* retried, because commands like `auto_assemble`, `allocate_memory` and `write_memory` are not idempotent. After a timeout the command keeps running in CE and the single-instance pipe stays busy until it finishes; the client waits up to 5 s for a busy pipe and then reports it as busy. JSON-RPC errors come back as `{success: false, error, error_code, jsonrpc_code}`.

**Security model:** each tool also declares an access class (`read`, `analysis`, `write`, `exec`). It sets the MCP annotations (`readOnlyHint` / `destructiveHint` / `openWorldHint`) and `CE_MCP_PROFILE` (`readonly`, `standard`, default `full`) registers only the allowed classes. `CE_MCP_AUDIT_LOG=<path>` makes `CEBridgeClient.send_command` append a JSON line per command (method, bounded params, outcome, error code, duration). Shell tools need `CE_MCP_ALLOW_SHELL=1` on both sides: the Python gate and `SHELL_ALLOWED` in the bridge, captured at load from CE's environment or a `CE_MCP_ALLOW_SHELL = true` global.

**Batch gate:** `batch_commands` is a `write` tool that runs several wire methods inside one main-thread slot, i.e. past the per-tool registration. `_batch_gate` therefore judges every request as the tool it stands for (dispatcher aliases map to their tool) and refuses the whole batch with `PERMISSION_DENIED` when a method is not a tool of this server or its toolset/access class is not registered. Keep it in step when you add a tool alias to the dispatcher.

**Tool list post-processing (end of the file):** tools are registered with `structured_output=False` (they all return one JSON string; the SDK would otherwise declare an outputSchema and send every result twice), pydantic's generated `title` keys are dropped from the input schemas and descriptions are dedented. `tests/test_ported_tools.py` checks all three; keep new tools returning one JSON string.

**Toolsets and threading:** `@tool("<toolset>", "<access>")` puts each tool in one of the groups in `TOOLSETS` (process, memory, scan, analysis, debug, kernel, scripting, table, gui, system). `CE_MCP_TOOLSETS` selects which groups get registered (default all; `process` is always on), and the `list_toolsets` tool reports what is disabled. Tools run in worker threads via `anyio.to_thread` so a slow scan does not stall the MCP event loop (pings, cancellations); `CEBridgeClient` serialises the actual pipe traffic with a lock.

**Windows stdio pitfalls (top of file, before any other imports)** — do not move this block:
- The MCP SDK's `stdio_server` wraps stdio with `TextIOWrapper` without `newline='\n'`, so on Windows it emits `\r\n` and the transport rejects with "invalid trailing data." The file monkey-patches `mcp.server.stdio.stdio_server` **and** `mcp.server.fastmcp.server.stdio_server` (FastMCP captures a reference at import time, so patching only the first module is a silent no-op).
- `sys.stdout` is redirected to `sys.stderr` around third-party imports so stray prints can't corrupt the JSON-RPC stream. Anything diagnostic must go through `debug_log()` (stderr only). A single stray `print()` on stdout will break the protocol.

### Lua side — `MCP_Server/ce_mcp_bridge.lua` + `MCP_Server/bridge/`

`ce_mcp_bridge.lua` is a small loader; the bridge itself is 32 modules in `MCP_Server/bridge/NN_<area>.lua` (core, JSON codec, one module per tool area, dispatcher last). The loader finds the folder (from its own file name, or `CE_MCP_BRIDGE_DIR`), calls the running instance's `StopMCPBridge` if there is one, loads the modules in the order of its `MODULES` list, and calls `StartMCPBridge()`.

**Module contract.** Each module is its own chunk called with the shared namespace table `B` (`local B = ...`). Top-level helpers are module locals: a module imports the ones it uses from earlier modules (`local toHex = B.toHex`, keeping the name) and exports every top-level local it defines at the end (`B.foo = foo`). Command handlers (`cmd_*`), `StartMCPBridge`/`StopMCPBridge` and the scan helpers stay globals. CE's 200-local limit therefore applies per module. Don't rebind an imported name (`toHex = ...`): other modules keep their own copy. Mutate shared tables in place instead (as `serverState` and `mappedMemoryMDL` are). `tests/test_bridge_modules.py` enforces the contract: a missing import compiles fine but silently becomes a nil global at runtime.

Key pieces:

- **Worker-thread pipe I/O** (`PipeWorker`): a dedicated thread owns the blocking `pipe.acceptConnection()` / `pipe.readBytes()` calls so the CE GUI never freezes. Every request is handed to the main thread via `thread.synchronize(function() response = executeCommand(payload) end)`. **All CE Lua API calls must run on the main thread** — your `cmd_*` handler is already on it when invoked, so just don't spawn new threads that touch CE APIs directly.
- **Command dispatcher** (`commandHandlers`): a plain table mapping JSON-RPC method name → `cmd_*` function. Several methods have aliases (`read_memory`/`read_bytes`, `find_what_writes_safe` → `cmd_start_dbvm_watch`, etc.).
- **Zombie cleanup** (`cleanupZombieState`, in `00_core.lua`): `StopMCPBridge` tears down the worker thread, pipe, hardware breakpoints, DBVM watches, scan objects and kernel memory mappings tracked in `serverState` / `mappedMemoryMDL`. On reload the loader calls the *previous* instance's `StopMCPBridge` before loading anything, because only that function still holds the old state. This is load-bearing: reloading the script while a HW breakpoint is live otherwise leaves orphaned DR slots and can freeze the target. Any new long-lived resource you add should get a cleanup entry here.
- **Operations unit (UNIT-25, `25_operations.lua`)**: `bridge_status` (health/diagnostics), `read_struct` (many typed fields from one read), `batch` (several commands in one main-thread slot; dispatches through `serverState.dispatch`, which `31_dispatcher.lua` sets right after the `commandHandlers` table) and the **async job system**. Jobs (`start_job`/`get_job`/`get_job_result`/`cancel_job`/`list_jobs`) run `scan_all`, `next_scan`, `aob_scan`, `find_references` and `find_call_references` without blocking CE: scans use CE's own async `MemScan` (no `waitTillDone`; `OnScanDone` only raises a flag and the pump timer / `get_job` does the work, because destroying a memscan from inside its own event handler is unsafe; `getProgress()` polling is the fallback) and the Lua-side post-processing of reference searches is time-sliced from a `createTimer` pump. `scan_all`/`next_scan` jobs own the shared scan session, so the blocking `scan_all`/`next_scan`/`get_scan_results` answer `BUSY` while one runs. New long-lived job resources get a cleanup entry through `cleanupHooks.jobs` (00_core).
- **Analysis unit (UNIT-26, `26_analysis.lua`)**: everything hangs off a single `U26` table (exported on `B`, later modules import it). PE parsing reads headers straight from target memory (`U26.parsePE`): `pe_info`/`pe_imports`/`pe_exports`/`pe_tls_callbacks`, address translation (`va_to_rva`, `rva_to_va`, `rebase_address`) and name exchange with IDA (`export_names`, `export_structures`, `import_names`). The scanning jobs `rtti_scan`, `find_string_refs`, `find_code_caves` run on a shared time-sliced chunk engine (`U26.startStages`; a stage = ranges + `process(job, data, dataBase)` + optional `carry` bytes for patterns that span chunk borders), and `find_pointer_path` runs value-between memscans level by level; holders whose windows lie within `U26.PP_MERGE_GAP` share one scan (`U26.ppClusters`), each result is matched back to every holder whose window contains it, and a heap holder that serves several targets keeps its cheapest chain. Snapshots (`snapshot_region`/`diff_snapshots`) keep raw region copies in `serverState.snapshots` (128 MB / 16 snapshots budget). Register new job kinds in `JOB_STARTERS` and append them to `JOB_KIND_NAMES`.
- **Function boundaries (UNIT-27, `27_functions_structs.lua`)**: on x64 `U26.functionAt` resolves the function containing an address from the exception table (`.pdata`, binary-searched in a cached copy of the RUNTIME_FUNCTION array; UNWIND_INFO gives prolog size, frame register, handler and chained parents, so split/cold fragments resolve to their primary function). `find_function_boundaries`, `analyze_function` and `find_string_refs` use it through the global `pdataFunctionBoundaries` / `U26.functionAt` and fall back to the prologue heuristic where there is no entry (leaf functions, x86). Note that those two handlers (`05_disassembly.lua`) are defined before `U26` exists, hence the global hook.
- **Struct recovery (UNIT-27)**: `U26.rttiAtVtable` reads the complete object locator in the slot before any vtable (class, bases via `U26.readBases`, `this_offset`), and `recover_struct` walks one or more instances of the same class: pointer-sized slots are classified by what they point at (another RTTI object, text, a vtable, static data), then inline text, doubles, floats, ints, with zero runs merged and the all-zero tail trimmed. The heuristics (`U26.plausibleFloat`/`plausibleDouble`/`looksLikePointer`) are deliberately conservative; extend them together with a case in `tests/test_lua_analysis.py` and a mutant in `tests/mutation_check.py`.
- **Breakpoint control (UNIT-27, `06_breakpoints.lua`)**: everything breakpoint-related that is not trivial lives in the `BPX` table. Hits are recorded through `recordBreakpointHit` (00_core), whose `max_hits` is the size of the hit ring buffer; `stop_after_hits` is the separate "detach after N matching hits". `BPX.install` is shared by `set_breakpoint`/`set_data_breakpoint`; `BPX.handle` is the single place a hit is judged (condition, record, `max_hits`, halt). Conditions are `load`ed with a restricted environment and run under a `debug.sethook` instruction budget. `mode="break"` returns a NON-ZERO number (1) from the CE callback without continuing, which is what leaves the thread stopped (measured live: `nil`/`false`/`true`/`0` make CE resume it; `debug_isBroken()` returns a function in CE 7.6, never trust it), recorded in `serverState.halted`; the watchdog (`BPX.watchdog`, driven by the job pump timer) resumes it after `halt_timeout_ms`, and the `cleanupHooks.early` hook (run first by `cleanupZombieState`), `remove_breakpoint`, `clear_all_breakpoints` and `debug_continue` keep that record honest. Never let any code path leave a thread stopped without `serverState.halted` pointing at it.
- **Cross-references (UNIT-28, `28_xrefs.lua`)**: `find_xrefs` is a job on the chunk engine: `U26.xrefModuleStages` builds the scan stages per module and `U26.xrefItem` validates each raw hit in a second, time-sliced phase (`U26.xrefResolveStep`). Raw hits come from byte patterns: `E8`/`E9`/`0F 8x` rel32, short jumps (only the +-128 bytes around the target are examined), modrm bytes with mod=00 rm=101 followed by a displacement (x64 rip-relative; the immediate size is unknown, so four candidate end addresses are tried), exact pointer needles in code and data, and 32-bit RVAs in non-`.pdata` data. The disassembler then decides: `U26.insnStart` decodes **forward** from the enclosing `.pdata` function start (else 96 bytes back) and accepts a rip candidate only if the instruction covering the displacement ends exactly where the candidate says; short jumps must additionally sit on an instruction boundary (`U26.atBoundary`). Do not "widen" backwards over prefix-looking bytes: the 0x40 ending `mov rax,[rax+40h]` looks like a REX prefix to `call [rip+x]` (this misattributed 30% of the hits in `msvcp140.dll`). Build Lua pattern classes with `U26.byteClass`, never by hand: a literal `%` (0x25) or `-` (0x2D) inside a class changes its meaning (the old `find_string_refs` class silently lost modrm 0x25, i.e. `lea r12,[rip+x]`). Validate changes with `python tests/test_lua_xrefs.py --real` (capstone is the independent oracle; `pip install capstone`).
- **Pointer path sets (UNIT-30, `29_pointer_sets.lua`)**: the two-run comparison. `serverState.path_sets` holds named lists of chains `{module, rva | abs, offsets, runs}` (`U26.ps*` helpers). `find_pointer_path(save_as=)` fills one in run 1 (its name is validated before the scans start); `cmd_compare_pointer_paths` re-resolves a set (or inline `chains`) against the address of the same value in the process as it is NOW and returns the chains that land exactly on it with `runs + 1`. Chains are stored module-relative (an absolute base inside a module is converted, module names are compared case-insensitively) because that is what survives ASLR; `module_missing` / `unreadable` / `missed` are counted apart, a miss within `near_delta` bytes is a `near_miss` with `suggested_offsets` (last offset corrected), and `same_process` flags a comparison against the pid of the previous run. Nothing is stored unless `save_as` is given, saving the same name narrows in place, and an empty result never overwrites a set (`U26.psPut` refuses empty sets). Bounds: 16 sets, 5000 chains, 20 history entries, 16 offsets per chain. Run 1's pointers must be re-found by the caller in run 2 (scan, `find_pointer_path`, CE's own pointer scanner): the comparison tests chains, it does not search. Every change is written to `ce_mcp_pointer_sets.json` (`U26.psSave`, via a `.tmp` copy) and `U26.psLoad` reads it back when the script runs, so sets survive reloads and CE restarts; the folder comes from `U26.stDir` (global/env `CE_MCP_STATE_DIR`, `off` disables, else the loader's folder `B.BRIDGE_DIR`, `%LOCALAPPDATA%`, temp). A failed save never fails a command; it shows up as `save_error`.
- **Patch journal (UNIT-31, `30_patch_journal.lua`)**: `U26.pjWrap(commandHandlers)` (called by `31_dispatcher.lua` right after the dispatcher table) wraps `write_memory`, `write_integer`, `write_string`, `copy_memory` and `auto_assemble` in `U26.pjRun`, so writes sent through `batch` are journaled too. `U26.pjRanges` says which bytes a call is about to overwrite; they are read BEFORE the handler runs and recorded only if it succeeds (`patch_id` in the reply). `cmd_auto_assemble` hands CE's disable info over in `serverState.aa_last` (it is not JSON-safe, so never part of a reply); undoing a script runs its `[DISABLE]` section with it. `undo_patch` refuses when the current bytes differ from what the patch wrote (`conflict`, unless `force`), when the patch belongs to another pid, or when it is already undone, and verifies the restore; `all=true` goes newest first so stacked patches unwind. Entries that cannot be undone are still listed with a `reason` (original unreadable, over 64 KB, script without `[DISABLE]`). Bounds: 500 entries / 16 MB, oldest dropped first. The journal is appended to `ce_mcp_patch_journal.jsonl` (one `add`/`undo` line per change, compacted on load and when it grows past 2 x 500 + 100 lines) and replayed by `U26.pjLoad`; entries carry the process name as well as the pid (`U26.pjSame`), because a pid can be reused after a restart. Script entries come back as not undoable (CE's disable info cannot be saved). `drop_patches` forgets inactive or all entries. If you add a tool that writes target memory, add it to `U26.PJ_METHODS` / `U26.pjRanges` or document why it is not journaled.
- **Universal 32/64-bit handling** (`getArchInfo`, `captureRegisters`, `captureStack`): always branch on `targetIs64Bit()` and use `readPointer()` instead of `readInteger()`/`readQword()` when you mean "pointer-sized." Hardcoding register names or pointer size will silently break on the other architecture.

### Adding a new MCP tool

Two files are the source of truth — there's no codegen, so you must edit both:

1. In the matching `MCP_Server/bridge/NN_<area>.lua` module: write `function cmd_foo(params) ... return { success = true, ... } end` (a global, as all handlers are) and register it in the `commandHandlers` table in `25_dispatcher.lua` inside the appropriate unit sub-block (see **Conventions -> Section markers** below). Import any shared helper you use at the top of the module (`local toHex = B.toHex`). A new area can get its own module: add the file and its name to `MODULES` in the loader, before the dispatcher. The handler name must match the snake_case verb-first convention (`cmd_<name>`).
2. In `mcp_cheatengine.py`: add `@tool("<toolset>", "<access>") def foo(...): return format_result(ce_client.send_command("foo", {...}))`, picking the toolset from `TOOLSETS` and the access class from `ACCESS_CLASSES` (never a bare `@mcp.tool()`; a drift test rejects it). Classify honestly: `read` changes nothing, `analysis` changes only CE's own analysis state, `write` touches the target or the host, `exec` runs arbitrary code. The class decides the MCP annotations and whether `CE_MCP_PROFILE` registers the tool. The function must stay synchronous; the decorator moves it off the event loop.
3. Follow the **Conventions** section below for return shape, address encoding, and naming.
4. Reload the Lua script in CE. The Python server picks up changes automatically via pipe reconnect.

## Environment & safety constraints

- **Windows only.** Named Pipe access via `pywin32`; no plans for cross-platform.
- **Cheat Engine prerequisite**: CE → Settings → Extra → **disable "Query memory region routines"**. With it enabled, memory scans on DBVM-protected pages trigger `CLOCK_WATCHDOG_TIMEOUT` BSODs. This is documented as a hard requirement in both `README.md` and `AI_Context/AI_Guide_MCP_Server_Implementation.md`; don't weaken the assumption without testing.
- **Pipe name** `\\.\pipe\CE_MCP_Bridge_v99` is hardcoded in both `mcp_cheatengine.py` (as `PIPE_NAME`) and `bridge/00_core.lua` (as `PIPE_NAME`). Keep them in sync if you ever rename it. The `_v99` suffix is the wire-protocol version and is independent of the bridge version (`12.2.0`).
- **Codex config:** use TOML, not JSON. Add `[mcp_servers.cheatengine]`, `command = "python"`, and `args = ['C:\path\to\MCP_Server\mcp_cheatengine.py']`. Use TOML single-quoted strings for Windows paths so backslashes are literal, then restart Codex and verify with the `ping` tool.
- **Anti-cheat safety** (per `AI_Context/AI_Guide_MCP_Server_Implementation.md`): prefer hardware DR0–DR3 breakpoints over software (`0xCC`) breakpoints, and prefer DBVM watches for truly invisible tracing. The existing `cmd_set_breakpoint` already uses `debug_setBreakpoint` (hardware); keep new debugging tools on that path.
- **Env vars:** `CE_MCP_TIMEOUT` (default 30s; `<=0` disables) limits per-tool latency, and timed-out commands are never retried; `CE_MCP_TOOLSETS` (comma-separated toolsets, default `all`) limits which tools are registered; `CE_MCP_PROFILE` (`readonly` / `standard` / `full`, default `full`) limits tools by access class; `CE_MCP_AUDIT_LOG=<path>` writes a JSON-lines audit log; `CE_MCP_STATE_DIR` (read by the Lua bridge; `off` disables) is the folder for the saved pointer sets and patch journal; `CE_MCP_ALLOW_SHELL=1` enables `run_command` / `shell_execute` (default: disabled) and must also be enabled on the CE side.

## Conventions (v12 overhaul)

### Return shape
- **Success:** `{ success: true, <fields> }`
- **Error:** `{ success: false, error: "<human msg>", error_code: "<UPPER_SNAKE>" }`
- **Error code enum:** `NO_PROCESS`, `INVALID_ADDRESS`, `INVALID_PARAMS`, `CE_API_UNAVAILABLE`, `DBVM_NOT_LOADED`, `DBK_NOT_LOADED`, `PERMISSION_DENIED`, `NOT_FOUND`, `OUT_OF_RESOURCES`, `BUSY`, `INTERNAL_ERROR`.

### Addresses
Output: always hex string via `toHex()` (e.g. `"0x140001000"`). Input: accept string or integer.

### Naming
Python tool name == Lua dispatcher key == `cmd_<name>` minus prefix. Snake_case, verb-first.

### Section markers for contributions
Each tool area lives in its own module, which keeps parallel contributions mergeable; inside a module, units keep their markers (e.g. `-- >>> BEGIN UNIT-NN <Title> <<<`). New dispatcher entries go inside the `commandHandlers` table in `25_dispatcher.lua`, in unit sub-blocks.

### Pagination
List-returning commands (scan results, memory regions, modules, threads, disassembly, references, BP hits) support `offset` / `limit` params with a standard `{ total, offset, limit, returned, <key>: [...] }` return shape.

Release notes live in `CHANGELOG.md` at the repo root; add an entry (and bump `VERSION` in the bridge) for any client-visible change. A drift test checks the version string everywhere it appears.

## Reference material in `AI_Context/`

- `MCP_Bridge_Command_Reference.md` — exhaustive per-command reference with request/response examples. Consult this when working on a specific tool instead of grepping the Lua file.
- `AI_Guide_MCP_Server_Implementation.md` — higher-level architecture and safety notes (v12.0.0).
- `CE_LUA_Documentation.md` — Cheat Engine 7.6 Lua API reference (~229 KB). Offline source of truth when a CE function's behavior is unclear.
- `Pointer_Tools_Design.md` / `Pointer_Tools_Implementation_Plan.md` — design and plan for the UNIT-24 pointer walk-back tools (`analyze_pointer_access`, `validate_pointer_chains`).
