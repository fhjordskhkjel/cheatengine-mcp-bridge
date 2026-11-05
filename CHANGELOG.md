# Changelog

All notable changes to the Cheat Engine MCP Bridge. The wire protocol (`CE_MCP_Bridge_v99`) is unchanged; reload `ce_mcp_bridge.lua` and restart the MCP server to pick up a new version.

## Unreleased

### Changed

- **The MCP server runs on `mcp` 2.x as well as 1.x** (`mcp>=1.28,<3`). It picks `MCPServer` (2.x) or `FastMCP` (1.x) at import. The Windows CRLF patch now hands the SDK's own `stdio_server` text streams opened with `newline='\n'` instead of re-implementing its reader/writer loop, so it no longer depends on SDK-internal message types. CI runs the offline suite, including the real-stdio and named-pipe tests, under both majors.
- **Lint in CI:** `python -m ruff check .` (pyflakes plus the comparison/lambda/bare-except rules, `ruff.toml`). The findings it had were unused imports, placeholder-less f-strings, two dead variables, an `== False` and a lambda assignment; none changed behaviour, except that `test_mcp.py`'s category summary now also prints the failed count it was computing and dropping.

## 12.3.0 — 2026-11-05

### Added

- **`CE_MCP_TOOLSETS=core`**: a preset of the 63 tools a reverse-engineering session uses nearly every turn (reads/writes with the patch journal, scans, disassembly, the analysis jobs, hardware breakpoints, auto-assembler, Lua, plus the `process` group). Its schemas are ~40 k characters against ~114 k for `all`. Presets combine with groups (`core,kernel`); `list_toolsets` lists them.
- **`batch_commands` has a wall-time budget.** `time_budget_ms` (default: 80% of `CE_MCP_TIMEOUT`, 20 s when the timeout is disabled) is checked before each request, so a batch of slow requests returns its partial results with `stopped_early: "time_budget"` and `not_run` instead of outliving the client's timeout (which lost the whole reply and kept the pipe busy). Replies also carry `elapsed_ms`, and `stop_on_error` reports `stopped_early: "stop_on_error"`.
- The blocking `scan_all` / `next_scan` / `aob_scan` / `find_references` / `find_call_references` tool descriptions now name their `start_job` form, which keeps Cheat Engine responsive.

## 12.2.0 — 2026-11-05

Covers [#4](https://github.com/fhjordskhkjel/cheatengine-mcp-bridge/pull/4) (module split) and [#5](https://github.com/fhjordskhkjel/cheatengine-mcp-bridge/pull/5) (ported units).

### Added

Ported from [miscusi-peek/cheatengine-mcp-bridge#65](https://github.com/miscusi-peek/cheatengine-mcp-bridge/pull/65) and [#68](https://github.com/miscusi-peek/cheatengine-mcp-bridge/pull/68) onto the module layout: 38 tools (214 in total), 6 new bridge modules (`25_operations` .. `30_patch_journal`; the dispatcher is now `31_dispatcher`).

- **Async jobs and operations:** `start_job` / `get_job` / `get_job_result` / `wait_for_job` / `cancel_job` / `list_jobs` run scans and analyses in the background on Cheat Engine's own async memscan and a time-sliced pump, so CE stays responsive and no MCP call times out. Also `bridge_status`, `read_struct` (many typed fields from one read) and `batch_commands`. `scan_all` / `next_scan` / `get_scan_results` answer `BUSY` while a scan job owns the scan session.
- **Binary analysis:** `pe_info`, `pe_imports`, `pe_exports`, `pe_tls_callbacks`, `pe_functions` (x64 `.pdata`), `va_to_rva`, `rva_to_va`, `rebase_address`, IDA exchange (`export_names`, `export_structures`, `import_names`), `rtti_scan_module`, `recover_struct`, `find_string_refs`, `find_code_caves`, snapshots (`snapshot_region`, `diff_snapshots`, ...), `find_xrefs` (calls, jumps, rip-relative operands, pointers, RVAs - validated against capstone on `msvcp140.dll` and `user32.dll`: 100% recall, no extras) and `find_pointer_path` (holders that lie close together share one memory scan).
- **Two-run pointer comparison:** `find_pointer_path(save_as=)` stores the chains it finds; after the target restarts, `compare_pointer_paths` keeps the ones that still reach the value (`runs` counts the restarts a chain survived; near misses come back with a corrected last offset). `list_pointer_sets` / `get_pointer_set` / `drop_pointer_set`.
- **Patch journal:** every write through `write_memory`, `write_integer`, `write_string`, `copy_memory` and `auto_assemble` (also inside `batch`) is recorded with the bytes it replaced; `list_patches`, `undo_patch` (conflict check, verification, `all=true` newest first, `[DISABLE]` for scripts) and `drop_patches`.
- **Saved state:** pointer sets (`ce_mcp_pointer_sets.json`) and the patch journal (`ce_mcp_patch_journal.jsonl`) survive reloads of the script and CE restarts. Folder: `CE_MCP_STATE_DIR` (Lua global or Cheat Engine's environment; `off` disables), else the folder of `ce_mcp_bridge.lua`, `%LOCALAPPDATA%`, or the temp folder. A failed save never fails a command (`save_error`). Script patches cannot be undone after a reload (CE's disable information is not saved).
- **Breakpoint control:** `set_breakpoint` / `set_data_breakpoint` take `condition` (a sandboxed expression over the registers and memory readers, run under an instruction budget), `stop_after_hits`, and `mode="break"`, which leaves the thread stopped for inspection (`get_halted_state`, `debug_continue` run/step; a watchdog resumes it after `halt_timeout_ms`). Data breakpoints report `value`, `previous_value` and `value_changed`.
- `read_memory` takes `format` (`hex`, `base64`, `array`, `both`); the tool defaults to compact `hex`, the wire default stays `both`. On x64 `find_function_boundaries` and `analyze_function` use the exception table for exact bounds (`method`: `pdata` | `heuristic`).
- `BUSY` joins the error code enum.
- **Tests:** `MCP_Server/tests/behaviour/` runs the real bridge modules in Lua 5.3 against a fake CE API (`pytest` runs them too, `lupa` required): about 660 checks plus a mutation check (139 mutants) and real-DLL oracles (`--real`). `test_ported_tools.py` covers the Python side, including the batch gate. `behaviour/live_smoke.py` checks the newer tools against a running Cheat Engine.

### Changed

- **`batch_commands` is judged request by request.** It is registered as a `write` tool; every request must be a tool that is registered under the active `CE_MCP_TOOLSETS` / `CE_MCP_PROFILE` (dispatcher aliases such as `read_bytes` map to their tool), otherwise the whole batch is refused with `PERMISSION_DENIED` before anything is sent.
- **The tool list is smaller:** tools are registered with `structured_output=False` (the SDK declared an `outputSchema` for every `-> str` tool and sent every result twice), the generated schema `title` keys are dropped and descriptions are dedented. With 38 more tools the list is 8% smaller than before (128,950 -> 118,341 characters).
- The breakpoint hit ring buffer keeps its meaning (`max_hits` = buffer size); "detach after N matching hits" is the new `stop_after_hits`.
- **The Lua bridge is split into modules.** `MCP_Server/ce_mcp_bridge.lua` is now a loader for 26 modules in `MCP_Server/bridge/` (core, JSON codec, one per tool area, dispatcher). Load it exactly as before, but keep the `bridge/` folder next to it. If CE runs the script without its file name, set `CE_MCP_BRIDGE_DIR` first. Each module is its own Lua chunk, so Cheat Engine's 200-local limit no longer applies to the whole bridge. Every dispatcher method returns the same results as before, apart from error-location prefixes, which now name the module file and line.

### Fixed

- **Breakpoint `condition` / `inspect` expressions can no longer allocate inside Cheat Engine.** The restricted environment hid every global, but a string value still reached the string library through the string metatable, so `("a"):rep(1 << 30)` in a condition allocated a gigabyte per hit in one C call that the instruction budget cannot interrupt — from the `standard` profile, which registers `set_breakpoint`. Expressions are numeric, so `BPX.compile` now refuses string literals, `..`, `:` and brackets with `INVALID_PARAMS`.
- **Reloading the script now stops the running bridge.** `StartMCPBridge` called `StopMCPBridge` after the reload had already replaced it with the new instance's version, so the old worker thread kept serving the pipe with the old code and its hardware breakpoints and DBVM watches were never removed. The loader now calls the previous instance's `StopMCPBridge` before loading anything; this also works when upgrading from the single-file bridge.
- **Kernel memory mappings are released on stop/reload.** `cleanupZombieState` referred to `mappedMemoryMDL` before it was declared, so it was always nil and `map_memory` mappings were never unmapped.

## 12.1.0 — 2026-11-04

Covers [#1](https://github.com/fhjordskhkjel/cheatengine-mcp-bridge/pull/1), [#2](https://github.com/fhjordskhkjel/cheatengine-mcp-bridge/pull/2) and the security / error-code / housekeeping changes that followed.

### Behaviour changes (check these if you parse results)

- **Shell tools need a second opt-in on the Cheat Engine side.** `run_command` / `shell_execute` now require `CE_MCP_ALLOW_SHELL=1` in Cheat Engine's environment (or `CE_MCP_ALLOW_SHELL = true` before loading the bridge) in addition to the MCP server's `CE_MCP_ALLOW_SHELL=1`. Otherwise they return `PERMISSION_DENIED`.
- **Every failure has an `error_code`** from the enum in `CLAUDE.md`. The non-enum codes `SCAN_ERROR` and `CE_API_ERROR` are now `INTERNAL_ERROR`. JSON-RPC errors from the bridge come back as `{success: false, error, error_code, jsonrpc_code}` instead of a stringified dict.
- **Integers are exact.** The bridge used to emit every integer through `%.14g`, so x64 pointers and qwords lost precision (`0x7FF612345678` became `1.4069484410226e+14`). `read_integer(type="qword")` now returns the exact signed value; `hex` is still the safest field for pointers above 2^63.
- **`read_integer` for `float` / `double`:** `hex` is now the raw IEEE-754 bit pattern (`87.5` → `"0x42AF0000"`), decoded from the same read as `value`.
- **Breakpoint `stack` captures:** `stack[0]` is now `[SP+0]`, which was previously dropped. Indices shift by one compared with 12.0.0; unreadable slots are `null`.
- **Lua tables with mixed or zero-based keys** encode as JSON objects instead of silently losing keys.
- **No automatic resend after delivery.** A command that times out or loses its connection after it was sent is reported and not retried, because `auto_assemble`, `allocate_memory`, `write_memory` and similar are not idempotent. Requests that provably never reached CE are still resent.
- The five code-injection handlers (`inject_dll`, `inject_dotnet_dll`, `execute_code`, `execute_code_ex`, `execute_method`) return `error_code: "NO_PROCESS"` when nothing is attached. The memory file tools reject empty filenames.

### Added

- **`CE_MCP_PROFILE`** (`readonly` / `standard` / `full`, default `full`). Every tool declares an access class (`read`, `analysis`, `write`, `exec`); the profile registers only the allowed classes. `readonly` (105 tools) never touches the target or the host.
- **MCP tool annotations** derived from the access class: `readOnlyHint`, `destructiveHint`, `openWorldHint`.
- **`CE_MCP_AUDIT_LOG=<path>`**: a JSON-lines record of every command (time, method, bounded parameters, outcome, error code, duration), including shell calls blocked by the gate.
- **`CE_MCP_TOOLSETS`** (comma-separated groups, default `all`) to cut the tool-schema context cost, and the **`list_toolsets`** tool, which explains which tools are disabled and why.
- **Breakpoint hit ring buffers:** `max_hits` (default 1000) on `set_breakpoint`, `set_data_breakpoint` and `debug_set_breakpoint_for_thread`; hits carry `hit_number`, and `get_breakpoint_hits` / `list_breakpoints` report `hit_count`, `dropped_hits` and `max_hits`.
- **`evaluate_lua`** returns `results` (every return value as structured JSON, `nil` as `null`) and `result_count`; `result` is unchanged.
- **Offline test suite** (`python -m pytest`, no Cheat Engine needed) and a GitHub Actions workflow running it on Linux and Windows, including real named-pipe tests.

### Fixed

- JSON codec: non-Latin text in requests no longer fails with a parse error, `é` decodes to UTF-8 instead of a raw byte, escaped backslashes before `u0041` stay literal, and responses are always valid UTF-8 (invalid bytes become `\u00XX`).
- `read_integer(type="float")` failed with *Internal error* on any non-integral value.
- A breakpoint hit arriving after `get_breakpoint_hits(clear=true)`, or any error while capturing a hit, skipped `debug_continueFromBreakpoint` and left the target thread suspended. Hit buffers were unbounded.
- Transport: a slow command could run twice; timeouts were reported as "not reachable"; busy and recreated pipes are now waited for; every request read by the bridge gets exactly one reply (bad frames get an error frame); an unexpected error no longer kills the bridge's worker thread; responses over the 32 MB frame cap become a clear error; the TCP relay reports pipe failures as error replies.
- Sync tools ran on the MCP event loop, so one slow scan blocked pings and cancellations.
- Importing `mcp_cheatengine.py` on Windows failed when stdin had no real descriptor.
- Command reference: the `run_command` / `shell_execute` entries listed parameters and fields that do not exist.

## 12.0.0

The v12 overhaul: ~180 tools across memory, process lifecycle, code injection, symbols, assembly, GUI automation, input, cheat tables and kernel mode.
