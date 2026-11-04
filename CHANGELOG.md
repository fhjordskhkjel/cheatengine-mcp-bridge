# Changelog

All notable changes to the Cheat Engine MCP Bridge. The wire protocol (`CE_MCP_Bridge_v99`) is unchanged; reload `ce_mcp_bridge.lua` and restart the MCP server to pick up a new version.

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

- **`CE_MCP_PROFILE`** (`readonly` / `standard` / `full`, default `full`). Every tool declares an access class (`read`, `analysis`, `write`, `exec`); the profile registers only the allowed classes. `readonly` (106 tools) never touches the target or the host.
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
