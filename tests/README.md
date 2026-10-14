# Offline test suites

These tests need **no Cheat Engine process**. They run the real bridge code against a fake CE API, so they are
fast (about 30 s in total) and safe to run on every change. The live end-to-end script is still
[`MCP_Server/test_mcp.py`](../MCP_Server/test_mcp.py) (needs CE running, the bridge loaded and a process attached).

```bash
python tests/run_all.py              # all suites
python tests/run_all.py -v           # + full output of each suite
python tests/run_all.py --real       # + validate PE/RTTI parsing against real system DLLs
python tests/run_all.py --mutation   # + check the suites catch deliberate breakages
python tests/test_lua_jobs.py        # a single suite (exit code 0 = all passed)
```

## Requirements
- Windows, `pip install -r MCP_Server/requirements.txt` (`mcp`, `pywin32`).
- Cheat Engine's `lua53-64.dll` (found in the usual install folders, or set `CE_LUA_DLL`). The bridge is written for
  CE's Lua 5.3, so the tests deliberately use that exact runtime. Without it the Lua suites are *skipped*, not failed
  (`run_all.py --strict` turns skips into failures).

## Suites
| File | What it covers |
|------|----------------|
| `test_lua_robustness.py` | JSON codec (`\u` escapes, int64 numbers, invalid UTF-8), `executeCommand` never throwing, breakpoint-hit recording and the callback that must always resume the target |
| `test_lua_jobs.py` | `read_memory` formats, `read_struct`, `batch`, `bridge_status`, and the async job system (scan jobs, poll fallback, cancel, caps, cleanup) |
| `test_lua_analysis.py` | PE imports/exports/TLS, RVA/IDA translation, RTTI, string refs, code caves, pointer paths, snapshots, `export_names`/`import_names`/`export_structures`, on synthetic x64 **and** x86 images |
| `test_client_retry.py` | The Python client against a fake bridge on a real named pipe: no double execution of state-changing commands, reconnect backoff, timeouts that must not hang, bad UTF-8, RPC errors |
| `test_client_jobs.py` | UNIT-25 MCP tools: parameter forwarding, `wait_for_job`, `batch_commands` retry policy |
| `test_client_analysis.py` | UNIT-26 MCP tools: parameter cleaning, job wrappers (`wait_seconds` / `timed_out`), tool registration and schemas |

`test_lua_analysis.py --real` goes further than the synthetic images: it parses `user32.dll` and `msvcp140.dll` as
loaded in the test process and cross-checks them with Windows itself: every export against `GetProcAddress`, every
resolved import against `GetProcAddress` of the imported function, section flags against `VirtualQuery`, and the RTTI
scan against the known `std::` exception classes. (Some `user32` exports are redirected by Windows' app-compat shims;
those are skipped because `GetProcAddress` no longer returns the module's own export.)

## Mutation check
`mutation_check.py` applies one small plausible bug at a time to a copy of `ce_mcp_bridge.lua` and requires the
matching suite to fail. It exists because "all tests pass" says nothing if the tests cannot fail. If you change the
bridge code and an anchor disappears the mutant is reported `STALE`; update its text in `mutation_check.py`.
One mutant is a documented survivor (a defensive x86 sanity check that cannot change any observable result).

## Writing tests
- Suites print lines starting with `PASS` / `FAIL`; `testkit` counts them and `finish()` turns the totals into the
  exit code (a run with zero passes, any `FAIL`, or any `LUA ERROR` / `COMPILE FAIL` line is a failure).
- Lua suites extract the real functions from `ce_mcp_bridge.lua` (see `lua_harness.func_end` / `between`) and run
  them in a fresh state with fake CE globals (`createMemScan`, `readBytes`, `enumModules`, ...). When you add a
  command, extend the matching suite *and* add a mutant for its most important branch.
- A passing fake-CE test proves the bridge logic, not that CE behaves as the fake does. Behaviour that depends on
  the real CE API (memscan events, hardware breakpoints, DBVM) still needs `MCP_Server/test_mcp.py` or manual checks.
