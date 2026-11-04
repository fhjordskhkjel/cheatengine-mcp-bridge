# Behaviour suites

These suites run the **real bridge modules** (`MCP_Server/bridge/*.lua`, loaded the way `ce_mcp_bridge.lua` loads them,
without starting the pipe server) in Lua 5.3 against a **fake Cheat Engine API**, and check what the handlers do with
synthetic PE images, a fake memscan, a fake debugger and simulated target restarts. They need no Cheat Engine and take a
few seconds each. They complement the pytest tests next to this folder (`ce_stub.lua`, `fake_bridge.py`, ...), which
cover the transport, the codec, the policy and the generic handlers.

```bash
pip install lupa                                   # the only requirement (embeds Lua 5.3, the version CE uses)
python MCP_Server/tests/behaviour/run_all.py       # all suites
python MCP_Server/tests/behaviour/run_all.py -v    # + full output of each suite
python MCP_Server/tests/behaviour/run_all.py --real      # + validate PE/RTTI/xref parsing against real system DLLs
python MCP_Server/tests/behaviour/run_all.py --mutation  # + check the suites catch deliberate breakages
python MCP_Server/tests/behaviour/suite_lua_jobs.py      # a single suite (exit code 0 = all passed)
```

`python -m pytest` runs them too (`test_behaviour_suites.py`); without `lupa` they are skipped, not failed.

## How a suite is built
`lua_harness.bridge_modules()` returns Lua code that loads the loader's module list into a namespace table `B`, then
publishes `B`'s fields as globals, so a test body can say `serverState`, `U26`, `BPX`, `paginate` or `cmd_read_struct`.
A suite concatenates `fake_ce.STUBS` (page-granular fake memory, memscan, timers, ...), those modules, `fake_ce.HELPERS`
(`eq`, `runJob`) and its own test body, and prints `PASS` / `FAIL` lines; `testkit.finish()` turns them into the exit code.
Every suite takes an optional argument: the path of a `MCP_Server` folder to test instead of the real one (this is how the
mutation check feeds it broken copies).

## Suites
| File | What it covers |
|------|----------------|
| `suite_lua_jobs.py` | `read_memory` formats, `read_struct`, `batch`, `bridge_status`, and the async job system (scan jobs, poll fallback, cancel, caps, cleanup) |
| `suite_lua_analysis.py` | PE imports/exports/TLS, RVA/IDA translation, RTTI, string refs, code caves, pointer paths (including the shared scans), snapshots, `export_names`/`import_names`/`export_structures`, function boundaries and struct recovery, on synthetic x64 **and** x86 images |
| `suite_lua_breakpoints.py` | Conditions, `stop_after_hits`, break-and-inspect with its watchdog, data-breakpoint validation, and the guarantee that a hit callback can never leave the target halted by accident |
| `suite_lua_xrefs.py` | `find_xrefs`: calls/jumps (rel32, rel8, across chunk borders), rip-relative operands and their read/write classification, absolute pointers, RVAs and the `.pdata` exclusion, ranges, module selection, limits, on synthetic x64 and x86 images with a fake instruction decoder |
| `suite_lua_pathsets.py` | `find_pointer_path(save_as=)` and `compare_pointer_paths` across simulated restarts (memory wiped, modules moved, pid changed): survivors and run counts, narrowing, near misses, null pointers / missing modules, inline chains, paging and bounds, x86 wrap-around; plus the saved state file (reload, damaged/edited files, `.tmp` fallback, `off`, unwritable folder) |
| `suite_lua_patches.py` | The patch journal: every write tool recorded with the exact bytes it replaced, failed writes not recorded, undo / conflicts / force / verification, stacked patches unwound newest first, other-process entries (including a reused pid), bounds; plus the saved journal (reload, compaction, damaged lines, `drop_patches`) |
| `suite_lua_load.py` | The WHOLE bridge through the real loader (`dofile`) in a fake CE: reloading must stop the previous instance, the real pipe worker/dispatcher answers every registered method with a proper reply (never a bare `true`; process-less calls say `NO_PROCESS`), the journal is wired into the real dispatcher (also inside `batch`), and state files round-trip between instances |

`--real` goes further than the synthetic images. `suite_lua_analysis.py --real` parses `user32.dll` and `msvcp140.dll` as loaded
in the test process and cross-checks them with Windows itself (every export against `GetProcAddress`, imports, section flags
against `VirtualQuery`, RTTI against the known `std::` exception classes). `suite_lua_xrefs.py --real` (`pip install capstone`)
checks `find_xrefs` against an independent oracle: capstone linear-sweeps the code of the same two DLLs and lists every direct
branch and rip-relative operand with the address it reaches; the bridge's instruction addresses must be identical.

`mutation_check.py` applies one small, plausible bug at a time to the module that holds its anchor text (in a temporary copy of
the bridge folder) and requires the matching suite to fail. A mutant reported `STALE` means the code it anchors on changed:
update the anchor, do not ignore it. New Lua logic needs a test in the matching suite and, if it can silently break, a mutant.

## Live smoke test (needs a running Cheat Engine)
`python MCP_Server/tests/behaviour/live_smoke.py [--only SECTION] [-v]` checks what only a real CE can confirm. It spawns its own
throwaway target (`live_target.py`), attaches CE to it, runs about 60 checks through the real MCP tool layer and re-attaches
whatever CE had open before. Sections: connection, attach, memory, scan jobs, PE analysis (incl. RTTI and `recover_struct` on a
real `msvcp140.dll`), xrefs, snapshots, pointer sets, patch journal, breakpoints (conditions, `stop_after_hits`, data breakpoints,
break mode: the target's counter must really stand still, the watchdog and `clear_all_breakpoints` must resume it) and bridge
health. It exits with code 77 (skipped) when the pipe does not exist. It is not part of `run_all.py`.
