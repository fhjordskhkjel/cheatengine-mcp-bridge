"""The split bridge: module list, import/export discipline, loader and reload behaviour."""
import re

import pytest

from conftest import BRIDGE_LUA, BRIDGE_MODULES, HERE, Bridge
from luascope import analyze

LOADER = BRIDGE_LUA.read_text(encoding="utf-8")
IMPORT_RE = re.compile(r"^local (\w+) = B\.(\w+)$", re.M)
EXPORT_RE = re.compile(r"^B\.(\w+) = (\w+)$", re.M)


def _loader_modules():
    block = re.search(r"local MODULES = \{(.*?)\n\}", LOADER, re.S).group(1)
    return re.findall(r'"([^"]+)"', block)


def test_loader_lists_every_module_in_order():
    assert _loader_modules() == [p.stem for p in BRIDGE_MODULES]


def test_modules_import_what_they_use_and_export_what_they_define():
    """Every shared name a module uses must be imported from an earlier module.

    A missing import would not fail to compile: the name would silently become
    an undefined global (nil) at runtime.
    """
    owner, problems = {}, []
    for path in BRIDGE_MODULES:
        text = path.read_text(encoding="utf-8")
        imports = dict(IMPORT_RE.findall(text))
        exports = dict(EXPORT_RE.findall(text))
        chunk_locals = [n for n, _ in analyze(text)[0] if n != "B"]
        own = [n for n in chunk_locals if n not in imports]
        for local_name, field in imports.items():
            if local_name != field:
                problems.append(f"{path.name}: import {local_name} = B.{field} must keep the name")
            if field not in owner:
                problems.append(f"{path.name}: imports B.{field}, which no earlier module exports")
        for name in own:
            if exports.get(name) != name:
                problems.append(f"{path.name}: top-level local {name} is not exported (B.{name} = {name})")
            if name in owner:
                problems.append(f"{path.name}: {name} already defined by {owner[name]}")
        used = {n for n, _ in analyze(text)[1]}
        for name in sorted(used & set(owner)):
            if name not in imports and name not in own:
                problems.append(f"{path.name}: uses {name} (from {owner[name]}) without importing it")
        for name in own:
            owner[name] = path.name
    assert not problems, "\n".join(problems)


def _bridge_with_tracking(prelude=b""):
    return Bridge(prelude=b"""
THREADS, TERMINATED, REMOVED, UNMAPPED = 0, 0, 0, 0
function createThread(fn) THREADS = THREADS + 1
  return { terminate = function() TERMINATED = TERMINATED + 1 end } end
function debug_removeBreakpoint() REMOVED = REMOVED + 1 end
function mapMemory(addr, size) return 0x7F0000, "mdl-1" end
function unmapMemory(addr, mdl) UNMAPPED = UNMAPPED + 1; LAST_MDL = mdl end
""" + prelude)


def test_reload_stops_the_previous_instance():
    b = _bridge_with_tracking()
    G = b.G
    assert b.result("set_breakpoint", address="0x140001000", id="bp1")["success"]
    removed_before = G[b"REMOVED"]
    b.L.eval(b"dofile")(str(BRIDGE_LUA).encode())  # reload, as re-executing the script in CE does
    assert G[b"THREADS"] == 2
    assert G[b"TERMINATED"] == 1, "the first instance's worker thread must be terminated"
    assert G[b"REMOVED"] > removed_before, "the first instance's breakpoint must be removed"


def test_stop_releases_mapped_memory():
    b = _bridge_with_tracking()
    r = b.result("map_memory", address="0x1000", size=4096)
    assert r["success"] and r["mapped_address"] == "0x007F0000"
    b.L.execute(b"StopMCPBridge()")
    assert b.G[b"UNMAPPED"] == 1 and b.G[b"LAST_MDL"] == b"mdl-1"


def test_loader_without_file_name_explains_how_to_load():
    lupa = pytest.importorskip("lupa")
    L = lupa.lua53.LuaRuntime(encoding=None)
    L.execute((HERE / "ce_stub.lua").read_bytes())
    run = L.eval(b"function(src) local f = assert(load(src, '=pasted')) return pcall(f) end")
    ok, err = run(BRIDGE_LUA.read_bytes())  # like pasting the loader into CE's Lua window
    assert ok is False and b"CE_MCP_BRIDGE_DIR" in err and b"dofile" in err


def test_loader_honours_ce_mcp_bridge_dir_when_pasted():
    lupa = pytest.importorskip("lupa")
    L = lupa.lua53.LuaRuntime(encoding=None)
    L.execute((HERE / "ce_stub.lua").read_bytes())
    L.globals()[b"CE_MCP_BRIDGE_DIR"] = str(BRIDGE_LUA.parent).encode()
    run = L.eval(b"function(src) local f = assert(load(src, '=pasted')) return pcall(f) end")
    ok, B = run(BRIDGE_LUA.read_bytes())
    assert ok is True and B[b"VERSION"]
