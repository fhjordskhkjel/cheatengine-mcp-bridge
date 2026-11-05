"""Runs Lua 5.3 chunks (lupa embeds the same Lua version Cheat Engine uses) against the REAL bridge modules.

The bridge is loaded exactly like ce_mcp_bridge.lua loads it (modules from the loader's list, in order, each called
with a shared namespace table B) but without starting the pipe server. `bridge_modules()` returns that Lua code; the
names the modules export on B are also published as globals so a test body can say `serverState`, `U26`, `paginate`
or `cmd_read_struct` like the old single-chunk bridge allowed.

Without lupa the suites exit with code 77 (skipped).
"""
import re
import sys
from pathlib import Path

from testkit import EXIT_SKIP, BRIDGE_DIR, BRIDGE_LUA, arg_path, has_flag, finish  # re-exported for the suites  # noqa: F401


def _runtime():
    try:
        import lupa.lua53 as lua53
    except ImportError:
        print("SKIP: lupa is not installed (pip install lupa).", file=sys.stderr)
        sys.exit(EXIT_SKIP)
    return lua53.LuaRuntime(encoding=None)


def _to_lua(value):
    return value.encode("utf-8") if isinstance(value, str) else value


def run_lua(code, name="chunk", ascii_only=True, callbacks=None):
    """Run `code` in a fresh Lua state. Returns (ok, text): the chunk's string result, or its error message.

    callbacks: {global name: python function(address) -> int | str | None}, available to the chunk as Lua globals
    (e.g. a real disassembler standing in for CE's getInstructionSize / disassemble).
    """
    lua = _runtime()
    for gname, fn in (callbacks or {}).items():
        def wrapper(*args, _fn=fn):
            try:
                return _to_lua(_fn(*args))
            except Exception as exc:                    # a callback must never unwind through the Lua VM
                print("CALLBACK ERROR:", exc)
                return None
        lua.globals()[gname.encode()] = wrapper
    try:
        result = lua.execute(_to_lua(code))
        if isinstance(result, tuple):
            result = result[0] if result else None
        text = result.decode("utf-8", "replace") if isinstance(result, bytes) else ("" if result is None else str(result))
        ok = True
    except Exception as exc:                            # lupa.LuaError / LuaSyntaxError
        text, ok = str(exc), False
        # A crashed chunk produces no PASS/FAIL lines, so make sure it is counted as an error.
        print("LUA ERROR in chunk '%s': %s" % (name, text[:300].replace("\n", " ")))
    if ascii_only:
        text = text.encode("ascii", "backslashreplace").decode("ascii")
    return ok, text


def module_names(bridge_dir=BRIDGE_DIR):
    """The loader's module list, in load order."""
    loader = (Path(bridge_dir) / "ce_mcp_bridge.lua").read_bytes().decode("utf-8")
    block = re.search(r"local MODULES = \{(.*?)\n\}", loader, re.S).group(1)
    return re.findall(r'"([^"]+)"', block)


def module_source(name, bridge_dir=BRIDGE_DIR):
    return (Path(bridge_dir) / "bridge" / (name + ".lua")).read_bytes().decode("utf-8").replace("\r\n", "\n")


def load(path=BRIDGE_DIR):
    """All module sources of the bridge in `path` (a MCP_Server folder), LF line endings, one string (for text checks)."""
    return "\n".join(module_source(n, path) for n in module_names(path))


def long_string(s):
    level = 0
    while ("]" + "=" * level + "]") in s:
        level += 1
    return "[" + "=" * level + "[" + s + "]" + "=" * level + "]"


def bridge_modules(bridge_dir=BRIDGE_DIR, upto=None, skip=()):
    """Lua code that loads the bridge modules into the namespace table `B` and publishes B's fields as globals.

    upto: stop after this module name (inclusive); skip: module names to leave out.
    """
    parts = ["local B = {}\n_G.B = B\n"]
    for name in module_names(bridge_dir):
        if name not in skip:
            parts.append("do local f = assert(load(%s, \"=%s\", \"t\")); f(B) end\n" % (long_string(module_source(name, bridge_dir)), name))
        if name == upto:
            break
    parts.append("for k, v in pairs(B) do if rawget(_G, k) == nil then rawset(_G, k, v) end end\n")
    return "".join(parts)


def func_end(text, start):
    """(start_index, end_index) of the top-level function that begins with the marker `start`."""
    i = text.index(start)
    return i, text.index("\nend\n", i) + 5


def func_block(text, start):
    i, j = func_end(text, start)
    return text[i:j]


def between(text, start, end_marker, include_end=True):
    i = text.index(start)
    j = text.index(end_marker, i)
    return text[i:j + (len(end_marker) if include_end else 0)]


def compile_check(bridge_dir=BRIDGE_DIR):
    """Every module must at least compile; prints COMPILE OK / COMPILE FAIL and exits on failure."""
    bad = []
    for name in module_names(bridge_dir):
        ok, msg = run_lua("local f, e = load(%s, '=%s', 't'); return f and 'OK' or tostring(e)" % (long_string(module_source(name, bridge_dir)), name))
        if msg != "OK":
            bad.append("%s: %s" % (name, msg))
    print("COMPILE OK" if not bad else "COMPILE FAIL: " + "; ".join(bad))
    if bad:
        finish()
