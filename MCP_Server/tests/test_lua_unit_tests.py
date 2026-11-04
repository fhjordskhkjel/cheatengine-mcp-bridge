"""Run the standalone Lua unit tests under Lua 5.3 (CE) and 5.4 via lupa."""
import pytest

from conftest import BRIDGE_LUA, BRIDGE_MODULES, SERVER_DIR

lupa = pytest.importorskip("lupa")
LUA_TESTS = ["test_json_codec.lua", "test_pointer_parse.lua"]
RUNTIMES = {"5.3": "lua53", "5.4": "lua54"}


@pytest.mark.parametrize("version", sorted(RUNTIMES))
@pytest.mark.parametrize("script", LUA_TESTS)
def test_lua_script(script, version):
    module = getattr(lupa, RUNTIMES[version], None)
    if module is None:
        pytest.skip(f"lupa has no Lua {version} runtime")
    L = module.LuaRuntime(encoding=None)
    path = str(SERVER_DIR / script).encode()
    L.execute(b"arg = {[0] = ...}", path)
    # os.exit would kill pytest; turn it into an error carrying the status.
    L.execute(b"os.exit = function(code) error('__exit__' .. tostring(code), 0) end")
    run = L.eval(b"function(p) local out = {} print = function(...) out[#out+1] = table.concat({...}, ' ') end "
                 b"local ok, err = pcall(dofile, p) return ok, err, table.concat(out, '\\n') end")
    ok, err, output = run(path)
    output = output.decode()
    if not ok and err in (b"__exit__0", b"__exit__true", b"__exit__nil"):
        ok = True  # the script called os.exit() with a success status
    assert ok, f"{script} failed: {err!r}\n{output}"
    assert "0 failed" in output, output


@pytest.mark.parametrize("version", sorted(RUNTIMES))
@pytest.mark.parametrize("path", [BRIDGE_LUA] + BRIDGE_MODULES, ids=lambda p: p.name)
def test_bridge_compiles(version, path):
    """Each file is its own chunk, so this also enforces CE's 200-local limit per module."""
    module = getattr(lupa, RUNTIMES[version], None)
    if module is None:
        pytest.skip(f"lupa has no Lua {version} runtime")
    L = module.LuaRuntime(encoding=None)
    compile_only = L.eval(b"function(src, name) local f, err = load(src, name) return f ~= nil, err end")
    ok, err = compile_only(path.read_bytes(), b"@" + path.name.encode())
    assert ok, err
