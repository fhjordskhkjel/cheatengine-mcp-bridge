"""Handlers of ce_mcp_bridge.lua run under Lua 5.3 with stubbed CE APIs."""
import struct


def test_read_float_non_integral(bridge):
    bridge.G[b"MEM_BYTES"][0x1000] = bridge.lua_table(struct.pack("<f", 87.5))
    r = bridge.result("read_integer", address="0x1000", type="float")
    assert r["success"] and r["value"] == 87.5 and r["hex"] == "0x42AF0000"


def test_read_double_raw_bits(bridge):
    bridge.G[b"MEM_BYTES"][0x2000] = bridge.lua_table(struct.pack("<d", 0.1))
    r = bridge.result("read_integer", address="0x2000", type="double")
    assert r["value"] == 0.1 and r["hex"] == "0x3FB999999999999A"


def test_read_qword_exact(bridge):
    bridge.G[b"MEM"][b"q" + str(0x3000).encode()] = 0x7FF612345678
    r = bridge.result("read_integer", address="0x3000", type="qword")
    assert r["value"] == 0x7FF612345678 and r["hex"] == "0x7FF612345678"


def _set_bp(bridge, max_hits=3):
    G = bridge.G
    G[b"RSP"], G[b"RIP"] = 0x5000, 0x140001000
    for i in range(4):
        G[b"MEM"][b"q" + str(0x5000 + 8 * i).encode()] = 0x140002000 + i
    r = bridge.result("set_breakpoint", address="0x140001000", id="bp1",
                      capture_stack=True, stack_depth=4, max_hits=max_hits)
    assert r["success"] and r["max_hits"] == max_hits
    return G[b"BP_CALLBACKS"][0x140001000]


def test_breakpoint_ring_buffer_and_stack(bridge):
    cb = _set_bp(bridge)
    for _ in range(5):
        cb()
    r = bridge.result("get_breakpoint_hits", id="bp1", clear=False)
    assert [h["hit_number"] for h in r["hits"]] == [3, 4, 5]
    assert (r["hit_count"], r["dropped_hits"], r["max_hits"]) == (5, 2, 3)
    assert r["hits"][0]["stack"] == ["0x140002000", "0x140002001", "0x140002002", "0x140002003"]
    assert bridge.G[b"CONTINUES"] == 5
    listed = bridge.result("list_breakpoints")["breakpoints"][0]
    assert listed["hit_count"] == 5


def test_hit_after_clear_all_is_recorded(bridge):
    cb = _set_bp(bridge)
    bridge.result("get_breakpoint_hits", clear=True)
    cb()
    r = bridge.result("get_breakpoint_hits", id="bp1", clear=False)
    assert r["total"] == 1 and bridge.G[b"CONTINUES"] == 1


def test_capture_error_still_resumes_target(bridge):
    cb = _set_bp(bridge)
    bridge.G[b"targetIs64Bit"] = None  # makes register capture raise
    cb()
    assert bridge.G[b"CONTINUES"] == 1
    hit = bridge.result("get_breakpoint_hits", id="bp1", clear=False)["hits"][-1]
    assert "hit capture failed" in hit["error"]


def test_evaluate_lua_structured_results(bridge):
    r = bridge.result("evaluate_lua", code="local t = {a=1, list={1,2,3}}; t.self = t; return t, nil, 'x', print")
    assert r["success"] and r["result_count"] == 4
    first = r["results"][0]
    assert first["list"] == [1, 2, 3] and first["self"].startswith("<cycle")
    assert r["results"][1:3] == [None, "x"] and r["result"].startswith("table:")


def test_evaluate_lua_nil_slots_and_ints(bridge):
    assert bridge.result("evaluate_lua", code="return 42, nil")["results"] == [42, None]
    assert bridge.result("evaluate_lua", code="return nil")["results"] == [None]
    assert bridge.result("evaluate_lua", code="local x = 1")["results"] == []
    r = bridge.result("evaluate_lua", code="return 0x7FF612345678")
    assert r["results"] == [0x7FF612345678] and r["result"] == "140694844102264"


def test_utf8_round_trip(bridge):
    r = bridge.result("evaluate_lua", code="return '日本 é', #'日本 é'")
    assert r["results"] == ["日本 é", 9]


def test_process_guard_has_error_code(bridge):
    bridge.L.execute(b"function getOpenedProcessID() return 0 end")
    r = bridge.result("inject_dll", filepath="x.dll")
    assert r == {"success": False, "error": "No process attached", "error_code": "NO_PROCESS"}
    r = bridge.result("aob_scan_module", pattern="90", module_name="a.exe")
    assert r["error_code"] == "NO_PROCESS"


def test_sanitize_filename_shared(bridge):
    assert "traversal" in bridge.result("md5_file", filename="..\\x")["error"]
    assert bridge.result("md5_file", filename="")["success"] is False
