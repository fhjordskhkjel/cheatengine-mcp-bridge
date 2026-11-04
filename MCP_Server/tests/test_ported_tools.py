"""Parameter forwarding, job wrappers, the batch gate and the tool list of the tools ported from UNIT-25..31.

The MCP server module is imported with a fake bridge client: every tool call is recorded as (method, params) and
answered with canned replies (jobs: a "fast" job finishes after two polls, a "slow" one never does).
"""
import json
import time

import pytest

import conftest  # noqa: F401  (puts MCP_Server on sys.path, picks the TCP transport)


@pytest.fixture
def mod(monkeypatch):
    import mcp_cheatengine as m

    params_seen = {}
    calls = []
    polls = {}

    def fake_send(method, params=None):
        params = params if params is not None else {}
        params_seen[method] = params
        calls.append(method)
        if method == "start_job":
            job = "job_slow" if params["kind"] == "find_pointer_path" else ("job_fail" if params["kind"] == "find_code_caves" else "job_fast")
            return {"success": True, "job_id": job, "kind": params["kind"], "state": "running"}
        if method == "get_job":
            jid = params["job_id"]
            polls[jid] = polls.get(jid, 0) + 1
            k = polls[jid]
            if jid in ("job_slow", "slow") or (jid in ("job_fast",) and k <= 2):
                return {"success": True, "job_id": jid, "state": "running", "progress": {"current": k, "total": 10}}
            if jid == "job_fail":
                return {"success": True, "job_id": jid, "state": "failed", "error": "boom"}
            return {"success": True, "job_id": jid, "state": "done"}
        if method == "get_job_result":
            return {"success": True, "echo_offset": params.get("offset"), "echo_limit": params.get("limit")}
        if method == "bridge_status":
            return {"success": True, "version": "12.1.0", "uptime_seconds": 5}
        return {"success": True, "echo": method}

    monkeypatch.setattr(m.ce_client, "send_command", fake_send)
    m.params_seen = params_seen
    m.calls = calls
    return m


def check(name, cond, extra=""):
    assert cond, f"{name}: {extra}"


def test_analysis_tool_parameters(mod):
    params_seen, calls = mod.params_seen, mod.calls
    mod.pe_info()
    check("pe_info() sends no params", params_seen["pe_info"] == {}, params_seen["pe_info"])
    mod.pe_info(module="game.exe")
    check("pe_info module forwarded", params_seen["pe_info"] == {"module": "game.exe"})
    mod.pe_imports(dll="kernel")
    check("pe_imports drops empty module, keeps paging", params_seen["pe_imports"] == {"dll": "kernel", "offset": 0, "limit": 100}, params_seen["pe_imports"])
    mod.pe_exports(name_contains="Create", limit=5)
    check("pe_exports filter", params_seen["pe_exports"] == {"name_contains": "Create", "offset": 0, "limit": 5}, params_seen["pe_exports"])
    mod.pe_tls_callbacks()
    check("pe_tls_callbacks", params_seen["pe_tls_callbacks"] == {})
    mod.va_to_rva(addresses=["0x1000", "0x2000"], ida_image_base="0x400000")
    check("va_to_rva list + ida base", params_seen["va_to_rva"] == {"addresses": ["0x1000", "0x2000"], "ida_image_base": "0x400000", "include_section": True}, params_seen["va_to_rva"])
    mod.rva_to_va(module="game.exe", rva="0x10")
    check("rva_to_va", params_seen["rva_to_va"] == {"module": "game.exe", "rva": "0x10"}, params_seen["rva_to_va"])
    mod.rebase_address(address="0x402800", from_base="0x400000", to_module="game.exe")
    check("rebase_address", params_seen["rebase_address"] == {"address": "0x402800", "from_base": "0x400000", "to_module": "game.exe"}, params_seen["rebase_address"])
    mod.export_names(module="game.exe", format="idapython")
    check("export_names", params_seen["export_names"] == {"module": "game.exe", "format": "idapython", "include_types": True}, params_seen["export_names"])
    mod.export_structures()
    check("export_structures", params_seen["export_structures"] == {})
    mod.import_names([{"name": "A", "rva": "0x10"}], module="game.exe")
    p = params_seen["import_names"]
    check("import_names", p["names"][0]["name"] == "A" and p["module"] == "game.exe" and p["do_not_save"] is True and "address_is_ida" not in p, p)
    mod.import_names([{"name": "A", "address": "0x1"}], address_is_ida=True, ida_image_base="0x400000", prefix="x_")
    p = params_seen["import_names"]
    check("import_names ida flags", p["address_is_ida"] is True and p["prefix"] == "x_" and p["ida_image_base"] == "0x400000", p)
    mod.pe_functions()
    check("pe_functions() sends only paging", params_seen["pe_functions"] == {"offset": 0, "limit": 100}, params_seen["pe_functions"])
    mod.pe_functions(address="0x140001025", include_unwind=True)
    check("pe_functions address + unwind", params_seen["pe_functions"] == {"address": "0x140001025", "offset": 0, "limit": 100, "include_unwind": True}, params_seen["pe_functions"])
    mod.recover_struct(addresses=["0x2A000000", "0x2A000200"], create=True, name="Player")
    check("recover_struct forwards instances/create/name", params_seen["recover_struct"] == {"addresses": ["0x2A000000", "0x2A000200"], "name": "Player", "create": True}, params_seen["recover_struct"])
    mod.recover_struct(address="0x2A000000", size=512)
    check("recover_struct single instance", params_seen["recover_struct"] == {"address": "0x2A000000", "size": 512}, params_seen["recover_struct"])
    mod.set_breakpoint("0x1000")
    check("set_breakpoint defaults send no new options", params_seen["set_breakpoint"] == {"address": "0x1000", "capture_registers": True, "capture_stack": False, "stack_depth": 16, "max_hits": 1000}, params_seen["set_breakpoint"])
    mod.set_breakpoint("0x1000", id="x", condition="RAX==5", mode="break", stop_after_hits=3, halt_timeout_ms=2000, inspect=[{"expr": "RDX", "size": 8}])
    check("set_breakpoint forwards condition/mode/stop_after_hits/halt_timeout/inspect", params_seen["set_breakpoint"] == {
        "address": "0x1000", "id": "x", "capture_registers": True, "capture_stack": False, "stack_depth": 16, "condition": "RAX==5",
        "mode": "break", "max_hits": 1000, "stop_after_hits": 3, "halt_timeout_ms": 2000, "inspect": [{"expr": "RDX", "size": 8}]}, params_seen["set_breakpoint"])
    mod.set_data_breakpoint("0x9000")
    check("set_data_breakpoint defaults", params_seen["set_data_breakpoint"] == {"address": "0x9000", "access_type": "w", "size": 4, "max_hits": 1000}, params_seen["set_data_breakpoint"])
    mod.set_data_breakpoint("0x9000", access_type="rw", size=8, condition="1", stop_after_hits=2)
    check("set_data_breakpoint forwards options", params_seen["set_data_breakpoint"] == {"address": "0x9000", "access_type": "rw", "size": 8, "max_hits": 1000, "condition": "1", "stop_after_hits": 2}, params_seen["set_data_breakpoint"])
    mod.get_halted_state()
    check("get_halted_state defaults", params_seen["get_halted_state"] == {"stack_depth": 16}, params_seen["get_halted_state"])
    mod.get_halted_state(stack_depth=4, extend_ms=500)
    check("get_halted_state options", params_seen["get_halted_state"] == {"stack_depth": 4, "extend_ms": 500}, params_seen["get_halted_state"])
    mod.snapshot_region(address="0x9000", size=16, name="A")
    check("snapshot_region address", params_seen["snapshot_region"] == {"address": "0x9000", "size": 16, "name": "A"}, params_seen["snapshot_region"])
    mod.snapshot_region(module="game.exe", section=".data")
    check("snapshot_region section (size omitted)", params_seen["snapshot_region"] == {"module": "game.exe", "section": ".data"}, params_seen["snapshot_region"])
    mod.list_snapshots()
    mod.delete_snapshot(name="A")
    check("delete_snapshot name", params_seen["delete_snapshot"] == {"name": "A"}, params_seen["delete_snapshot"])
    mod.delete_snapshot(all=True)
    check("delete_snapshot all", params_seen["delete_snapshot"] == {"all": True}, params_seen["delete_snapshot"])
    mod.diff_snapshots(["A", "B"])
    check("diff_snapshots minimal", params_seen["diff_snapshots"] == {"snapshots": ["A", "B"], "unit": 4, "limit": 200}, params_seen["diff_snapshots"])
    mod.diff_snapshots(["A", "B", "C"], pattern="CU", unit=8, offset=16, length=64, merge_gap=8, limit=5)
    check("diff_snapshots full", params_seen["diff_snapshots"] == {"snapshots": ["A", "B", "C"], "pattern": "CU", "unit": 8, "offset": 16, "length": 64, "merge_gap": 8, "limit": 5}, params_seen["diff_snapshots"])

    # ---- job-backed tools
    out = json.loads(mod.rtti_scan_module(module="game.exe", wait_seconds=5, limit=50, offset=10))
    check("rtti_scan_module: start_job params", params_seen["start_job"] == {"kind": "rtti_scan", "params": {"module": "game.exe", "max_vtable_entries": 256}}, params_seen["start_job"])
    check("rtti_scan_module waits then fetches paged result", out.get("echo_offset") == 10 and out.get("echo_limit") == 50, out)
    t0 = time.monotonic()
    out = json.loads(mod.find_pointer_path("0x2A000100", wait_seconds=0.7))
    check("find_pointer_path: params", params_seen["start_job"] == {"kind": "find_pointer_path", "params": {
        "address": "0x2A000100", "max_depth": 3, "max_offset": 1024, "max_per_level": 16, "max_results": 100, "protection": "+W"}}, params_seen["start_job"])
    check("find_pointer_path: times out cleanly with the job id", out.get("timed_out") is True and out.get("job_id") == "job_slow" and "wait_for_job('job_slow')" in out.get("hint", ""), out)
    check("find_pointer_path: honoured wait_seconds", 0.5 < time.monotonic() - t0 < 3, time.monotonic() - t0)
    out = json.loads(mod.find_code_caves(wait_seconds=3))
    check("find_code_caves: failed job status is returned as-is", out.get("state") == "failed" and out.get("error") == "boom", out)
    check("find_code_caves: defaults", params_seen["start_job"] == {"kind": "find_code_caves", "params": {"byte": 204, "min_size": 16, "sections": "exec"}}, params_seen["start_job"])
    mod.find_string_refs(text="Hello", wait_seconds=3)
    check("find_string_refs: params (wide dropped when false)", params_seen["start_job"] == {"kind": "find_string_refs", "params": {"text": "Hello", "match": "start", "include_data": True}}, params_seen["start_job"])
    mod.find_string_refs(address="0x1000", wide=True, match="any", include_data=False, wait_seconds=3)
    check("find_string_refs: address/wide/any/no-data", params_seen["start_job"]["params"] == {"address": "0x1000", "wide": True, "match": "any", "include_data": False}, params_seen["start_job"])
    out = json.loads(mod.find_xrefs("game.exe+1234", wait_seconds=3, limit=20, offset=40))
    check("find_xrefs: defaults send only the address", params_seen["start_job"] == {"kind": "find_xrefs", "params": {"address": "game.exe+1234"}}, params_seen["start_job"])
    check("find_xrefs: paging goes to get_job_result", out.get("echo_offset") == 40 and out.get("echo_limit") == 20, out)
    mod.find_xrefs("0x3000", size=32, module="all", kinds="call,rip", max_results=100, wait_seconds=3)
    check("find_xrefs: size/module/kinds/max_results forwarded", params_seen["start_job"] == {"kind": "find_xrefs", "params": {
        "address": "0x3000", "size": 32, "module": "all", "kinds": "call,rip", "max_results": 100}}, params_seen["start_job"])
    mod.find_pointer_path("0x2A000100", save_as="hp", wait_seconds=0.3)
    check("find_pointer_path: save_as forwarded", params_seen["start_job"]["params"].get("save_as") == "hp", params_seen["start_job"])

    # ---- pointer path sets (two-run comparison)
    mod.compare_pointer_paths("0x1F000100", name="hp")
    check("compare_pointer_paths: defaults send only target, name and limit", params_seen["compare_pointer_paths"] == {"target": "0x1F000100", "name": "hp", "limit": 100}, params_seen["compare_pointer_paths"])
    mod.compare_pointer_paths("0x1F000100", chains=[{"base": "game.exe+0x10", "offsets": [64]}], save_as="x", near_delta=64, near_limit=3, offset=5, limit=10)
    check("compare_pointer_paths: everything forwarded", params_seen["compare_pointer_paths"] == {
        "target": "0x1F000100", "chains": [{"base": "game.exe+0x10", "offsets": [64]}], "save_as": "x", "near_delta": 64, "near_limit": 3, "offset": 5, "limit": 10}, params_seen["compare_pointer_paths"])
    mod.list_pointer_sets()
    check("list_pointer_sets calls the bridge", calls[-1] == "list_pointer_sets")
    mod.get_pointer_set("hp", offset=2, limit=5)
    check("get_pointer_set params", params_seen["get_pointer_set"] == {"name": "hp", "offset": 2, "limit": 5}, params_seen["get_pointer_set"])
    mod.drop_pointer_set(name="hp")
    check("drop_pointer_set by name", params_seen["drop_pointer_set"] == {"name": "hp"}, params_seen["drop_pointer_set"])
    mod.drop_pointer_set(all=True)
    check("drop_pointer_set all", params_seen["drop_pointer_set"] == {"all": True}, params_seen["drop_pointer_set"])

    # ---- patch journal
    mod.list_patches()
    check("list_patches defaults", params_seen["list_patches"] == {"limit": 50}, params_seen["list_patches"])
    mod.list_patches(active_only=True, offset=10, limit=5)
    check("list_patches options", params_seen["list_patches"] == {"active_only": True, "offset": 10, "limit": 5}, params_seen["list_patches"])
    mod.undo_patch("p3")
    check("undo_patch by id", params_seen["undo_patch"] == {"id": "p3"}, params_seen["undo_patch"])
    mod.undo_patch(all=True, force=True)
    check("undo_patch all + force", params_seen["undo_patch"] == {"all": True, "force": True}, params_seen["undo_patch"])
    mod.drop_patches()
    check("drop_patches defaults to the inactive entries", params_seen["drop_patches"] == {"which": "inactive"}, params_seen["drop_patches"])
    mod.drop_patches("all")
    check("drop_patches all", params_seen["drop_patches"] == {"which": "all"}, params_seen["drop_patches"])



def test_job_and_operations_tools(mod):
    params_seen = mod.params_seen
    # ---- read_memory defaults to compact hex
    mod.read_memory("0x1000", 16)
    check("read_memory sends format=hex by default", params_seen["read_memory"].get("format") == "hex", params_seen.get("read_memory"))
    mod.read_memory("0x1000", 16, format="base64")
    check("read_memory forwards explicit format", params_seen["read_memory"].get("format") == "base64")

    # ---- read_struct / jobs tools forward their params
    mod.read_struct("0x1000", [{"name": "hp", "type": "float", "offset": 4}])
    check("read_struct forwards fields", params_seen["read_struct"]["fields"][0]["name"] == "hp")
    mod.start_job("aob_scan", {"pattern": "90"})
    check("start_job forwards kind+params", params_seen["start_job"] == {"kind": "aob_scan", "params": {"pattern": "90"}})
    mod.start_job("find_references")
    check("start_job params default to {}", params_seen["start_job"]["params"] == {})
    mod.get_job_result("job_1", offset=5, limit=7)
    check("get_job_result paging params", params_seen["get_job_result"] == {"job_id": "job_1", "offset": 5, "limit": 7})

    # ---- wait_for_job
    t0 = time.monotonic()
    out = json.loads(mod.wait_for_job("fast", timeout_seconds=10, poll_interval=0.1))
    check("wait_for_job returns when done", out.get("state") == "done" and not out.get("timed_out"), out)
    check("wait_for_job did not wait for the timeout", time.monotonic() - t0 < 3, time.monotonic() - t0)
    t0 = time.monotonic()
    out = json.loads(mod.wait_for_job("slow", timeout_seconds=0.6, poll_interval=0.1))
    check("wait_for_job times out cleanly", out.get("timed_out") is True and out.get("state") == "running", out)
    check("wait_for_job honours its timeout", 0.5 < time.monotonic() - t0 < 2.5, time.monotonic() - t0)



def test_tool_list(mod):
    # ---- MCP registration / schemas
    tools = {tool.name: tool for tool in mod.mcp._tool_manager.list_tools()}
    need = ["pe_info", "get_halted_state", "pe_functions", "recover_struct", "pe_imports", "pe_exports", "pe_tls_callbacks", "va_to_rva", "rva_to_va", "rebase_address", "export_names", "export_structures",
            "import_names", "rtti_scan_module", "find_string_refs", "find_xrefs", "find_code_caves", "find_pointer_path", "snapshot_region", "list_snapshots",
            "delete_snapshot", "diff_snapshots", "compare_pointer_paths", "list_pointer_sets", "get_pointer_set", "drop_pointer_set", "list_patches", "undo_patch", "drop_patches"]
    check("all new tools registered with MCP", all(n in tools for n in need), [n for n in need if n not in tools])


    def _titles(node, path=""):
        if isinstance(node, dict):
            found = [path] if isinstance(node.get("title"), str) else []
            for k, v in node.items():
                found += _titles(v, path + "/" + k)
            return found
        if isinstance(node, list):
            return [p for i, v in enumerate(node) for p in _titles(v, "%s/%d" % (path, i))]
        return []


    with_titles = {n: _titles(t.parameters) for n, t in tools.items() if _titles(t.parameters)}
    check("tool schemas carry no generated titles", not with_titles, dict(list(with_titles.items())[:3]))
    fw = tools["find_window"].parameters["properties"]
    check("a parameter called title is kept", "title" in fw and "class_name" in fw, fw)
    with_output = sorted(n for n, t in tools.items() if t.output_schema is not None)
    check("no tool declares an output schema (results are not sent twice)", not with_output, with_output[:5])


    def _indented(desc):        # every continuation line still carries the docstring's source indentation
        rest = [l for l in (desc or "").splitlines()[1:] if l.strip()]
        return bool(rest) and all(l.startswith("    ") for l in rest)


    indented = sorted(n for n, t in tools.items() if _indented(t.description))
    check("descriptions are dedented", not indented, indented[:5])
    check("schemas keep types and defaults", tools["drop_patches"].parameters["properties"]["which"] == {"default": "inactive", "type": "string"},
          tools["drop_patches"].parameters["properties"]["which"])
    check("diff_snapshots schema", tools["diff_snapshots"].parameters["properties"]["snapshots"]["type"] == "array", tools["diff_snapshots"].parameters)
    check("find_xrefs requires address", tools["find_xrefs"].parameters.get("required") == ["address"], tools["find_xrefs"].parameters.get("required"))
    check("compare_pointer_paths requires only target", tools["compare_pointer_paths"].parameters.get("required") == ["target"], tools["compare_pointer_paths"].parameters.get("required"))
    check("compare_pointer_paths chains schema is a list", tools["compare_pointer_paths"].parameters["properties"]["chains"].get("anyOf") is not None
          or tools["compare_pointer_paths"].parameters["properties"]["chains"].get("type") == "array", tools["compare_pointer_paths"].parameters["properties"]["chains"])
    check("find_pointer_path requires address", tools["find_pointer_path"].parameters.get("required") == ["address"], tools["find_pointer_path"].parameters.get("required"))

    stop = True



def test_batch_gate(mod, monkeypatch):
    """A batch runs inside the bridge, past the per-tool registration: every request is judged as the tool it stands for."""
    out = json.loads(mod.batch_commands([{"method": "batch"}, {"nomethod": 1}]))
    assert out["error_code"] == "INVALID_PARAMS" and "nested" in out["error"] and "needs a 'method'" in out["error"]

    ok = [{"method": "read_integer", "params": {"address": "0x1"}}, {"method": "get_process_info"}, {"method": "read_bytes", "params": {}}]
    assert json.loads(mod.batch_commands(ok))["success"] is True
    assert mod.params_seen["batch"]["stop_on_error"] is False

    mod.params_seen.pop("batch")
    out = json.loads(mod.batch_commands([{"method": "no_such_method"}]))
    assert out["error_code"] == "PERMISSION_DENIED" and "not a tool of this server" in out["error"]
    assert "batch" not in mod.params_seen, "a refused batch must not reach the bridge"

    monkeypatch.setattr(mod, "ALLOWED_ACCESS", {"read", "analysis"})            # CE_MCP_PROFILE=readonly
    out = json.loads(mod.batch_commands([{"method": "read_integer"}, {"method": "write_memory", "params": {}}]))
    assert out["error_code"] == "PERMISSION_DENIED" and "requests[1]" in out["error"] and "disabled_by_profile" in out["error"]
    assert "requests[0]" not in out["error"]
    out = json.loads(mod.batch_commands([{"method": "set_write_breakpoint"}]))     # dispatcher alias of set_data_breakpoint (a write)
    assert out["error_code"] == "PERMISSION_DENIED"
    assert json.loads(mod.batch_commands([{"method": "read_integer"}, {"method": "read_struct"}]))["success"] is True
    monkeypatch.setattr(mod, "ALLOWED_ACCESS", {"read", "analysis", "write", "exec"})

    monkeypatch.setattr(mod, "ENABLED_TOOLSETS", {"process", "memory"})            # CE_MCP_TOOLSETS=memory
    out = json.loads(mod.batch_commands([{"method": "read_integer"}, {"method": "disassemble"}]))
    assert out["error_code"] == "PERMISSION_DENIED" and "disabled_by_toolsets" in out["error"]
