"""Access classes, CE_MCP_PROFILE, MCP tool annotations and the audit log."""
import json
import time

import pytest

pytest.importorskip("mcp.server.fastmcp")
import mcp_cheatengine as m  # noqa: E402

from fake_bridge import FakeBridge  # noqa: E402
from test_server_stdio import Server  # noqa: E402


# ---------------------------------------------------------------- classification

def test_every_tool_has_an_access_class():
    assert set(m.TOOL_ACCESS) == set(m.TOOL_TOOLSET)
    assert set(m.TOOL_ACCESS.values()) <= set(m.ACCESS_CLASSES)


@pytest.mark.parametrize("name", [
    "evaluate_lua", "auto_assemble", "auto_assemble_check", "compile_c_code", "compile_cs_code", "create_thread",
    "queue_to_main_thread", "inject_dll", "inject_dotnet_dll", "execute_code", "execute_code_ex",
    "execute_method", "execute_code_local", "execute_code_local_ex", "run_command", "shell_execute",
    "create_process", "load_table",
])
def test_code_execution_tools_are_exec(name):
    assert m.TOOL_ACCESS[name] == "exec"


@pytest.mark.parametrize("name", [
    "write_memory", "write_integer", "write_string", "set_memory_record_value", "allocate_memory",
    "set_memory_protection", "set_breakpoint", "set_data_breakpoint", "debug_process",
    "start_dbvm_watch", "write_process_memory_cr3", "delete_file", "key_down", "send_window_message",
])
def test_target_and_host_mutations_are_write(name):
    assert m.TOOL_ACCESS[name] == "write"


@pytest.mark.parametrize("raw,expected", [(None, "full"), ("", "full"), ("READONLY", "readonly"),
                                          (" standard ", "standard"), ("full", "full")])
def test_parse_profile(raw, expected):
    assert m._parse_profile(raw) == expected


def test_parse_profile_rejects_unknown():
    with pytest.raises(ValueError, match="CE_MCP_PROFILE"):
        m._parse_profile("paranoid")


# ---------------------------------------------------------------- over real stdio

@pytest.fixture
def fake():
    fb = FakeBridge()
    yield fb
    fb.close()


def _tools(fake, **env):
    s = Server(fake.port, **env)
    try:
        return {t["name"]: t for t in s.tools()}
    finally:
        s.close()


def test_readonly_profile_is_passive(fake):
    tools = _tools(fake, CE_MCP_PROFILE="readonly")
    classes = {m.TOOL_ACCESS[n] for n in tools}
    assert classes == {"read", "analysis"}
    assert {"read_memory", "scan_all", "disassemble", "open_process", "list_toolsets"} <= set(tools)
    assert not {"write_memory", "set_breakpoint", "evaluate_lua", "run_command"} & set(tools)


def test_standard_profile_drops_only_exec(fake):
    tools = _tools(fake, CE_MCP_PROFILE="standard")
    assert "write_memory" in tools and "set_breakpoint" in tools
    assert not {n for n, a in m.TOOL_ACCESS.items() if a == "exec"} & set(tools)


def test_annotations_follow_access_class(fake):
    tools = _tools(fake)
    assert tools["read_memory"]["annotations"]["readOnlyHint"] is True
    assert tools["scan_all"]["annotations"]["readOnlyHint"] is False
    assert tools["scan_all"]["annotations"]["destructiveHint"] is False
    assert tools["write_memory"]["annotations"]["destructiveHint"] is True
    assert tools["evaluate_lua"]["annotations"]["openWorldHint"] is True


def test_profile_and_toolsets_combine(fake):
    tools = _tools(fake, CE_MCP_PROFILE="readonly", CE_MCP_TOOLSETS="memory")
    assert "read_memory" in tools and "write_memory" not in tools and "scan_all" not in tools


def test_list_toolsets_explains_disabled_tools(fake):
    s = Server(fake.port, CE_MCP_PROFILE="readonly", CE_MCP_TOOLSETS="memory")
    try:
        s.call(3, "list_toolsets")
        info = json.loads(s.read_until({3})[1][3]["result"]["content"][0]["text"])
    finally:
        s.close()
    assert info["profile"] == "readonly" and info["allowed_access"] == ["read", "analysis"]
    status = info["toolsets"]["memory"]["tool_status"]
    assert status["read_memory"] == {"access": "read", "status": "enabled"}
    assert status["write_memory"] == {"access": "write", "status": "disabled_by_profile"}
    assert info["toolsets"]["scan"]["tool_status"]["scan_all"]["status"] == "disabled_by_toolsets"


# ---------------------------------------------------------------- audit log

@pytest.fixture
def audited(fake, tmp_path):
    c = m.CETcpBridgeClient("127.0.0.1", fake.port)
    c.timeout_seconds = 1.0
    path = tmp_path / "audit.jsonl"
    c.audit = m.AuditLog(str(path))

    def entries():
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    yield c, entries
    c.close()


def test_audit_records_success_failure_and_timeout(audited):
    client, entries = audited
    client.send_command("write_memory", {"address": "0x1000", "bytes": [144, 144]})
    client.send_command("rpc_error")
    with pytest.raises(TimeoutError):
        client.send_command("slow", {"secs": 2})
    log = entries()
    assert [e["method"] for e in log] == ["write_memory", "rpc_error", "slow"]
    assert log[0]["outcome"] == "ok" and log[0]["success"] is True
    assert log[0]["params"] == {"address": "0x1000", "bytes": [144, 144]}
    assert log[1]["outcome"] == "failed" and log[1]["error_code"] == "NOT_FOUND"
    assert log[2]["outcome"] == "timeout" and "timed out" in log[2]["error"]
    assert all(e["ts"].endswith("Z") and e["duration_ms"] >= 0 for e in log)
    assert log[2]["duration_ms"] >= 900


def test_audit_records_unreachable_bridge(tmp_path):
    c = m.CETcpBridgeClient("127.0.0.1", 1)
    path = tmp_path / "audit.jsonl"
    c.audit = m.AuditLog(str(path))
    with pytest.raises(ConnectionError):
        c.send_command("ping")
    entry = json.loads(path.read_text(encoding="utf-8"))
    assert entry["outcome"] == "transport_error" and "not reachable" in entry["error"]


def test_audit_bounds_large_params(audited):
    client, entries = audited
    client.send_command("write_memory", {"bytes": list(range(300)), "code": "x" * 20000})
    params = entries()[0]["params"]
    assert len(params["bytes"]) == 257 and params["bytes"][-1] == "...[+44 items]"
    assert params["code"].endswith("...[+3616 chars]") and len(params["code"]) < 17000


def test_audit_write_failure_does_not_break_tools(fake, tmp_path):
    c = m.CETcpBridgeClient("127.0.0.1", fake.port)
    c.audit = m.AuditLog(str(tmp_path / "missing-dir" / "audit.jsonl"))
    assert c.send_command("echo")["success"] is True
    c.close()


def test_blocked_shell_call_is_audited(fake, tmp_path):
    path = tmp_path / "audit.jsonl"
    s = Server(fake.port, CE_MCP_AUDIT_LOG=str(path), CE_MCP_ALLOW_SHELL="")
    try:
        s.call(3, "run_command", {"command": "whoami"})
        reply = json.loads(s.read_until({3})[1][3]["result"]["content"][0]["text"])
    finally:
        s.close()
    assert reply["error_code"] == "PERMISSION_DENIED"
    deadline = time.time() + 5
    while not path.exists() and time.time() < deadline:
        time.sleep(0.05)
    entry = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["method"] == "run_command" and entry["outcome"] == "blocked"
    assert entry["params"] == {"command": "whoami", "args": ""}
    assert fake.execs["run_command"] == 0  # never reached the bridge
