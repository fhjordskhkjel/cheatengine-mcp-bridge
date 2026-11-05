"""mcp_cheatengine.py as a real MCP stdio server, backed by the fake bridge."""
import json
import os
import subprocess
import sys
import time

import pytest

from conftest import SERVER_DIR
from fake_bridge import FakeBridge

pytest.importorskip("mcp.server.fastmcp")


class Server:
    def __init__(self, port, **env):
        full_env = dict(os.environ, CE_MCP_TRANSPORT="tcp", CE_MCP_PORT=str(port), CE_MCP_TIMEOUT="10", **env)
        self.p = subprocess.Popen([sys.executable, str(SERVER_DIR / "mcp_cheatengine.py")],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  env=full_env)
        self.request(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "pytest", "version": "1"}})
        self.read_until({1})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def send(self, obj):
        self.p.stdin.write((json.dumps(obj) + "\n").encode())
        self.p.stdin.flush()

    def request(self, rid, method, params=None):
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})

    def read_until(self, ids):
        """Read responses until every id in ids arrived; returns (order, by_id)."""
        order, by_id = [], {}
        while not ids <= set(by_id):
            line = self.p.stdout.readline()
            assert line, "server exited"
            msg = json.loads(line)
            if "id" in msg:
                order.append(msg["id"])
                by_id[msg["id"]] = msg
        return order, by_id

    def tools(self):
        self.request(2, "tools/list")
        return self.read_until({2})[1][2]["result"]["tools"]

    def call(self, rid, name, args=None):
        self.request(rid, "tools/call", {"name": name, "arguments": args or {}})

    def close(self):
        self.p.kill()
        self.p.wait()


@pytest.fixture
def fake():
    fb = FakeBridge()
    yield fb
    fb.close()


def test_all_toolsets_by_default(fake):
    s = Server(fake.port)
    try:
        names = {t["name"] for t in s.tools()}
        assert len(names) == 214 and {"list_toolsets", "ping", "set_breakpoint"} <= names
    finally:
        s.close()


def test_core_preset(fake):
    """CE_MCP_TOOLSETS=core registers the preset's tools plus the process toolset; presets and toolsets combine."""
    import mcp_cheatengine as m
    s = Server(fake.port, CE_MCP_TOOLSETS="core")
    try:
        names = {t["name"] for t in s.tools()}
        expected = set(m.TOOL_PRESETS["core"]["tools"]) | {n for n, g in m.TOOL_TOOLSET.items() if g == "process"}
        assert names == expected and len(names) < len(m.TOOL_TOOLSET) // 3
        s.call(3, "list_toolsets")
        info = json.loads(s.read_until({3})[1][3]["result"]["content"][0]["text"])
        assert info["enabled"] == ["process"] and info["enabled_presets"] == ["core"]
        assert info["presets"]["core"]["enabled"] is True and "disassemble" in info["presets"]["core"]["tools"]
        status = info["toolsets"]["analysis"]["tool_status"]
        assert status["disassemble"]["status"] == "enabled" and status["get_instruction_info"]["status"] == "disabled_by_toolsets"
        assert "core" in info["how_to_enable"]
    finally:
        s.close()
    s = Server(fake.port, CE_MCP_TOOLSETS="core,kernel")
    try:
        names = {t["name"] for t in s.tools()}
        assert "disassemble" in names and "map_memory" in names and "get_instruction_info" not in names
    finally:
        s.close()


def test_toolset_filter(fake):
    s = Server(fake.port, CE_MCP_TOOLSETS="memory")
    try:
        names = {t["name"] for t in s.tools()}
        assert "read_memory" in names and "ping" in names and "list_toolsets" in names
        assert "set_breakpoint" not in names and "evaluate_lua" not in names
        s.call(3, "list_toolsets")
        info = json.loads(s.read_until({3})[1][3]["result"]["content"][0]["text"])
        assert info["enabled"] == ["memory", "process"]
        assert info["toolsets"]["debug"]["enabled"] is False
        assert "set_breakpoint" in info["toolsets"]["debug"]["tools"]
    finally:
        s.close()


def test_slow_tool_does_not_block_event_loop(fake):
    fake.slow_methods["scan_all"] = 2.0
    s = Server(fake.port)
    try:
        t0 = time.time()
        s.call(3, "scan_all", {"value": "100"})
        time.sleep(0.2)
        s.request(4, "ping")              # MCP protocol ping, handled by the server loop
        s.call(5, "list_toolsets")        # Python-only tool
        order, by_id = s.read_until({3, 4, 5})
        assert order.index(4) < order.index(3) and order.index(5) < order.index(3), order
        assert time.time() - t0 >= 2.0
        assert json.loads(by_id[3]["result"]["content"][0]["text"])["method"] == "scan_all"
    finally:
        s.close()


def test_unicode_tool_call(fake):
    s = Server(fake.port)
    try:
        s.call(3, "write_string", {"address": "0x1000", "value": "日本 é"})
        text = s.read_until({3})[1][3]["result"]["content"][0]["text"]
        assert json.loads(text)["echo"]["value"] == "日本 é"
    finally:
        s.close()
