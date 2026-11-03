"""Shared fixtures for the offline test suite (no Cheat Engine required).

Run from the repo root:  python -m pytest MCP_Server/tests
"""
import json
import os
import struct
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SERVER_DIR = HERE.parent
BRIDGE_LUA = SERVER_DIR / "ce_mcp_bridge.lua"

# mcp_cheatengine picks its transport at import time; the named-pipe client
# needs pywin32, so the offline suite always talks TCP.
os.environ.setdefault("CE_MCP_TRANSPORT", "tcp")
sys.path.insert(0, str(SERVER_DIR))


def frame(body: bytes) -> bytes:
    return struct.pack("<I", len(body)) + body


class Bridge:
    """ce_mcp_bridge.lua loaded into Lua 5.3 (CE's version) with ce_stub.lua."""

    def __init__(self):
        lupa = pytest.importorskip("lupa")
        self.L = lupa.lua53.LuaRuntime(encoding=None)
        self.L.execute((HERE / "ce_stub.lua").read_bytes())
        src = BRIDGE_LUA.read_bytes()
        hook = b"\n-- Auto-start\nStartMCPBridge()"
        assert hook in src, "auto-start marker moved; update conftest.Bridge"
        src = src.replace(hook, b"\n_TEST = { json = json, exec = executeCommand, serve = serveOneRequest }\n")
        self.L.execute(src)
        self.G = self.L.globals()
        t = self.G[b"_TEST"]
        self.json, self.exec, self.serve = t[b"json"], t[b"exec"], t[b"serve"]

    def call(self, method, **params):
        req = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 7},
                         ensure_ascii=False).encode()
        return json.loads(self.exec(req).decode("utf-8"))

    def result(self, method, **params):
        return self.call(method, **params)["result"]

    def lua_table(self, values):
        return self.L.table(*values)


@pytest.fixture
def bridge():
    return Bridge()
