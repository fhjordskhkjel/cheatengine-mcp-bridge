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
BRIDGE_LUA = SERVER_DIR / "ce_mcp_bridge.lua"   # the loader
BRIDGE_MODULES = sorted((SERVER_DIR / "bridge").glob("*.lua"))

# mcp_cheatengine picks its transport at import time; the named-pipe client
# needs pywin32, so the offline suite always talks TCP.
os.environ.setdefault("CE_MCP_TRANSPORT", "tcp")
sys.path.insert(0, str(SERVER_DIR))


def frame(body: bytes) -> bytes:
    return struct.pack("<I", len(body)) + body


class Bridge:
    """The bridge (loader + bridge/*.lua) loaded into Lua 5.3 (CE's version) with ce_stub.lua."""

    def __init__(self, prelude=b""):
        lupa = pytest.importorskip("lupa")
        self.L = lupa.lua53.LuaRuntime(encoding=None)
        self.L.execute((HERE / "ce_stub.lua").read_bytes())
        if prelude:
            self.L.execute(prelude)  # runs before the bridge loads, like a CE user's setup
        # Load through the real loader, exactly as Cheat Engine does with dofile().
        self.B = self.L.eval(b"dofile")(str(BRIDGE_LUA).encode())
        self.G = self.L.globals()
        self.json, self.exec, self.serve = self.B[b"json"], self.B[b"executeCommand"], self.B[b"serveOneRequest"]

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
