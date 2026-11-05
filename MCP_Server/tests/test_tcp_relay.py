"""ce_tcp_relay.py with pywin32 stubbed out and a fake CE pipe behind it."""
import importlib.util
import json
import socketserver
import struct
import sys
import threading
import types

import pytest

from conftest import SERVER_DIR

pytest.importorskip("mcp")
import mcp_cheatengine as m  # noqa: E402


class WinErr(Exception):
    def __init__(self, code, msg=""):
        super().__init__(code, "fn", msg)
        self.winerror = code


class FakePipeWorld:
    """State of the fake CE pipe the relay talks to."""

    def __init__(self):
        self.exists, self.busy, self.stale_writes, self.lose_after_send = True, False, 0, False
        self.execs = {}

    def modules(self):
        world = self
        pywintypes = types.ModuleType("pywintypes")
        pywintypes.error = WinErr

        class Handle:
            def __init__(self):
                self.out, self.lost = b"", False

        def CreateFile(name, *a):
            if not world.exists:
                raise WinErr(2, "not found")
            if world.busy:
                raise WinErr(231, "busy")
            return Handle()

        def WriteFile(h, data):
            if world.stale_writes > 0:
                world.stale_writes -= 1
                raise WinErr(232, "pipe is being closed")
            req = json.loads(data[4:].decode())
            world.execs[req["method"]] = world.execs.get(req["method"], 0) + 1
            if world.lose_after_send:
                h.lost = True
                return
            body = json.dumps({"jsonrpc": "2.0", "result": {"success": True, "m": req["method"]}, "id": req["id"]}).encode()
            h.out = struct.pack("<I", len(body)) + body

        def ReadFile(h, n):
            if h.lost:
                raise WinErr(109, "broken pipe")
            chunk, h.out = h.out[:n], h.out[n:]
            return (0, chunk)

        win32file = types.ModuleType("win32file")
        win32file.CreateFile, win32file.WriteFile, win32file.ReadFile = CreateFile, WriteFile, ReadFile
        win32file.CloseHandle = lambda h: None
        win32file.GENERIC_READ = win32file.GENERIC_WRITE = win32file.OPEN_EXISTING = 0
        win32pipe = types.ModuleType("win32pipe")

        def WaitNamedPipe(name, ms):
            raise WinErr(121, "timeout")
        win32pipe.WaitNamedPipe = WaitNamedPipe
        return {"pywintypes": pywintypes, "win32file": win32file, "win32pipe": win32pipe}


@pytest.fixture
def relay_client(monkeypatch):
    world = FakePipeWorld()
    for name, mod in world.modules().items():
        monkeypatch.setitem(sys.modules, name, mod)
    spec = importlib.util.spec_from_file_location("ce_tcp_relay_under_test", SERVER_DIR / "ce_tcp_relay.py")
    relay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(relay)
    relay.PIPE_BUSY_WAIT_MS = 10
    relay.time = types.SimpleNamespace(sleep=lambda s: None)  # skip the not-found back-off

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = Server(("127.0.0.1", 0), relay.RelayHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = m.CETcpBridgeClient("127.0.0.1", server.server_address[1])
    client.timeout_seconds = 2.0
    yield world, client
    client.close()
    server.shutdown()
    server.server_close()


def test_normal_request(relay_client):
    world, client = relay_client
    assert client.send_command("a") == {"success": True, "m": "a"}


def test_stale_pipe_reopened_and_sent_once(relay_client):
    world, client = relay_client
    world.stale_writes = 1
    assert client.send_command("b") == {"success": True, "m": "b"}
    assert world.execs["b"] == 1


def test_missing_pipe_reported_not_sent(relay_client):
    world, client = relay_client
    client.send_command("warmup")
    conn = client._conn
    world.stale_writes, world.exists = 1, False
    r = client.send_command("c")
    assert r["success"] is False and "not available" in r["error"] and "c" not in world.execs
    assert client._conn is conn  # TCP connection survives pipe-side errors


def test_busy_pipe_reported(relay_client):
    world, client = relay_client
    world.busy = True
    r = client.send_command("d")
    assert r["success"] is False and "busy" in r["error"] and "d" not in world.execs
    world.busy = False
    assert client.send_command("e")["success"]


def test_lost_after_send_reported_once(relay_client):
    world, client = relay_client
    world.lose_after_send = True
    r = client.send_command("f")
    assert r["success"] is False and "not retried" in r["error"] and world.execs["f"] == 1
    world.lose_after_send = False
    assert client.send_command("g")["success"]
