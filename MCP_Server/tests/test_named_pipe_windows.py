"""CENamedPipeBridgeClient against a real Windows named pipe (Windows only).

The fake server mirrors the Lua worker: one pipe instance at a time
(maxInstances=1), recreated ~50 ms after each client disconnects.
"""
import collections
import json
import os
import struct
import sys
import threading
import time

import pytest

if sys.platform != "win32":
    pytest.skip("named pipes are Windows-only", allow_module_level=True)

pywintypes = pytest.importorskip("pywintypes")
win32file = pytest.importorskip("win32file")
win32pipe = pytest.importorskip("win32pipe")
pytest.importorskip("mcp")
import mcp_cheatengine as m  # noqa: E402


class PipeServer:
    def __init__(self, name):
        self.name = name
        self.execs = collections.Counter()
        self.slow = {}                 # method -> seconds
        self.drop_after_reply = False  # simulate a bridge reload after each reply
        self.stopped = False
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                win32pipe.WaitNamedPipe(self.name, 100)
                return
            except pywintypes.error:
                time.sleep(0.02)
        raise RuntimeError("fake pipe server did not start")

    def stop(self):
        self.stopped = True
        try:  # unblock ConnectNamedPipe
            h = win32file.CreateFile(self.name, win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                     0, None, win32file.OPEN_EXISTING, 0, None)
            win32file.CloseHandle(h)
        except pywintypes.error:
            pass
        self.thread.join(5)

    def _read_exact(self, h, n):
        buf = b""
        while len(buf) < n:
            buf += win32file.ReadFile(h, n - len(buf))[1]
        return buf

    def _loop(self):
        while not self.stopped:
            h = win32pipe.CreateNamedPipe(
                self.name, win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                1, 65536, 65536, 0, None)
            try:
                try:
                    win32pipe.ConnectNamedPipe(h, None)
                except pywintypes.error as exc:
                    if exc.args[0] != 535:  # ERROR_PIPE_CONNECTED
                        raise
                while not self.stopped:
                    n = struct.unpack("<I", self._read_exact(h, 4))[0]
                    req = json.loads(self._read_exact(h, n))
                    self.execs[req["method"]] += 1
                    time.sleep(self.slow.get(req["method"], 0))
                    body = json.dumps({"jsonrpc": "2.0", "result": {"success": True, "method": req["method"]},
                                       "id": req["id"]}).encode()
                    win32file.WriteFile(h, struct.pack("<I", len(body)) + body)
                    if self.drop_after_reply:
                        # DisconnectNamedPipe discards unread data, so wait until
                        # the client has read the reply. This models a reload
                        # *between* calls, which is when the real bridge drops.
                        win32file.FlushFileBuffers(h)
                        break
            except pywintypes.error:
                pass  # client went away
            finally:
                try:
                    win32pipe.DisconnectNamedPipe(h)
                except pywintypes.error:
                    pass
                win32file.CloseHandle(h)
            time.sleep(0.05)  # same recreate gap as the Lua worker


@pytest.fixture
def pipe_name(monkeypatch):
    name = rf"\\.\pipe\CE_MCP_Test_{os.getpid()}_{time.monotonic_ns()}"
    monkeypatch.setattr(m, "PIPE_NAME", name)
    return name


@pytest.fixture
def server(pipe_name):
    s = PipeServer(pipe_name)
    yield s
    s.stop()


@pytest.fixture
def client():
    c = m.CENamedPipeBridgeClient()
    c.timeout_seconds = 1.0
    yield c
    c.close()


def test_round_trip(server, client):
    assert client.send_command("echo")["method"] == "echo"


def test_missing_pipe_message(pipe_name, client):
    t0 = time.time()
    with pytest.raises(ConnectionError, match="does not exist"):
        client.send_command("echo")
    assert time.time() - t0 < 3


def test_reload_between_calls_resends_once(server, client):
    server.drop_after_reply = True
    client.send_command("warmup")
    server.execs.clear()
    assert client.send_command("count")["success"]  # stale handle -> write fails -> reconnect
    assert server.execs["count"] == 1


def test_busy_pipe_message_then_recovers(server, client, pipe_name):
    holder = win32file.CreateFile(pipe_name, win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                  0, None, win32file.OPEN_EXISTING, 0, None)
    try:
        with pytest.raises(ConnectionError, match="is busy"):
            client.send_command("echo")
    finally:
        win32file.CloseHandle(holder)
    assert client.send_command("echo")["success"]


def test_timeout_not_retried_and_recovers(server, client):
    server.slow["slow"] = 2.0
    with pytest.raises(TimeoutError, match="not retried"):
        client.send_command("slow")
    assert server.execs["slow"] == 1
    client.timeout_seconds = 5.0  # long enough to wait out the busy pipe
    assert client.send_command("echo")["success"]
    assert server.execs["slow"] == 1
