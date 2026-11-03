"""A fake CE bridge speaking the length-prefixed JSON-RPC protocol over TCP.

Methods it understands (anything else is echoed back as a success result):
  slow             sleeps params["secs"] (default 2) before replying
  close_after_read reads the request, then closes without replying
  bad_json         replies with a malformed body
  wrong_id         replies with a different id
  rpc_error        replies with a JSON-RPC -32601 error
"""
import collections
import json
import socket
import struct
import threading
import time


def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _frame(obj):
    body = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode()
    return struct.pack("<I", len(body)) + body


class FakeBridge:
    def __init__(self):
        self.execs = collections.Counter()
        self.close_idle_after_reply = False
        self.slow_methods = {}  # method -> seconds to sleep before replying
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def close(self):
        self.sock.close()

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        with conn:
            while True:
                try:
                    header = _recv_exact(conn, 4)
                except OSError:  # client reset the connection (e.g. killed server process)
                    return
                if header is None:
                    return
                req = json.loads(_recv_exact(conn, struct.unpack("<I", header)[0]).decode("utf-8"))
                method, rid, params = req["method"], req["id"], req.get("params") or {}
                self.execs[method] += 1
                if method == "slow":
                    time.sleep(params.get("secs", 2))
                elif method in self.slow_methods:
                    time.sleep(self.slow_methods[method])
                if method == "close_after_read":
                    return
                if method == "bad_json":
                    conn.sendall(_frame(b"{nope"))
                    continue
                if method == "wrong_id":
                    rid += 1000
                if method == "rpc_error":
                    conn.sendall(_frame({"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found: x"}, "id": rid}))
                    continue
                try:
                    conn.sendall(_frame({"jsonrpc": "2.0", "result": {"success": True, "method": method, "echo": params}, "id": rid}))
                except OSError:
                    return
                if self.close_idle_after_reply:
                    return
