#!/usr/bin/env python3
r"""TCP-to-named-pipe relay for the Cheat Engine MCP bridge.

Run this script on Windows while ``ce_mcp_bridge.lua`` is loaded in Cheat
Engine. It accepts the same length-prefixed JSON-RPC frames used by
``mcp_cheatengine.py`` and forwards them to ``\\.\pipe\CE_MCP_Bridge_v99``.

Use this when the MCP server cannot open the Windows named pipe directly, such
as from WSL, a container, or another host.

Bind to 127.0.0.1 unless you intentionally want to expose Cheat Engine control
to another machine.
"""

from __future__ import annotations

import argparse
import json
import socket
import socketserver
import struct
import sys
import time
from typing import Optional

try:
    import pywintypes
    import win32file
    import win32pipe
except ImportError as exc:  # pragma: no cover - Windows-only helper
    print("ce_tcp_relay.py must run on Windows with pywin32 installed.", file=sys.stderr)
    raise SystemExit(1) from exc


PIPE_NAME = r"\\.\pipe\CE_MCP_Bridge_v99"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9876
MAX_FRAME_SIZE_BYTES = 32 * 1024 * 1024


def read_socket_exact(sock: socket.socket, size: int) -> Optional[bytes]:
    """Read exactly size bytes, returning None on clean peer disconnect."""
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            if remaining == size:
                return None
            raise ConnectionError("TCP client disconnected mid-frame.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_pipe_exact(handle, size: int) -> bytes:
    """Read exactly size bytes from a Windows named pipe."""
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = win32file.ReadFile(handle, remaining)[1]
        if not chunk:
            raise ConnectionError("Cheat Engine pipe closed mid-frame.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def validate_frame_size(size: int, direction: str) -> None:
    if size > MAX_FRAME_SIZE_BYTES:
        raise ConnectionError(
            f"{direction} frame too large: {size} bytes "
            f"(max {MAX_FRAME_SIZE_BYTES} bytes)."
        )


ERROR_FILE_NOT_FOUND = 2
ERROR_PIPE_BUSY = 231
PIPE_BUSY_WAIT_MS = 5000


def open_pipe():
    """Open the CE pipe, waiting briefly if it is busy or being recreated."""
    for attempt in range(10):
        try:
            return win32file.CreateFile(
                PIPE_NAME,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None,
            )
        except pywintypes.error as exc:
            code = exc.args[0] if exc.args else None
            if code == ERROR_PIPE_BUSY and attempt == 0:
                try:
                    win32pipe.WaitNamedPipe(PIPE_NAME, PIPE_BUSY_WAIT_MS)
                except pywintypes.error:
                    pass
                continue
            if code == ERROR_FILE_NOT_FOUND and attempt < 9:
                time.sleep(0.05)  # Lua worker recreates the pipe ~50 ms after a disconnect
                continue
            raise


def error_frame(req_body: bytes, code: int, message: str) -> bytes:
    """Build a JSON-RPC error response frame for the request in req_body."""
    try:
        req_id = json.loads(req_body.decode("utf-8", errors="replace")).get("id")
    except (ValueError, AttributeError):
        req_id = None
    body = json.dumps(
        {"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": req_id},
        ensure_ascii=False,
    ).encode("utf-8")
    return struct.pack("<I", len(body)) + body


class RelayHandler(socketserver.BaseRequestHandler):
    """Relay one TCP client connection to the CE pipe.

    The pipe is opened lazily per request and reopened after failures, and
    pipe-side failures are reported to the client as JSON-RPC error frames
    instead of dropping the TCP connection. That keeps the client's retry
    rule intact: a request is resent to CE only if it was never written to
    the pipe; once written, a failure is reported, never retried.
    """

    pipe_handle = None

    def setup(self) -> None:
        self.pipe_handle = None
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _forward(self, req_header: bytes, req_body: bytes) -> bytes:
        """Send one request to CE and return the response frame (or an error frame)."""
        for attempt in range(2):
            if self.pipe_handle is None:
                try:
                    self.pipe_handle = open_pipe()
                except pywintypes.error as exc:
                    code = exc.args[0] if exc.args else None
                    if code == ERROR_PIPE_BUSY:
                        msg = ("Cheat Engine bridge is busy (most likely still executing an "
                               "earlier command that timed out). Request not sent.")
                    else:
                        msg = (f"Cheat Engine pipe {PIPE_NAME} is not available ({exc}). Is "
                               "ce_mcp_bridge.lua loaded? Request not sent.")
                    return error_frame(req_body, -32000, msg)
            try:
                win32file.WriteFile(self.pipe_handle, req_header + req_body)
            except pywintypes.error:
                # Stale pipe (e.g. bridge script reloaded): nothing reached CE.
                self._close_pipe()
                continue
            try:
                resp_header = read_pipe_exact(self.pipe_handle, 4)
                resp_len = struct.unpack("<I", resp_header)[0]
                validate_frame_size(resp_len, "response")
                resp_body = read_pipe_exact(self.pipe_handle, resp_len)
                return resp_header + resp_body
            except (pywintypes.error, ConnectionError) as exc:
                self._close_pipe()
                return error_frame(
                    req_body, -32000,
                    f"Connection to Cheat Engine lost after the request was sent ({exc}). "
                    "The command may or may not have run; it was not retried.",
                )
        return error_frame(req_body, -32000, "Could not write the request to the Cheat Engine pipe. Request not sent.")

    def handle(self) -> None:
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[relay] TCP client connected: {peer}", file=sys.stderr, flush=True)
        try:
            while True:
                req_header = read_socket_exact(self.request, 4)
                if req_header is None:
                    break
                req_len = struct.unpack("<I", req_header)[0]
                validate_frame_size(req_len, "request")
                req_body = read_socket_exact(self.request, req_len)
                if req_body is None:
                    raise ConnectionError("TCP client disconnected before request body.")
                self.request.sendall(self._forward(req_header, req_body))
        except (ConnectionError, OSError) as exc:
            print(f"[relay] Connection ended for {peer}: {exc}", file=sys.stderr, flush=True)
        finally:
            self._close_pipe()
            print(f"[relay] TCP client disconnected: {peer}", file=sys.stderr, flush=True)

    def _close_pipe(self) -> None:
        if self.pipe_handle is None:
            return
        try:
            win32file.CloseHandle(self.pipe_handle)
        except pywintypes.error:
            pass
        finally:
            self.pipe_handle = None


class RelayServer(socketserver.TCPServer):
    allow_reuse_address = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Relay TCP frames to the Cheat Engine MCP Windows named pipe."
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"TCP bind host (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"TCP bind port (default: {DEFAULT_PORT})")
    parser.add_argument("--pipe", default=PIPE_NAME, help=f"Named pipe path (default: {PIPE_NAME})")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 1 <= args.port <= 65535:
        print("--port must be between 1 and 65535.", file=sys.stderr)
        return 2

    global PIPE_NAME
    PIPE_NAME = args.pipe

    print(
        f"[relay] Listening on {args.host}:{args.port}; forwarding to {PIPE_NAME}",
        file=sys.stderr,
        flush=True,
    )
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print(
            "[relay] WARNING: non-loopback bind exposes Cheat Engine control to the network.",
            file=sys.stderr,
            flush=True,
        )

    with RelayServer((args.host, args.port), RelayHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[relay] Stopping.", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
