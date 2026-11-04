import sys
import os

# ============================================================================
# CRITICAL: WINDOWS LINE ENDING FIX FOR MCP (MONKEY-PATCH)
# The MCP SDK's stdio_server uses TextIOWrapper without newline='\n', causing
# Windows to output CRLF (\r\n) instead of LF (\n). This causes the error:
# "invalid trailing data at the end of stream"
# We MUST patch the MCP SDK BEFORE importing FastMCP.
# ============================================================================

if sys.platform == "win32":
    import msvcrt
    from io import TextIOWrapper
    from contextlib import asynccontextmanager
    
    # Set binary mode on underlying file handles. Skip streams without a real
    # descriptor (e.g. pytest's capture objects when this module is imported
    # as a library); the stdio server only ever runs on real handles.
    for _stream in (sys.stdin, sys.stdout):
        try:
            msvcrt.setmode(_stream.fileno(), os.O_BINARY)
        except (AttributeError, OSError, ValueError):  # io.UnsupportedOperation is OSError+ValueError
            pass
    
    # Monkey-patch the MCP SDK's stdio_server to use newline='\n'
    import mcp.server.stdio as mcp_stdio
    import anyio
    import anyio.lowlevel
    from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
    import mcp.types as types
    from mcp.shared.message import SessionMessage
    
    @asynccontextmanager
    async def _patched_stdio_server(
        stdin: "anyio.AsyncFile[str] | None" = None,
        stdout: "anyio.AsyncFile[str] | None" = None,
    ):
        """Patched stdio_server with proper Windows newline handling."""
        if not stdin:
            # Use newline='\n' to prevent CRLF translation on Windows
            stdin = anyio.wrap_file(TextIOWrapper(sys.stdin.buffer, encoding="utf-8", newline='\n'))
        if not stdout:
            # Use newline='\n' to prevent CRLF translation on Windows
            stdout = anyio.wrap_file(TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline='\n'))

        read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
        write_stream, write_stream_reader = anyio.create_memory_object_stream(0)

        async def stdin_reader():
            try:
                async with read_stream_writer:
                    async for line in stdin:
                        try:
                            message = types.JSONRPCMessage.model_validate_json(line)
                        except Exception as exc:
                            await read_stream_writer.send(exc)
                            continue
                        session_message = SessionMessage(message)
                        await read_stream_writer.send(session_message)
            except anyio.ClosedResourceError:
                await anyio.lowlevel.checkpoint()

        async def stdout_writer():
            try:
                async with write_stream_reader:
                    async for session_message in write_stream_reader:
                        json = session_message.message.model_dump_json(by_alias=True, exclude_none=True)
                        await stdout.write(json + "\n")
                        await stdout.flush()
            except anyio.ClosedResourceError:
                await anyio.lowlevel.checkpoint()

        async with anyio.create_task_group() as tg:
            tg.start_soon(stdin_reader)
            tg.start_soon(stdout_writer)
            yield read_stream, write_stream
    
    # Apply the monkey-patch
    mcp_stdio.stdio_server = _patched_stdio_server

# ============================================================================
# STDOUT PROTECTION FOR MCP
# MCP uses stdout for JSON-RPC. ANY stray output corrupts it.
# ============================================================================

# Save original stdout for MCP to use
_mcp_stdout = sys.stdout

# Redirect stdout to stderr so any accidental prints go to logs, not MCP stream
sys.stdout = sys.stderr

# Now safe to import libraries that might print during import
import functools
import itertools
import json
import select
import socket
import struct
import time
import math
import threading
import traceback

try:
    import anyio
    import anyio.to_thread
    from mcp.server.fastmcp import FastMCP
    from mcp.types import ToolAnnotations
    
    # CRITICAL: Also patch the reference inside the fastmcp module
    # FastMCP already imported stdio_server before our patch, so we need to update its reference too
    if sys.platform == "win32":
        import mcp.server.fastmcp.server as fastmcp_server
        fastmcp_server.stdio_server = _patched_stdio_server
        
except ImportError as e:
    print(f"[MCP CE] Import Error: {e}", file=sys.stderr, flush=True)
    sys.exit(1)

try:
    import win32file
    import pywintypes
except ImportError:
    win32file = None
    pywintypes = None

try:
    import win32pipe
except ImportError:
    win32pipe = None

# Restore stdout for MCP usage after imports are complete
sys.stdout = _mcp_stdout

# Debug helper - always goes to stderr, never corrupts MCP
def debug_log(msg):
    print(f"[MCP CE] {msg}", file=sys.stderr, flush=True)

# Helper to format results as proper JSON strings for MCP tools
def format_result(result):
    """Format CE Bridge result as a proper JSON string for AI consumption."""
    if isinstance(result, dict):
        return json.dumps(result, indent=None, ensure_ascii=False)
    elif isinstance(result, str):
        return result  # Already a string
    else:
        return json.dumps(result)

# ============================================================================
# CONFIGURATION
# ============================================================================

# Bridge wire protocol endpoint
PIPE_NAME = r"\\.\pipe\CE_MCP_Bridge_v99"
MCP_SERVER_NAME = "cheatengine"
MAX_RESPONSE_SIZE_BYTES = 32 * 1024 * 1024
DEFAULT_TCP_HOST = "127.0.0.1"
DEFAULT_TCP_PORT = 9876


def _parse_timeout_seconds(raw_value):
    """Parse CE_MCP_TIMEOUT seconds; <=0 disables timeout."""
    if raw_value is None:
        return 30.0
    try:
        timeout = float(raw_value)
    except (TypeError, ValueError):
        return 30.0
    if not math.isfinite(timeout):
        return 30.0
    if timeout <= 0:
        return None
    return timeout


CE_MCP_TIMEOUT_SECONDS = _parse_timeout_seconds(os.environ.get("CE_MCP_TIMEOUT"))


def _parse_transport(raw_value):
    """Parse CE_MCP_TRANSPORT; defaults to Windows named pipe."""
    transport = (raw_value or "pipe").strip().lower()
    aliases = {
        "named_pipe": "pipe",
        "named-pipe": "pipe",
        "np": "pipe",
        "socket": "tcp",
    }
    transport = aliases.get(transport, transport)
    if transport not in {"pipe", "tcp"}:
        raise ValueError("CE_MCP_TRANSPORT must be 'pipe' or 'tcp'.")
    return transport


def _parse_tcp_port(raw_value):
    """Parse CE_MCP_PORT as a TCP port number."""
    if raw_value is None or str(raw_value).strip() == "":
        return DEFAULT_TCP_PORT
    try:
        port = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("CE_MCP_PORT must be an integer TCP port.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("CE_MCP_PORT must be between 1 and 65535.")
    return port


CE_MCP_TRANSPORT = _parse_transport(os.environ.get("CE_MCP_TRANSPORT"))
CE_MCP_HOST = os.environ.get("CE_MCP_HOST", DEFAULT_TCP_HOST).strip() or DEFAULT_TCP_HOST
CE_MCP_PORT = _parse_tcp_port(os.environ.get("CE_MCP_PORT"))

# ============================================================================
# AUDIT LOG
# ============================================================================
# CE_MCP_AUDIT_LOG=<path> appends one JSON object per command to <path>: what
# was asked of Cheat Engine, when, how long it took and how it ended. It is
# the record of exactly what an agent did to the target (every write,
# injection and breakpoint), and it shows whether a command that timed out
# ran once. Writing is best-effort: if the file cannot be written, a warning
# goes to stderr once and tools keep working.

_AUDIT_MAX_STRING = 16 * 1024  # long enough to keep whole Lua / assembler scripts
_AUDIT_MAX_ITEMS = 256         # e.g. write_memory byte lists


def _audit_value(value, depth=0):
    """Copy a value for the audit log, bounding its size."""
    if isinstance(value, str):
        if len(value) > _AUDIT_MAX_STRING:
            return value[:_AUDIT_MAX_STRING] + f"...[+{len(value) - _AUDIT_MAX_STRING} chars]"
        return value
    if depth >= 6:
        return repr(value)[:200]
    if isinstance(value, dict):
        return {str(k): _audit_value(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        items = [_audit_value(v, depth + 1) for v in value[:_AUDIT_MAX_ITEMS]]
        if len(value) > _AUDIT_MAX_ITEMS:
            items.append(f"...[+{len(value) - _AUDIT_MAX_ITEMS} items]")
        return items
    return value


class AuditLog:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._fh = None
        self._warned = False

    def write(self, record):
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            try:
                if self._fh is None:
                    self._fh = open(self.path, "a", encoding="utf-8", buffering=1)
                self._fh.write(line + "\n")
            except OSError as exc:
                if not self._warned:
                    self._warned = True
                    debug_log(f"Audit log {self.path!r} not writable ({exc}); continuing without it.")

    def record(self, method, params, outcome, started, result=None, error=None):
        now = time.time()
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + f".{int(now * 1000) % 1000:03d}Z",
            "method": method,
            "params": _audit_value(params or {}),
            "outcome": outcome,
            "duration_ms": round((time.monotonic() - started) * 1000, 1),
        }
        if isinstance(result, dict):
            entry["success"] = result.get("success")
            if result.get("success") is False:
                entry["error_code"] = result.get("error_code")
                entry["error"] = _audit_value(str(result.get("error", "")))
        if error is not None:
            entry["error"] = _audit_value(str(error))
        self.write(entry)


_audit_path = os.environ.get("CE_MCP_AUDIT_LOG", "").strip()
AUDIT_LOG = AuditLog(_audit_path) if _audit_path else None

# ============================================================================
# BRIDGE CLIENTS
# ============================================================================

class BridgeError(ConnectionError):
    """Base class for bridge transport/protocol failures."""


class RequestNotSentError(BridgeError):
    """The request never reached Cheat Engine, so resending it is safe."""


class ProtocolError(BridgeError):
    """The response frame was malformed; the stream state is unknown."""


# JSON-RPC error code -> v12 error_code (see CLAUDE.md "Return shape").
_JSONRPC_ERROR_CODES = {
    -32700: "INVALID_PARAMS",    # parse error
    -32600: "INVALID_PARAMS",    # invalid request / frame
    -32601: "NOT_FOUND",         # method not found
    -32602: "INVALID_PARAMS",
    -32603: "INTERNAL_ERROR",
    -32001: "OUT_OF_RESOURCES",  # response too large
}


class CEBridgeClient:
    """Length-prefixed JSON-RPC client.

    Retry rule: a request is resent only when it provably never reached CE
    (connect failure, stale connection detected before sending, or a failed
    write). Once the request is on the wire, a failure or timeout is reported
    and NOT retried, because commands like auto_assemble, allocate_memory or
    write_memory are not idempotent and may already have run.

    Timeout rule: the exchange runs on a helper thread. On timeout the
    connection is detached (not closed under the blocked thread); the helper
    closes it once CE finally answers, so nothing is closed while another
    thread is blocked on it and a late response cannot reach a later request.
    """

    def __init__(self):
        self.timeout_seconds = CE_MCP_TIMEOUT_SECONDS
        self._conn = None
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self.last_connect_error = None
        self.audit = AUDIT_LOG

    # -- transport hooks -------------------------------------------------
    def _open(self):
        """Open and return a new connection object, or raise."""
        raise NotImplementedError

    def _close_conn(self, conn):
        raise NotImplementedError

    def _write(self, conn, data):
        raise NotImplementedError

    def _read_exact(self, conn, size):
        raise NotImplementedError

    def _is_stale(self, conn):
        """True if the connection is known to be dead before sending."""
        return False

    def _endpoint_description(self):
        return "Cheat Engine Bridge"

    def _unreachable_message(self):
        return f"{self._endpoint_description()} is not reachable."

    # -- connection management ------------------------------------------
    @property
    def connected(self):
        return self._conn is not None

    def connect(self):
        self.last_connect_error = None
        try:
            self._conn = self._open()
            return True
        except Exception as exc:
            self.last_connect_error = exc
            self._conn = None
            return False

    def close(self):
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                self._close_conn(conn)
            except Exception:
                pass

    # -- framing ---------------------------------------------------------
    def _decode_response(self, resp_header_buffer, resp_body_buffer):
        # The Lua encoder escapes non-UTF-8 bytes, but decode leniently anyway:
        # one bad byte must never cost the whole response.
        try:
            return json.loads(resp_body_buffer.decode('utf-8', errors='replace'))
        except ValueError as exc:
            raise ProtocolError("Invalid JSON received from CE") from exc

    def _exchange_once(self, conn, req_json):
        """Send one framed request and read one framed response."""
        header = struct.pack('<I', len(req_json))
        try:
            self._write(conn, header + req_json)
        except Exception as exc:
            raise RequestNotSentError(f"write failed: {exc}") from exc

        resp_header_buffer = self._read_exact(conn, 4)
        resp_len = struct.unpack('<I', resp_header_buffer)[0]
        if resp_len > MAX_RESPONSE_SIZE_BYTES:
            raise ProtocolError(f"Response too large: {resp_len} bytes")
        resp_body_buffer = self._read_exact(conn, resp_len)
        return self._decode_response(resp_header_buffer, resp_body_buffer)

    def _exchange_with_timeout(self, req_json, method):
        """Run one exchange, enforcing CE_MCP_TIMEOUT."""
        conn = self._conn
        timeout = self.timeout_seconds
        if timeout is None:
            return self._exchange_once(conn, req_json)

        state = {"finished": False, "abandoned": False}
        state_lock = threading.Lock()

        def _worker():
            try:
                state["response"] = self._exchange_once(conn, req_json)
            except BaseException as exc:
                state["error"] = exc
            finally:
                with state_lock:
                    state["finished"] = True
                    abandoned = state["abandoned"]
                if abandoned:
                    try:
                        self._close_conn(conn)
                    except Exception:
                        pass

        worker = threading.Thread(target=_worker, name=f"ce-mcp-{method}", daemon=True)
        worker.start()
        worker.join(timeout)

        with state_lock:
            if not state["finished"]:
                state["abandoned"] = True
        if state["abandoned"]:
            # Hand the connection to the worker; it closes it when CE answers.
            if self._conn is conn:
                self._conn = None
            raise TimeoutError(
                f"Command '{method}' timed out after {timeout:g}s (CE_MCP_TIMEOUT). "
                "It was sent and may still be running inside Cheat Engine; it was not "
                "retried. The bridge stays busy until it finishes."
            )

        if "error" in state:
            raise state["error"]
        return state["response"]

    # -- public API ------------------------------------------------------
    def send_command(self, method, params=None):
        """Send one command to the CE bridge.

        Raises ConnectionError / TimeoutError on transport failure; JSON-RPC
        errors come back as {"success": False, "error", "error_code"}.
        Every call is recorded in the audit log when CE_MCP_AUDIT_LOG is set.
        """
        if self.audit is None:
            return self._send_command_serialised(method, params)
        started = time.monotonic()
        try:
            result = self._send_command_serialised(method, params)
        except TimeoutError as exc:
            self.audit.record(method, params, "timeout", started, error=exc)
            raise
        except Exception as exc:
            self.audit.record(method, params, "transport_error", started, error=exc)
            raise
        failed = isinstance(result, dict) and result.get("success") is False
        self.audit.record(method, params, "failed" if failed else "ok", started, result=result)
        return result

    def _send_command_serialised(self, method, params):
        # Tools run in worker threads, so calls can arrive concurrently; CE has
        # one pipe, so they are serialised here. A call queued behind a slow
        # one gives up after CE_MCP_TIMEOUT rather than waiting forever.
        acquire_timeout = -1 if self.timeout_seconds is None else self.timeout_seconds
        if not self._lock.acquire(timeout=acquire_timeout):
            raise TimeoutError(
                f"Command '{method}' was not sent: the bridge was busy with another "
                f"command for {self.timeout_seconds:g}s (CE_MCP_TIMEOUT)."
            )
        try:
            return self._send_command_locked(method, params)
        finally:
            self._lock.release()

    def _send_command_locked(self, method, params):
        request_id = next(self._ids)
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": request_id,
        }
        # ensure_ascii=False: send raw UTF-8 rather than \uXXXX escapes.
        # errors='replace' guards against lone surrogates in tool input.
        req_json = json.dumps(request, ensure_ascii=False).encode('utf-8', errors='replace')

        last_error = None
        for _attempt in range(2):
            if self.connected and self._is_stale(self._conn):
                self.close()
            if not self.connected and not self.connect():
                raise ConnectionError(self._unreachable_message())

            try:
                response = self._exchange_with_timeout(req_json, method)
            except RequestNotSentError as exc:
                # Stale connection (e.g. bridge script reloaded): nothing
                # reached CE, so reconnecting and resending is safe.
                self.close()
                last_error = exc
                continue
            except TimeoutError as exc:
                if self._conn is not None:
                    # Raised by the transport itself rather than the CE_MCP_TIMEOUT
                    # guard: the stream state is unknown, so drop the connection.
                    self.close()
                    raise TimeoutError(
                        f"Command '{method}' timed out ({exc}); it was sent and was not retried."
                    ) from exc
                raise
            except ProtocolError as exc:
                self.close()
                raise ConnectionError(
                    f"Protocol error on '{method}': {exc}. The command ran in CE but its "
                    "response could not be read; it was not retried."
                ) from exc
            except (OSError, ConnectionError) as exc:
                self.close()
                raise ConnectionError(
                    f"Connection to {self._endpoint_description()} lost after '{method}' was "
                    f"sent: {exc}. The command may or may not have run in Cheat Engine; it "
                    "was not retried automatically."
                ) from exc

            return self._unwrap_response(response, request_id, method)

        raise ConnectionError(
            f"Could not deliver '{method}' to {self._endpoint_description()}: {last_error}"
        )

    def _unwrap_response(self, response, request_id, method):
        if not isinstance(response, dict):
            self.close()
            raise ConnectionError(f"Protocol error on '{method}': response is not a JSON object.")
        resp_id = response.get("id")
        if resp_id is not None and resp_id != request_id:
            self.close()
            raise ConnectionError(
                f"Protocol error on '{method}': response id {resp_id!r} does not match "
                f"request id {request_id!r} (stream out of sync); connection reset."
            )
        if 'error' in response:
            err = response['error']
            if isinstance(err, dict):
                code = err.get("code")
                message = err.get("message") or str(err)
            else:
                code, message = None, str(err)
            result = {
                "success": False,
                "error": message,
                "error_code": _JSONRPC_ERROR_CODES.get(code, "INTERNAL_ERROR"),
            }
            if code is not None:
                result["jsonrpc_code"] = code
            return result
        if 'result' in response:
            return response['result']
        return response


# Win32 error codes used when connecting to the pipe.
_ERROR_FILE_NOT_FOUND = 2
_ERROR_PIPE_BUSY = 231
# The Lua worker recreates the pipe ~50 ms after a client disconnects.
_PIPE_MISSING_WAIT_SECONDS = 0.5
# Upper bound on waiting for a busy pipe (CE still running a previous command).
_PIPE_BUSY_WAIT_SECONDS = 5.0


def _winerror(exc):
    code = getattr(exc, "winerror", None)
    if code is None and getattr(exc, "args", None):
        code = exc.args[0]
    return code


class CENamedPipeBridgeClient(CEBridgeClient):
    def __init__(self):
        super().__init__()
        if win32file is None or pywintypes is None:
            raise RuntimeError(
                "Named pipe transport requires Windows and pywin32. "
                "Set CE_MCP_TRANSPORT=tcp when the MCP server cannot open the Windows pipe directly."
            )

    def _open(self):
        """Open the pipe, waiting briefly while it is busy or being recreated."""
        start = time.monotonic()
        busy_budget = _PIPE_BUSY_WAIT_SECONDS
        if self.timeout_seconds is not None:
            busy_budget = min(busy_budget, self.timeout_seconds)
        missing_deadline = None
        while True:
            try:
                return win32file.CreateFile(
                    PIPE_NAME,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    0,
                    None
                )
            except pywintypes.error as exc:
                code = _winerror(exc)
                now = time.monotonic()
                elapsed = now - start
                if code == _ERROR_PIPE_BUSY and elapsed < busy_budget:
                    missing_deadline = None
                    wait_ms = max(1, int(min(1.0, busy_budget - elapsed) * 1000))
                    if win32pipe is not None:
                        try:
                            win32pipe.WaitNamedPipe(PIPE_NAME, wait_ms)
                        except pywintypes.error:
                            pass  # timed out or pipe vanished; loop re-checks
                    else:
                        time.sleep(wait_ms / 1000.0)
                    continue
                if code == _ERROR_FILE_NOT_FOUND:
                    # Covers the gap while the Lua worker recreates the pipe,
                    # including right after a busy wait ends.
                    if missing_deadline is None:
                        missing_deadline = now + _PIPE_MISSING_WAIT_SECONDS
                    if now < missing_deadline:
                        time.sleep(0.05)
                        continue
                raise

    def _close_conn(self, conn):
        win32file.CloseHandle(conn)

    def _write(self, conn, data):
        win32file.WriteFile(conn, data)

    def _read_exact(self, conn, size):
        chunks = []
        remaining = size
        while remaining > 0:
            try:
                chunk = win32file.ReadFile(conn, remaining)[1]
            except pywintypes.error as exc:
                raise ConnectionError(f"Pipe communication failed: {exc}") from exc
            if not chunk:
                raise ConnectionError("Connection closed while reading from CE pipe.")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _endpoint_description(self):
        return "Cheat Engine Bridge (v12/v99 pipe)"

    def _unreachable_message(self):
        err = self.last_connect_error
        code = _winerror(err) if err is not None else None
        if code == _ERROR_PIPE_BUSY:
            return (
                f"{self._endpoint_description()} is busy: Cheat Engine is most likely still "
                "executing an earlier command that timed out. Retry once it finishes, or "
                "raise CE_MCP_TIMEOUT for long operations."
            )
        if code == _ERROR_FILE_NOT_FOUND:
            return (
                f"{self._endpoint_description()} is not reachable: pipe {PIPE_NAME} does not "
                "exist. Is Cheat Engine running with ce_mcp_bridge.lua loaded?"
            )
        detail = f" ({err})" if err is not None else ""
        return f"{self._endpoint_description()} is not reachable{detail}."


class CETcpBridgeClient(CEBridgeClient):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port

    def _open(self):
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout_seconds)
        # The helper-thread join enforces CE_MCP_TIMEOUT; the socket timeout is
        # only a backstop, kept longer so the two never race.
        sock.settimeout(None if self.timeout_seconds is None else self.timeout_seconds + 5.0)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    def _close_conn(self, conn):
        conn.close()

    def _is_stale(self, conn):
        # A peer that has closed shows up as readable with EOF. Checking before
        # sending lets a dead connection be replaced without risking a resend
        # of a request that was already delivered.
        try:
            readable, _, _ = select.select([conn], [], [], 0)
            if not readable:
                return False
            return conn.recv(1, socket.MSG_PEEK) == b""
        except (OSError, ValueError):
            return True

    def _write(self, conn, data):
        conn.sendall(data)

    def _read_exact(self, conn, size):
        chunks = []
        remaining = size
        while remaining > 0:
            chunk = conn.recv(remaining)
            if not chunk:
                raise ConnectionError("Connection closed while reading from TCP relay.")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _endpoint_description(self):
        return f"Cheat Engine Bridge TCP relay ({self.host}:{self.port})"

    def _unreachable_message(self):
        err = self.last_connect_error
        detail = f": {err}" if err is not None else ""
        return f"{self._endpoint_description()} is not reachable{detail}. Is ce_tcp_relay.py running?"


def _create_bridge_client():
    if CE_MCP_TRANSPORT == "tcp":
        debug_log(f"Using TCP relay transport at {CE_MCP_HOST}:{CE_MCP_PORT}")
        return CETcpBridgeClient(CE_MCP_HOST, CE_MCP_PORT)
    debug_log("Using Windows named pipe transport")
    return CENamedPipeBridgeClient()


ce_client = _create_bridge_client()

# ============================================================================
# MCP SERVER - v12 IMPLEMENTATION
# ============================================================================

mcp = FastMCP(MCP_SERVER_NAME)

# ============================================================================
# TOOLSETS + OFF-LOOP EXECUTION
# ============================================================================
# Every tool belongs to one toolset. CE_MCP_TOOLSETS (comma-separated, default
# "all") picks which ones are registered, so a client only pays the context
# cost of the tool schemas it needs. "process" (attach/inspect + ping +
# list_toolsets) is always registered.
TOOLSETS = {
    "process":   "Attach to / list / inspect processes, modules and threads; ping.",
    "memory":    "Read/write memory, pointer chains, allocation, protection, memory ops.",
    "scan":      "Value scans, AOB scans, persistent and pointer scans, memory regions.",
    "analysis":  "Disassembly, function/reference analysis, structures, symbols.",
    "debug":     "Hardware breakpoints, debugger control, thread context.",
    "kernel":    "DBVM / DBK: physical memory, CR3 access, kernel allocation, watches.",
    "scripting": "Lua evaluation, auto-assembler, compilers, code injection/execution, CE threads.",
    "table":     "Cheat table (address list) records, load/save .CT.",
    "gui":       "Window messages, dialogs, mouse/keyboard input, screen, sound.",
    "system":    "Files, clipboard, shell (shell also needs CE_MCP_ALLOW_SHELL=1).",
}
ALWAYS_ON_TOOLSET = "process"


def _parse_toolsets(raw_value):
    """Parse CE_MCP_TOOLSETS; returns the set of enabled toolset names."""
    if raw_value is None or raw_value.strip() == "":
        return set(TOOLSETS)
    wanted = {part.strip().lower() for part in raw_value.split(",") if part.strip()}
    if "all" in wanted:
        return set(TOOLSETS)
    unknown = sorted(wanted - set(TOOLSETS))
    if unknown:
        raise ValueError(
            f"CE_MCP_TOOLSETS: unknown toolset(s) {', '.join(unknown)}. "
            f"Valid: all, {', '.join(TOOLSETS)}."
        )
    return wanted | {ALWAYS_ON_TOOLSET}


ENABLED_TOOLSETS = _parse_toolsets(os.environ.get("CE_MCP_TOOLSETS"))
TOOL_TOOLSET = {}  # tool name -> toolset, for every defined tool (enabled or not)

# Every tool also declares what it can change. The class drives both the MCP
# tool annotations (so clients can auto-approve reads and prompt on the rest)
# and CE_MCP_PROFILE (which classes get registered at all).
ACCESS_CLASSES = {
    "read":     "Pure read of the target, CE or the host; changes nothing.",
    "analysis": "Changes only CE's own analysis state (attached process, scan sessions, "
                "structures, registered symbols, hit buffers); never the target or the host.",
    "write":    "Modifies the target (memory, protection, allocations, threads, debugger and "
                "breakpoint state, DBVM/DBK state) or the host (files, clipboard, input, windows, "
                "sounds, dialogs).",
    "exec":     "Runs arbitrary code or loads programs/modules: Lua, the auto-assembler, "
                "compilers, injection, remote execution, the shell, cheat tables (which can "
                "carry scripts).",
}
PROFILES = {
    "readonly": ("read", "analysis"),           # passive: never touches the target or the host
    "standard": ("read", "analysis", "write"),  # everything except arbitrary code execution
    "full":     ("read", "analysis", "write", "exec"),
}
_ACCESS_ANNOTATIONS = {
    "read":     ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False),
    "analysis": ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False),
    "write":    ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False),
    "exec":     ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True),
}


def _parse_profile(raw_value):
    """Parse CE_MCP_PROFILE; defaults to 'full' (every access class)."""
    profile = (raw_value or "full").strip().lower() or "full"
    if profile not in PROFILES:
        raise ValueError(f"CE_MCP_PROFILE must be one of: {', '.join(PROFILES)} (got {raw_value!r}).")
    return profile


CE_MCP_PROFILE = _parse_profile(os.environ.get("CE_MCP_PROFILE"))
ALLOWED_ACCESS = set(PROFILES[CE_MCP_PROFILE])
TOOL_ACCESS = {}  # tool name -> access class, for every defined tool


def _run_off_event_loop(fn):
    """Wrap a blocking tool so it runs in a worker thread.

    FastMCP calls sync tools inline on its event loop, so one slow scan would
    stall pings, cancellations and every other request. Concurrent calls still
    reach CE one at a time (CEBridgeClient serialises them).
    """
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))
    return wrapper


def tool(toolset, access):
    """Register an MCP tool (replaces a bare @mcp.tool()).

    toolset: one of TOOLSETS. access: one of ACCESS_CLASSES; it sets the MCP
    annotations and decides whether CE_MCP_PROFILE registers the tool.
    """
    if toolset not in TOOLSETS:
        raise ValueError(f"unknown toolset {toolset!r}")
    if access not in ACCESS_CLASSES:
        raise ValueError(f"unknown access class {access!r}")

    def decorator(fn):
        TOOL_TOOLSET[fn.__name__] = toolset
        TOOL_ACCESS[fn.__name__] = access
        if toolset in ENABLED_TOOLSETS and access in ALLOWED_ACCESS:
            mcp.tool(annotations=_ACCESS_ANNOTATIONS[access])(_run_off_event_loop(fn))
        return fn
    return decorator


def _registration_status(name):
    if TOOL_TOOLSET[name] not in ENABLED_TOOLSETS:
        return "disabled_by_toolsets"
    if TOOL_ACCESS[name] not in ALLOWED_ACCESS:
        return "disabled_by_profile"
    return "enabled"


@tool("process", "read")
def list_toolsets() -> str:
    """List tool groups, the active profile, and which tools are registered.

    Tools are disabled either by CE_MCP_TOOLSETS (their group is off) or by
    CE_MCP_PROFILE (their access class is not allowed). Both are set in the MCP
    server's environment and need a restart to change.
    """
    groups = {}
    for name, group in TOOL_TOOLSET.items():
        groups.setdefault(group, []).append(name)
    return format_result({
        "success": True,
        "enabled": sorted(ENABLED_TOOLSETS),
        "profile": CE_MCP_PROFILE,
        "allowed_access": [a for a in ACCESS_CLASSES if a in ALLOWED_ACCESS],
        "access_classes": ACCESS_CLASSES,
        "toolsets": {
            group: {
                "enabled": group in ENABLED_TOOLSETS,
                "description": TOOLSETS[group],
                "tools": sorted(groups.get(group, [])),
                "tool_status": {
                    name: {"access": TOOL_ACCESS[name], "status": _registration_status(name)}
                    for name in sorted(groups.get(group, []))
                },
            }
            for group in TOOLSETS
        },
        "how_to_enable": (
            "Set CE_MCP_TOOLSETS (e.g. 'memory,scan,debug' or 'all') and/or CE_MCP_PROFILE "
            "(readonly | standard | full) in the MCP server config and restart it."
        ),
    })

# --- PROCESS & MODULES ---

@tool("process", "read")
def get_process_info() -> str:
    """Get current process ID, name, modules count and architecture."""
    return format_result(ce_client.send_command("get_process_info"))

@tool("process", "read")
def enum_modules(offset: int = 0, limit: int = 100) -> str:
    """List all loaded modules (DLLs) with their base addresses and sizes.

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum modules to return (default 100, max 10000).

    Returns JSON with: success, total, offset, limit, returned, modules.
    """
    return format_result(ce_client.send_command("enum_modules", {"offset": offset, "limit": limit}))

@tool("process", "read")
def get_thread_list(offset: int = 0, limit: int = 100) -> str:
    """Get list of threads in the attached process.

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum threads to return (default 100, max 10000).

    Returns JSON with: success, total, offset, limit, returned, threads.
    """
    return format_result(ce_client.send_command("get_thread_list", {"offset": offset, "limit": limit}))

@tool("process", "read")
def get_symbol_address(symbol: str) -> str:
    """Resolve a symbol name (e.g., 'Engine.GameEngine') to an address."""
    return format_result(ce_client.send_command("get_symbol_address", {"symbol": symbol}))

@tool("process", "read")
def get_address_info(address: str, include_modules: bool = True, include_symbols: bool = True, include_sections: bool = False) -> str:
    """Get symbolic name and module info for an address (Reverse of get_symbol_address)."""
    return format_result(ce_client.send_command("get_address_info", {
        "address": address, 
        "include_modules": include_modules, 
        "include_symbols": include_symbols,
        "include_sections": include_sections
    }))

@tool("process", "read")
def get_rtti_classname(address: str) -> str:
    """Try to identify the class name of an object at address using Run-Time Type Information."""
    return format_result(ce_client.send_command("get_rtti_classname", {"address": address}))

# --- MEMORY READING ---

@tool("memory", "read")
def read_memory(address: str, size: int = 256, format: str = "hex") -> str:
    """Read raw bytes from memory.

    Args:
        address: Address (hex string or symbol).
        size: Number of bytes (max 1 MB).
        format: 'hex' (default, "48 65 6C ..."), 'base64' (smallest for big reads),
                'array' (list of ints) or 'both' (hex + array; 3x the tokens, the wire default).
    """
    return format_result(ce_client.send_command("read_memory", {"address": address, "size": size, "format": format}))

@tool("memory", "read")
def read_integer(address: str, type: str = "dword") -> str:
    """Read a number from memory. Types: byte, word, dword, qword, float, double."""
    return format_result(ce_client.send_command("read_integer", {"address": address, "type": type}))

@tool("memory", "read")
def read_string(address: str, max_length: int = 256, wide: bool = False, encoding: str = "utf8") -> str:
    """Read a string from memory.

    Args:
        address: Memory address to read from.
        max_length: Maximum number of bytes to read.
        wide: Legacy flag — when True, overrides encoding to 'utf16le' for backward compat.
        encoding: One of 'ascii', 'utf8' (default), 'utf16le', or 'raw'.
                  'ascii': strip non-printable bytes.
                  'utf8': preserve valid UTF-8 multi-byte sequences.
                  'utf16le': read as wide (UTF-16 LE) string.
                  'raw': return bytes as a hex string (e.g. '48 65 6C 6C 6F').

    Returns JSON with: success, address, value, encoding, wide, length, raw_length.
    """
    # Backward compat: wide=True maps to utf16le unless caller also set encoding explicitly
    resolved_encoding = "utf16le" if wide else encoding
    return format_result(ce_client.send_command("read_string", {"address": address, "max_length": max_length, "wide": wide, "encoding": resolved_encoding}))

@tool("memory", "read")
def read_pointer(address: str, offsets: list[int] = None) -> str:
    """Read a pointer chain. Returns the final address and value."""
    # Bridge supports 'read_pointer' for single dereference or 'read_pointer_chain' for multiple
    if offsets:
        return format_result(ce_client.send_command("read_pointer_chain", {"base": address, "offsets": offsets}))
    else:
        return format_result(ce_client.send_command("read_pointer_chain", {"base": address, "offsets": [0]}))

@tool("memory", "read")
def read_pointer_chain(base: str, offsets: list[int]) -> str:
    """Follow a multi-level pointer chain and return analysis of every step."""
    return format_result(ce_client.send_command("read_pointer_chain", {"base": base, "offsets": offsets}))

@tool("memory", "read")
def analyze_pointer_access(instruction: str, registers: dict, accessed_address: str = None, is_64bit: bool = None) -> str:
    """Parse a captured memory access (instruction + register snapshot from a breakpoint/DBVM hit) into base register, displacement, and the concrete struct-base address for pointer-chain walk-back. Pure analysis; no process access. next_scan_value is the address to scan for (as a pointer) to find the next level up."""
    return format_result(ce_client.send_command("analyze_pointer_access", {
        "instruction": instruction,
        "registers": registers,
        "accessed_address": accessed_address,
        "is_64bit": is_64bit,
    }))

@tool("memory", "read")
def validate_pointer_chains(chains: list, target: str, include_misses: bool = False) -> str:
    """Resolve a list of candidate pointer chains and report which currently land on `target`. Each chain is {"base": <addr|symbol>, "offsets": [int,...]}. Returns only matches by default (token-frugal); set include_misses=true to also list non-matches. Re-run after a game restart with the new target to find chains that stay valid (the stable pointer). Max 5000 chains per call."""
    return format_result(ce_client.send_command("validate_pointer_chains", {
        "chains": chains,
        "target": target,
        "include_misses": include_misses,
    }))

@tool("memory", "read")
def checksum_memory(address: str, size: int) -> str:
    """Calculate MD5 checksum of a memory region to detect changes."""
    return format_result(ce_client.send_command("checksum_memory", {"address": address, "size": size}))

# --- SCANNING ---

@tool("scan", "analysis")
def scan_all(value: str = None, type: str = "dword", protection: str = "+W-C",
             scan_option: str = "exact", value2: str = None) -> str:
    """Unified Memory Scanner (first scan).

    Args:
        value: Value to search for. Omit when scan_option is 'unknown'.
        type: Value type: byte, word, dword, qword, float, double, string.
        protection: +W-C (Writable, Not Copy-on-Write).
        scan_option: exact, unknown, between, bigger, smaller.
        value2: Upper bound for 'between'.
            Alternatively pass both bounds in value as "min,max" (e.g. "0,1").
    """
    return format_result(ce_client.send_command("scan_all", {
        "value": value, "type": type, "protection": protection,
        "scan_option": scan_option, "value2": value2
    }))

@tool("scan", "read")
def get_scan_results(offset: int = 0, limit: int = 100, max: int = None) -> str:
    """Get results from the last 'scan_all' operation.

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum results to return (default 100, max 10000). Preferred over 'max'.
        max: Deprecated alias for 'limit'. Use 'limit' instead.

    Returns JSON with: success, total, offset, limit, returned, results.
    """
    return format_result(ce_client.send_command("get_scan_results", {"offset": offset, "limit": limit, "max": max}))

@tool("scan", "analysis")
def next_scan(value: str = None, scan_type: str = "exact", value2: str = None) -> str:
    """Next scan to filter results from the last 'scan_all'.

    Args:
        value: Value to compare against. Not needed for increased/decreased/changed/unchanged.
        scan_type: exact, between, bigger, smaller, increased, decreased, increased_by, decreased_by, changed, unchanged.
        value2: Upper bound for 'between'. Alternatively pass both bounds in value as "min,max" (e.g. "0,1").
    """
    return format_result(ce_client.send_command("next_scan", {
        "value": value, "scan_type": scan_type, "value2": value2
    }))

@tool("memory", "write")
def write_integer(address: str, value: int, type: str = "dword") -> str:
    """Write a number to memory. Types: byte, word, dword, qword, float, double."""
    return format_result(ce_client.send_command("write_integer", {"address": address, "value": value, "type": type}))

@tool("memory", "write")
def write_memory(address: str, bytes: list[int]) -> str:
    """Write raw bytes to memory."""
    return format_result(ce_client.send_command("write_memory", {"address": address, "bytes": bytes}))

@tool("memory", "write")
def write_string(address: str, value: str, wide: bool = False) -> str:
    """Write a string to memory (ASCII or Wide/UTF-16)."""
    return format_result(ce_client.send_command("write_string", {"address": address, "value": value, "wide": wide}))


@tool("scan", "read")
def aob_scan(pattern: str, protection: str = "+X", limit: int = 100) -> str:
    """Scan for an Array of Bytes (AOB) pattern. Example: '48 89 5C 24'."""
    return format_result(ce_client.send_command("aob_scan", {"pattern": pattern, "protection": protection, "limit": limit}))

@tool("scan", "read")
def search_string(string: str, wide: bool = False, limit: int = 100) -> str:
    """Quickly search for a text string in memory."""
    return format_result(ce_client.send_command("search_string", {"string": string, "wide": wide, "limit": limit}))

@tool("scan", "read")
def generate_signature(address: str) -> str:
    """Generate a unique AOB signature that can find this specific address again."""
    return format_result(ce_client.send_command("generate_signature", {"address": address}))

@tool("scan", "read")
def get_memory_regions(max: int = 100) -> str:
    """Get list of valid memory regions nearby common bases."""
    return format_result(ce_client.send_command("get_memory_regions", {"max": max}))

@tool("scan", "read")
def enum_memory_regions_full(offset: int = 0, limit: int = 100, max: int = None) -> str:
    """Enumerate ALL memory regions in the process (Native EnumMemoryRegions).

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum regions to return (default 100, max 10000). Preferred over 'max'.
        max: Deprecated alias for 'limit'. Use 'limit' instead.

    Returns JSON with: success, total, offset, limit, returned, regions.
    """
    return format_result(ce_client.send_command("enum_memory_regions_full", {"offset": offset, "limit": limit, "max": max}))

# --- ANALYSIS & DISASSEMBLY ---

@tool("analysis", "read")
def disassemble(address: str, count: int = 20, offset: int = 0, limit: int = 100) -> str:
    """Disassemble instructions starting at an address.

    Args:
        address: Target address (hex string or symbol).
        count: Number of instructions to generate (default 20).
        offset: Start index within the generated list for pagination (default 0).
        limit: Maximum instructions to return (default 100, max 10000).

    Returns JSON with: success, start_address, total, offset, limit, returned, instructions.
    """
    return format_result(ce_client.send_command("disassemble", {"address": address, "count": count, "offset": offset, "limit": limit}))

@tool("analysis", "read")
def get_instruction_info(address: str) -> str:
    """Get detailed info about a single instruction (size, bytes, opcode)."""
    return format_result(ce_client.send_command("get_instruction_info", {"address": address}))

@tool("analysis", "read")
def find_function_boundaries(address: str, max_search: int = 4096) -> str:
    """Find the start and end of the function containing the address.

    x64 modules: exact boundaries from the exception table (.pdata), reported with method="pdata", exact=true
    (also the exception handler address, and `fragment` when the address is in a split/cold part of a function).
    Anything else (x86, leaf functions without unwind data, JIT code): prologue/ret heuristic, method="heuristic".
    """
    return format_result(ce_client.send_command("find_function_boundaries", {"address": address, "max_search": max_search}))

@tool("analysis", "read")
def analyze_function(address: str) -> str:
    """Analyze a function to find all CALL instructions (calls made by this function).

    When .pdata knows the function (x64) the whole exact range is walked, including code after the first `ret`;
    otherwise it stops at the first `ret` found by the heuristic. `method` says which was used.
    """
    return format_result(ce_client.send_command("analyze_function", {"address": address}))

@tool("analysis", "read")
def find_references(address: str, offset: int = 0, limit: int = 50) -> str:
    """Find instructions that access (reference) this address.

    Args:
        address: Target address to find references to.
        offset: Start index for pagination (default 0).
        limit: Maximum references to return (default 50, max 10000).

    Returns JSON with: success, target, total, offset, limit, returned, references, arch.
    """
    return format_result(ce_client.send_command("find_references", {"address": address, "offset": offset, "limit": limit}))

@tool("analysis", "read")
def find_call_references(function_address: str, offset: int = 0, limit: int = 100) -> str:
    """Find all locations that CALL this function.

    Args:
        function_address: Address of the function to find callers of.
        offset: Start index for pagination (default 0).
        limit: Maximum callers to return (default 100, max 10000).

    Returns JSON with: success, function_address, total, offset, limit, returned, callers.
    """
    return format_result(ce_client.send_command("find_call_references", {"address": function_address, "offset": offset, "limit": limit}))

@tool("analysis", "read")
def dissect_structure(address: str, size: int = 256) -> str:
    """Use CE's auto-guess feature to interpret memory at address as a structure."""
    return format_result(ce_client.send_command("dissect_structure", {"address": address, "size": size}))

# --- DEBUGGING & BREAKPOINTS ---

@tool("debug", "write")
def set_breakpoint(address: str, id: str = None, capture_registers: bool = True, capture_stack: bool = False, stack_depth: int = 16,
                   max_hits: int = 1000, condition: str = "", mode: str = "log", stop_after_hits: int = 0,
                   halt_timeout_ms: int = 0, inspect: list[dict] = None) -> str:
    """Hardware execution breakpoint (debug register; at most 4 at once). Default mode "log": each hit
    records registers (optionally the stack) and the thread keeps running; read hits with get_breakpoint_hits.

    Args:
        id: Breakpoint name (default: the address).
        capture_stack: Record stack slots; hit.stack[0] is [SP+0] (the return address on a function-entry breakpoint).
        max_hits: Hit buffer size (1-100000, default 1000). Only the newest hits are kept; hit_count/dropped_hits
            report the overflow.
        condition: Record only hits where this is true, e.g. "RAX == 5", "u32(RDX+8) == 0x1234 and RCX ~= 0". Sees the
                   registers, memory readers u8..u64 i8..i64 f32 f64 ptr (nil if unreadable), hits(), seen(),
                   abs/min/max/floor; nothing else. Runs under an instruction budget; an erroring condition records
                   the hit with condition_error and is disabled after 5 failures.
        mode: "break" leaves the thread STOPPED: inspect it with get_halted_state, resume with debug_continue. A
              watchdog resumes it after halt_timeout_ms (default 10000, max 300000) so the target never stays frozen.
        stop_after_hits: Remove the breakpoint after this many matching hits (0 = unlimited).
        inspect: mode "break" only: [{"expr": "RDX+0x10", "size": 32}] memory captured at the hit (max 8 x 256 bytes).
    """
    return format_result(ce_client.send_command("set_breakpoint", _params(
        address=address, id=id, capture_registers=capture_registers, capture_stack=capture_stack, stack_depth=stack_depth,
        max_hits=max_hits, condition=condition, mode=mode if mode != "log" else None, stop_after_hits=stop_after_hits or None,
        halt_timeout_ms=halt_timeout_ms or None, inspect=inspect)))

@tool("debug", "write")
def set_data_breakpoint(address: str, id: str = None, access_type: str = "w", size: int = 4, max_hits: int = 1000,
                        condition: str = "", mode: str = "log", stop_after_hits: int = 0, halt_timeout_ms: int = 0,
                        inspect: list[dict] = None) -> str:
    """Hardware data breakpoint (watchpoint): what writes or accesses a value.

    Args:
        address: Must be aligned to size.
        access_type: "w" (default) or "rw"; "r" watches both and drops hits that changed the value.
        size: 1, 2, 4 (default) or 8.
        max_hits: Hit buffer size (1-100000, default 1000); only the newest hits are kept.
        condition / mode / stop_after_hits / halt_timeout_ms / inspect: as for set_breakpoint.

    Each hit records value, previous_value, value_changed, the registers and the instruction.
    """
    return format_result(ce_client.send_command("set_data_breakpoint", _params(
        address=address, id=id, access_type=access_type, size=size, max_hits=max_hits,
        condition=condition, mode=mode if mode != "log" else None, stop_after_hits=stop_after_hits or None,
        halt_timeout_ms=halt_timeout_ms or None, inspect=inspect)))

@tool("debug", "write")
def remove_breakpoint(id: str) -> str:
    """Remove a breakpoint by its ID."""
    return format_result(ce_client.send_command("remove_breakpoint", {"id": id}))

@tool("debug", "read")
def list_breakpoints() -> str:
    """List all active breakpoints."""
    return format_result(ce_client.send_command("list_breakpoints"))

@tool("debug", "write")
def clear_all_breakpoints() -> str:
    """Remove ALL breakpoints."""
    return format_result(ce_client.send_command("clear_all_breakpoints"))

@tool("debug", "analysis")
def get_breakpoint_hits(id: str = None, clear: bool = False, offset: int = 0, limit: int = 100) -> str:
    """Get hits for a specific breakpoint ID (or all if None). Set clear=True to flush buffer.

    Args:
        id: Breakpoint ID to query, or None for all breakpoints.
        clear: If True, flush the hit buffer after reading (default False).
        offset: Start index for pagination (default 0).
        limit: Maximum hits to return (default 100, max 10000).

    Returns JSON with: success, total, offset, limit, returned, hits, plus
    hit_count / dropped_hits / max_hits for a single id, or a per-id "stats"
    map when querying all breakpoints. Each hit carries a hit_number.
    """
    return format_result(ce_client.send_command("get_breakpoint_hits", {"id": id, "clear": clear, "offset": offset, "limit": limit}))

# --- DBVM / HYPERVISOR TOOLS (Ring -1) ---

@tool("kernel", "read")
def get_physical_address(address: str) -> str:
    """Translate Virtual Address to Physical Address (requires DBVM)."""
    return format_result(ce_client.send_command("get_physical_address", {"address": address}))

@tool("kernel", "write")
def start_dbvm_watch(address: str, mode: str = "w", max_entries: int = 1000) -> str:
    """Start invisible DBVM hypervisor watch. Modes: 'w' (writes), 'r' (reads), 'x' (execute)."""
    return format_result(ce_client.send_command("start_dbvm_watch", {"address": address, "mode": mode, "max_entries": max_entries}))

@tool("kernel", "write")
def stop_dbvm_watch(address: str) -> str:
    """Stop DBVM watch and return results."""
    return format_result(ce_client.send_command("stop_dbvm_watch", {"address": address}))

@tool("kernel", "read")
def poll_dbvm_watch(address: str, max_results: int = 1000) -> str:
    """Poll DBVM watch logs WITHOUT stopping. Returns register state at each execution hit."""
    return format_result(ce_client.send_command("poll_dbvm_watch", {
        "address": address, 
        "max_results": max_results
    }))

# --- KERNEL MODE / DBVM EXTENSIONS (Unit 21) ---

@tool("kernel", "read")
def dbk_get_cr0() -> str:
    """Read Control Register 0 (CR0) via the DBK kernel driver.

    Requires the DBK kernel driver to be loaded (CE Settings -> Debugger -> Kernelmode).
    Returns cr0 as a hex string.
    """
    return format_result(ce_client.send_command("dbk_get_cr0"))

@tool("kernel", "read")
def dbk_get_cr3() -> str:
    """Read Control Register 3 (CR3 — page-table base) via DBK or DBVM.

    Works when either the DBK kernel driver or the DBVM hypervisor is loaded.
    Returns cr3 as a hex string.
    """
    return format_result(ce_client.send_command("dbk_get_cr3"))

@tool("kernel", "read")
def dbk_get_cr4() -> str:
    """Read Control Register 4 (CR4) via the DBK kernel driver.

    Requires the DBK kernel driver to be loaded (CE Settings -> Debugger -> Kernelmode).
    Returns cr4 as a hex string.
    """
    return format_result(ce_client.send_command("dbk_get_cr4"))

@tool("kernel", "read")
def read_process_memory_cr3(cr3: str, address: str, size: int) -> str:
    """Read virtual memory using an explicit CR3 page-table base via DBK/DBVM.

    Bypasses the standard OS memory-translation path, making it effective for
    processes that hide memory from normal reads (e.g. anti-cheat analysis).

    Requires: DBK kernel driver or DBVM hypervisor loaded; a process must be attached.

    Args:
        cr3: CR3 value (hex string or integer) identifying the target page table.
        address: Virtual address to read from (hex string or symbol name).
        size: Number of bytes to read.
    """
    return format_result(ce_client.send_command(
        "read_process_memory_cr3",
        {"cr3": cr3, "address": address, "size": size}
    ))

@tool("kernel", "write")
def write_process_memory_cr3(cr3: str, address: str, bytes: list) -> str:
    """Write to virtual memory using an explicit CR3 page-table base via DBK/DBVM.

    Bypasses the standard OS memory-translation path.

    Requires: DBK kernel driver or DBVM hypervisor loaded; a process must be attached.

    Args:
        cr3: CR3 value (hex string or integer) identifying the target page table.
        address: Virtual address to write to (hex string or symbol name).
        bytes: List of integer byte values to write.
    """
    return format_result(ce_client.send_command(
        "write_process_memory_cr3",
        {"cr3": cr3, "address": address, "bytes": bytes}
    ))

@tool("kernel", "write")
def map_memory(address: str, size: int) -> str:
    """Map a kernel/physical address range into the CE usermode context via DBK.

    Returns a mapped_address that can be used for ordinary memory reads/writes.
    Call unmap_memory() with the same mapped_address when finished.

    Requires: DBK kernel driver loaded; a process must be attached.

    Args:
        address: Source address to map (hex string or symbol name).
        size: Number of bytes to map.
    """
    return format_result(ce_client.send_command(
        "map_memory",
        {"address": address, "size": size}
    ))

@tool("kernel", "write")
def unmap_memory(mapped_address: str, size: int = 0) -> str:
    """Release a memory mapping created by map_memory().

    The size parameter is accepted for API compatibility but unused internally;
    the MDL handle captured during map_memory() is used to release the mapping.

    Requires: DBK kernel driver loaded; a process must be attached.

    Args:
        mapped_address: The mapped address returned by a prior map_memory() call.
        size: Unused; kept for API symmetry with map_memory().
    """
    return format_result(ce_client.send_command(
        "unmap_memory",
        {"mapped_address": mapped_address, "size": size}
    ))

@tool("kernel", "write")
def dbk_writes_ignore_write_protection(enable: bool) -> str:
    """Toggle whether DBK memory writes bypass copy-on-write (CoW) protection.

    When enabled, writes go directly to the underlying physical page instead of
    triggering a page fault and creating a process-private copy. Useful when
    patching shared read-only pages across all processes simultaneously.

    Requires: DBK kernel driver loaded.

    Args:
        enable: True to bypass CoW; False to restore normal CoW behaviour.
    """
    return format_result(ce_client.send_command(
        "dbk_writes_ignore_write_protection",
        {"enable": enable}
    ))

@tool("kernel", "read")
def get_physical_address_cr3(cr3: str, virtual_address: str) -> str:
    """Translate a virtual address to its physical address using an explicit CR3.

    Unlike get_physical_address (which uses the currently attached process's CR3),
    this function lets you walk any process's page table — useful for cross-process
    physical memory analysis.

    Requires: DBK kernel driver or DBVM hypervisor loaded; a process must be attached.

    Args:
        cr3: CR3 value (hex string or integer) of the target process's page table.
        virtual_address: Virtual address to translate (hex string or symbol name).
    """
    return format_result(ce_client.send_command(
        "get_physical_address_cr3",
        {"cr3": cr3, "virtual_address": virtual_address}
    ))

# --- SCRIPTING & CONTROL ---

@tool("scripting", "exec")
def evaluate_lua(code: str) -> str:
    """Execute arbitrary Lua code in Cheat Engine.

    Returns JSON with: success, result (tostring of the first return value),
    results (every return value as structured JSON; tables are converted with
    depth/size limits and cycle detection), result_count.
    """
    return format_result(ce_client.send_command("evaluate_lua", {"code": code}))

@tool("scripting", "exec")
def auto_assemble(script: str) -> str:
    """Run an AutoAssembler script (injection, code caves, etc)."""
    return format_result(ce_client.send_command("auto_assemble", {"script": script}))

@tool("scripting", "read")
def assemble_instruction(
    line: str,
    address: str = None,
    preference: int = 0,
    skip_range_check: bool = False,
) -> str:
    """Assemble a single x86/x64 instruction into bytes.

    Requires an attached process when an address is given (the address is used to
    resolve relative operands such as JMP targets).

    Returns {success, bytes: [int], size: int}.
    preference: 0=none, 1=short, 2=long, 3=far.
    """
    params: dict = {"line": line, "preference": preference, "skip_range_check": skip_range_check}
    if address is not None:
        params["address"] = address
    return format_result(ce_client.send_command("assemble_instruction", params))


@tool("scripting", "exec")
def auto_assemble_check(
    script: str,
    enable: bool = True,
    target_self: bool = False,
) -> str:
    """Validate an Auto Assembler script for syntax errors without assembling it.

    SECURITY: classified `exec`. Cheat Engine still runs `{$lua}` blocks (and
    registered AA command hooks) during a syntax check, so a script can run
    arbitrary Lua even here.

    Returns {success, valid: bool, errors: [str]}.
    enable: True checks the [Enable] section; False checks [Disable].
    target_self: if True, validates against CE's own process instead of the target.
    """
    return format_result(ce_client.send_command("auto_assemble_check", {
        "script": script,
        "enable": enable,
        "target_self": target_self,
    }))


@tool("scripting", "exec")
def compile_c_code(
    source: str,
    address: str = None,
    target_self: bool = False,
    kernelmode: bool = False,
) -> str:
    """Compile C source code using CE's built-in TCC compiler.

    Does not require an attached process unless an address is provided.
    Returns {success, symbols: {name: address}, errors: [str]}.
    If TCC is unavailable: {success=false, error="TCC compiler not available",
    error_code="CE_API_UNAVAILABLE"}.
    """
    params: dict = {"source": source, "target_self": target_self, "kernelmode": kernelmode}
    if address is not None:
        params["address"] = address
    return format_result(ce_client.send_command("compile_c_code", params))


@tool("scripting", "exec")
def compile_cs_code(
    source: str,
    references: list = None,
    core_assembly: str = None,
) -> str:
    """Compile C# source code using CE's .NET compiler (requires .NET 4+).

    Returns {success, assembly_handle: str} where assembly_handle is the path to
    the generated assembly. On .NET runtime absent:
    {success=false, error_code="CE_API_UNAVAILABLE"}.
    """
    params: dict = {"source": source, "references": references or []}
    if core_assembly is not None:
        params["core_assembly"] = core_assembly
    return format_result(ce_client.send_command("compile_cs_code", params))


@tool("scripting", "read")
def generate_api_hook_script(
    address: str,
    target_address: str,
    code_to_execute: str = "",
) -> str:
    """Generate an Auto Assembler script that hooks a function and redirects it.

    Requires an attached process. address is the function to hook;
    target_address is where execution should jump after the hook.
    code_to_execute is optional extra AA code inserted into the generated script.
    Returns {success, script: str}.
    """
    return format_result(ce_client.send_command("generate_api_hook_script", {
        "address": address,
        "target_address": target_address,
        "code_to_execute": code_to_execute,
    }))


@tool("scripting", "read")
def generate_code_injection_script(address: str) -> str:
    """Generate a boilerplate code-injection Auto Assembler script for an address.

    Requires an attached process.
    Returns {success, script: str} — the script can be used as a starting point
    for patching code at that location.
    """
    return format_result(ce_client.send_command("generate_code_injection_script", {
        "address": address,
    }))


@tool("process", "read")
def ping() -> str:
    """Check connectivity and get version info."""
    return format_result(ce_client.send_command("ping"))

# --- DEBUG OUTPUT & MULTIMEDIA (Unit 23) ---

@tool("gui", "write")
def output_debug_string(message: str) -> str:
    """Post a message to the Windows debugger via OutputDebugString (readable with tools like DebugView)."""
    return format_result(ce_client.send_command("output_debug_string", {"message": message}))

@tool("gui", "write")
def speak_text(text: str, english_only: bool = False) -> str:
    """Speak text via Windows SAPI text-to-speech. Set english_only=True to force the English voice."""
    return format_result(ce_client.send_command("speak_text", {"text": text, "english_only": english_only}))

@tool("gui", "write")
def play_sound(filename: str) -> str:
    """Play a WAV sound file by filename. Path must not contain '..' directory traversal."""
    return format_result(ce_client.send_command("play_sound", {"filename": filename}))

@tool("gui", "write")
def beep() -> str:
    """Play a simple system beep sound."""
    return format_result(ce_client.send_command("beep", {}))

@tool("gui", "write")
def set_progress_state(state: str) -> str:
    """Set the Cheat Engine taskbar progress state. Valid states: none, normal, paused, error, indeterminate."""
    return format_result(ce_client.send_command("set_progress_state", {"state": state}))

@tool("gui", "write")
def set_progress_value(current: int, max: int) -> str:
    """Set the Cheat Engine taskbar progress bar position. Provide current value and maximum value."""
    return format_result(ce_client.send_command("set_progress_value", {"current": current, "max": max}))
# --- THREADING & SYNCHRONIZATION (Unit-22) ---

@tool("scripting", "exec")
def create_thread(code: str, arg: str = "") -> str:
    """Execute Lua code in a new CE thread.

    SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process,
    carrying the same risk as evaluate_lua. Only use with trusted code.

    Returns {success, thread_id}.
    """
    return format_result(ce_client.send_command("create_thread", {"code": code, "arg": arg}))

@tool("scripting", "read")
def get_global_variable(name: str) -> str:
    """Read a global variable from CE's main Lua state.

    Useful for reading values set by scripts running in other threads.
    Returns {success, value} where value is stringified via tostring().
    """
    return format_result(ce_client.send_command("get_global_variable", {"name": name}))

@tool("scripting", "write")
def set_global_variable(name: str, value: str) -> str:
    """Write a global variable in CE's main Lua state.

    Useful for passing values to scripts running in other threads.
    Returns {success}.
    """
    return format_result(ce_client.send_command("set_global_variable", {"name": name, "value": value}))

@tool("scripting", "exec")
def queue_to_main_thread(code: str) -> str:
    """Queue Lua code to run on CE's main thread without waiting for its result.

    SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process
    on the main thread, carrying the same risk as evaluate_lua. Only use with
    trusted code.

    Returns {success}.
    """
    return format_result(ce_client.send_command("queue_to_main_thread", {"code": code}))

@tool("scripting", "read")
def check_synchronize() -> str:
    """Process queued main-thread calls (checkSynchronize).

    Call this from an infinite loop in the main thread when using threading
    and synchronize calls. Returns {success}.
    """
    return format_result(ce_client.send_command("check_synchronize"))

@tool("scripting", "read")
def in_main_thread() -> str:
    """Check whether the current code is running in CE's main thread.

    Returns {success, is_main_thread}.
    """
    return format_result(ce_client.send_command("in_main_thread"))
# >>> BEGIN UNIT-20b Shell Execution <<<
def _check_shell_gate(method, params):
    """Python-side half of the shell opt-in (the bridge checks its own half)."""
    if os.environ.get("CE_MCP_ALLOW_SHELL") == "1":
        return None
    result = {
        "success": False,
        "error": "Shell execution disabled. Set CE_MCP_ALLOW_SHELL=1 in the MCP server's environment "
                 "(and in Cheat Engine's; see README) to enable.",
        "error_code": "PERMISSION_DENIED",
    }
    if ce_client.audit is not None:
        ce_client.audit.record(method, params, "blocked", time.monotonic(), result=result)
    return json.dumps(result)

@tool("system", "exec")
def run_command(command: str, args: str = "") -> str:
    """Execute a shell command in the host OS. SECURITY: Arbitrary code execution.

    REQUIRES CE_MCP_ALLOW_SHELL=1 in the MCP server's environment AND the CE-side
    opt-in (CE_MCP_ALLOW_SHELL=1 in Cheat Engine's environment, or
    `CE_MCP_ALLOW_SHELL = true` before loading the bridge), plus CE_MCP_PROFILE=full.
    By default, this tool returns a PERMISSION_DENIED error.

    Args:
        command: Command path or name (e.g. "notepad.exe", "cmd.exe").
        args: Arguments string.

    Returns JSON with: success, output, exit_code.
    """
    params = {"command": command, "args": args}
    blocked = _check_shell_gate("run_command", params)
    if blocked:
        return blocked
    return format_result(ce_client.send_command("run_command", params))

@tool("system", "exec")
def shell_execute(command: str, args: str = "", verb: str = "open", working_dir: str = "", showcommand: int = None) -> str:
    """Invoke Windows ShellExecute. SECURITY: Arbitrary code execution.

    REQUIRES CE_MCP_ALLOW_SHELL=1 in the MCP server's environment AND the CE-side
    opt-in (CE_MCP_ALLOW_SHELL=1 in Cheat Engine's environment, or
    `CE_MCP_ALLOW_SHELL = true` before loading the bridge), plus CE_MCP_PROFILE=full.

    Args:
        command: Command or file to execute.
        args: Arguments string.
        verb: ShellExecute verb. CE currently supports "open" only.
        working_dir: Working directory (empty for current).
        showcommand: Optional Win32 show command integer.

    Returns JSON with: success.
    """
    params = {
        "command": command,
        "args": args,
        "verb": verb,
        "working_dir": working_dir,
    }
    if showcommand is not None:
        params["showcommand"] = showcommand
    blocked = _check_shell_gate("shell_execute", params)
    if blocked:
        return blocked
    return format_result(ce_client.send_command("shell_execute", params))
# >>> END UNIT-20b <<<
# >>> BEGIN UNIT-20a File IO Clipboard <<<

@tool("system", "read")
def file_exists(filename: str) -> str:
    """Check whether a file exists at the given path. Returns {success, exists: bool}."""
    return format_result(ce_client.send_command("file_exists", {"filename": filename}))

@tool("system", "write")
def delete_file(filename: str) -> str:
    """Delete a file at the given path. Returns {success}.

    WARNING: This is a destructive operation. The file will be permanently deleted
    from disk. Path traversal sequences ('..') are blocked by the bridge. Use with
    extreme caution — there is no undo.
    """
    return format_result(ce_client.send_command("delete_file", {"filename": filename}))

@tool("system", "read")
def get_file_list(path: str) -> str:
    """List files in the given directory path. Returns {success, count, files: [str]}."""
    return format_result(ce_client.send_command("get_file_list", {"path": path}))

@tool("system", "read")
def get_directory_list(path: str) -> str:
    """List subdirectories in the given directory path. Returns {success, count, directories: [str]}."""
    return format_result(ce_client.send_command("get_directory_list", {"path": path}))

@tool("system", "read")
def get_temp_folder() -> str:
    """Return the path to the system temp folder. Returns {success, path: str}."""
    return format_result(ce_client.send_command("get_temp_folder"))

@tool("system", "read")
def get_file_version(filename: str) -> str:
    """Get the version info of a file (major, minor, release, build). Returns {success, major, minor, release, build, version_string}."""
    return format_result(ce_client.send_command("get_file_version", {"filename": filename}))

@tool("system", "read")
def read_clipboard() -> str:
    """Read text from the system clipboard. Returns {success, text: str}."""
    return format_result(ce_client.send_command("read_clipboard"))

@tool("system", "write")
def write_clipboard(text: str) -> str:
    """Write text to the system clipboard. Returns {success}."""
    return format_result(ce_client.send_command("write_clipboard", {"text": text}))

# >>> END UNIT-20a <<<
# >>> BEGIN UNIT-19 Structure Management <<<

@tool("analysis", "analysis")
def create_structure(name: str) -> str:
    """Create a new empty CE structure definition and add it to the global list.

    Args:
        name: The name for the new structure.

    Returns JSON with: success, structure_id.
    """
    return format_result(ce_client.send_command("create_structure", {"name": name}))


@tool("analysis", "read")
def get_structure_by_name(name: str) -> str:
    """Find a CE structure by name in the global structure list.

    Args:
        name: The structure name to search for.

    Returns JSON with: success, structure_id, name, element_count, size.
    """
    return format_result(ce_client.send_command("get_structure_by_name", {"name": name}))


@tool("analysis", "analysis")
def add_element_to_structure(structure_id: int, name: str, offset: int, type: str) -> str:
    """Add a new element to an existing CE structure.

    Args:
        structure_id: The structure ID returned by create_structure or get_structure_by_name.
        name: The element name.
        offset: The byte offset of the element within the structure.
        type: The variable type. Accepted values: byte, word, dword, qword,
              float, single, double, string, aob, bytearray, pointer.

    Returns JSON with: success, element_index.
    """
    return format_result(ce_client.send_command("add_element_to_structure", {
        "structure_id": structure_id,
        "name": name,
        "offset": offset,
        "type": type,
    }))


@tool("analysis", "read")
def get_structure_elements(structure_id: int) -> str:
    """Get all elements of a CE structure.

    Args:
        structure_id: The structure ID.

    Returns JSON with: success, structure_id, elements (list of {name, offset, type, size}).
    """
    return format_result(ce_client.send_command("get_structure_elements", {"structure_id": structure_id}))


@tool("analysis", "read")
def export_structure_to_xml(structure_id: int) -> str:
    """Export a CE structure definition as XML.

    Args:
        structure_id: The structure ID.

    Returns JSON with: success, xml (XML string representation of the structure).
    """
    return format_result(ce_client.send_command("export_structure_to_xml", {"structure_id": structure_id}))


@tool("analysis", "analysis")
def delete_structure(structure_id: int) -> str:
    """Delete a CE structure from the global list and free it.

    Args:
        structure_id: The structure ID to delete.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("delete_structure", {"structure_id": structure_id}))

# >>> END UNIT-19 <<<
# >>> BEGIN UNIT-18 Cheat Table Records <<<

@tool("table", "exec")
def load_table(filename: str, merge: bool = False) -> str:
    """Load a Cheat Engine table (.ct) file into the current session.

    Args:
        filename: Path to the .ct or .cetrainer file to load.
        merge: If True, merge with the current table instead of replacing it.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("load_table", {"filename": filename, "merge": merge}))

@tool("table", "write")
def save_table(filename: str, protect: bool = False) -> str:
    """Save the current cheat table to a file.

    Args:
        filename: Destination path for the .ct or .cetrainer file.
        protect: If True and the filename has a .cetrainer extension, protect it from normal reading.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("save_table", {"filename": filename, "protect": protect}))

@tool("table", "read")
def get_address_list(offset: int = 0, limit: int = 100) -> str:
    """List memory records in the current cheat table's address list.

    Args:
        offset: Zero-based index of the first record to return.
        limit: Maximum number of records to return (default 100).

    Returns JSON with: success, total, offset, limit, returned, records (list of
    {id, description, address, type, value, offsets, enabled}).
    """
    return format_result(ce_client.send_command("get_address_list", {"offset": offset, "limit": limit}))

@tool("table", "read")
def get_memory_record(id: int = None, description: str = None) -> str:
    """Retrieve a single memory record by ID or description.

    Args:
        id: Unique numeric ID of the memory record.
        description: Description string of the memory record (used when id is not provided).

    Returns JSON with: success, record ({id, description, address, type, value, offsets, enabled}).
    """
    params = {}
    if id is not None:
        params["id"] = id
    if description is not None:
        params["description"] = description
    return format_result(ce_client.send_command("get_memory_record", params))

@tool("table", "analysis")
def create_memory_record(description: str, address: str, var_type: str = "dword") -> str:
    """Create a new memory record in the cheat table address list.

    Args:
        description: Human-readable label for the new entry.
        address: Address string (hex, symbol, or pointer expression) to watch.
        var_type: Variable type — byte, word, dword, qword, float, double, string, bytearray (default: dword).

    Returns JSON with: success, id, record ({id, description, address, type, value, offsets, enabled}).
    """
    return format_result(ce_client.send_command("create_memory_record", {
        "description": description,
        "address": address,
        "type": var_type,
    }))

@tool("table", "analysis")
def delete_memory_record(id: int) -> str:
    """Delete a memory record from the cheat table address list by ID.

    Args:
        id: Unique numeric ID of the memory record to delete.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("delete_memory_record", {"id": id}))

@tool("table", "read")
def get_memory_record_value(id: int) -> str:
    """Read the current value of a memory record as a string.

    Args:
        id: Unique numeric ID of the memory record.

    Returns JSON with: success, value (string representation of the current value).
    """
    return format_result(ce_client.send_command("get_memory_record_value", {"id": id}))

@tool("table", "write")
def set_memory_record_value(id: int, value: str) -> str:
    """Write a value to a memory record (and therefore to the target process memory).

    Args:
        id: Unique numeric ID of the memory record to update.
        value: New value as a string (e.g. "100", "3.14", "FF AA BB").

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("set_memory_record_value", {"id": id, "value": value}))

# >>> END UNIT-18 <<<
# --- INPUT AUTOMATION (Unit-17) — system-wide, no process guard required ---

@tool("gui", "read")
def get_pixel(x: int, y: int) -> str:
    """Get the colour of a screen pixel at (x, y). Returns r, g, b channels and the raw COLORREF integer."""
    return format_result(ce_client.send_command("get_pixel", {"x": x, "y": y}))

@tool("gui", "read")
def get_mouse_pos() -> str:
    """Get the current mouse cursor position. Returns x and y screen coordinates."""
    return format_result(ce_client.send_command("get_mouse_pos"))

@tool("gui", "write")
def set_mouse_pos(x: int, y: int) -> str:
    """Move the mouse cursor to screen position (x, y)."""
    return format_result(ce_client.send_command("set_mouse_pos", {"x": x, "y": y}))

@tool("gui", "read")
def is_key_pressed(vk: int) -> str:
    """Check whether a key is currently held down.
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space, 0x01 for left mouse button).
    Returns pressed: bool."""
    return format_result(ce_client.send_command("is_key_pressed", {"vk": vk}))

@tool("gui", "write")
def key_down(vk: int) -> str:
    """Simulate pressing a key down (does NOT release it automatically).
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space)."""
    return format_result(ce_client.send_command("key_down", {"vk": vk}))

@tool("gui", "write")
def key_up(vk: int) -> str:
    """Release a key that was pressed with key_down.
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space)."""
    return format_result(ce_client.send_command("key_up", {"vk": vk}))

@tool("gui", "write")
def do_key_press(vk: int) -> str:
    """Simulate a full key press (down + up) for the given key.
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space)."""
    return format_result(ce_client.send_command("do_key_press", {"vk": vk}))

@tool("gui", "read")
def get_screen_info() -> str:
    """Get the primary screen dimensions and DPI. Returns width, height (pixels) and dpi."""
    return format_result(ce_client.send_command("get_screen_info"))
# --- WINDOW / GUI TOOLS (Unit-16) ---

@tool("gui", "read")
def find_window(title: str = None, class_name: str = None) -> str:
    """Find a top-level window by title and/or class name (system-wide, no process required).

    At least one of title or class_name must be provided.
    Returns {success, handle} on success or {success=false, error_code="NOT_FOUND"} when
    no matching window exists.
    """
    params = {}
    if title is not None:
        params["title"] = title
    if class_name is not None:
        params["class_name"] = class_name
    return format_result(ce_client.send_command("find_window", params))

@tool("gui", "read")
def get_window_caption(handle: str) -> str:
    """Return the caption (title bar text) of a window given its handle (hex string)."""
    return format_result(ce_client.send_command("get_window_caption", {"handle": handle}))

@tool("gui", "read")
def get_window_class_name(handle: str) -> str:
    """Return the window class name of a window given its handle (hex string)."""
    return format_result(ce_client.send_command("get_window_class_name", {"handle": handle}))

@tool("gui", "read")
def get_window_process_id(handle: str) -> str:
    """Return the process ID that owns a window given its handle (hex string)."""
    return format_result(ce_client.send_command("get_window_process_id", {"handle": handle}))

@tool("gui", "write")
def send_window_message(handle: str, msg: int, wparam: int = 0, lparam: int = 0) -> str:
    """Send a Windows message (WM_*) to a window.

    handle  -- hex window handle string
    msg     -- message ID (e.g. 0x000F for WM_PAINT)
    wparam  -- WPARAM value (default 0)
    lparam  -- LPARAM value (default 0)

    Returns {success, result} where result is the integer return value of SendMessage.
    """
    return format_result(ce_client.send_command("send_window_message", {
        "handle": handle,
        "msg": msg,
        "wparam": wparam,
        "lparam": lparam,
    }))

@tool("gui", "write")
def show_message(message: str) -> str:
    """Show a modal message dialog in Cheat Engine.

    WARNING — NOT SAFE FOR AUTOMATED WORKFLOWS:
    This call BLOCKS the CE main thread until the user dismisses the dialog by
    clicking OK.  Do not invoke from automation that expects a timely response.

    Returns {success} after the user closes the dialog.
    """
    return format_result(ce_client.send_command("show_message", {"message": message}))

@tool("gui", "write")
def input_query(caption: str, prompt: str, default: str = "") -> str:
    """Show a modal text-input dialog in Cheat Engine and return what the user typed.

    WARNING — NOT SAFE FOR AUTOMATED WORKFLOWS:
    This call BLOCKS the CE main thread until the user submits or cancels the dialog.
    Do not invoke from automation that expects a timely response.

    Returns {success, value, cancelled}.  If cancelled is true, value is an empty string.
    """
    return format_result(ce_client.send_command("input_query", {
        "caption": caption,
        "prompt": prompt,
        "default": default,
    }))

@tool("gui", "write")
def show_selection_list(caption: str, prompt: str, options: list) -> str:
    """Show a modal list-selection dialog in Cheat Engine.

    WARNING — NOT SAFE FOR AUTOMATED WORKFLOWS:
    This call BLOCKS the CE main thread until the user picks an item or cancels.
    Do not invoke from automation that expects a timely response.

    options -- list of strings to display
    Returns {success, selected_index, selected_value, cancelled}.
    selected_index is -1 and cancelled is true when the user dismisses without selecting.
    """
    return format_result(ce_client.send_command("show_selection_list", {
        "caption": caption,
        "prompt": prompt,
        "options": options,
    }))

# --- UNIT 15: ADVANCED SCANNING ---

@tool("scan", "read")
def aob_scan_unique(pattern: str, protection: str = "+X") -> str:
    """Scan for an AOB pattern that must match exactly once. Returns {success, address} or error with count.
    Use this when you expect a signature to be unique in the process."""
    return format_result(ce_client.send_command("aob_scan_unique", {"pattern": pattern, "protection": protection}))

@tool("scan", "read")
def aob_scan_module(pattern: str, module_name: str, protection: str = "+X") -> str:
    """Scan for an AOB pattern restricted to a specific module's memory range.
    Returns {success, count, addresses: [str]}."""
    return format_result(ce_client.send_command("aob_scan_module", {
        "pattern": pattern,
        "module_name": module_name,
        "protection": protection
    }))

@tool("scan", "read")
def aob_scan_module_unique(pattern: str, module_name: str, protection: str = "+X") -> str:
    """Scan for an AOB pattern in a specific module that must match exactly once.
    Returns {success, address} or error with count."""
    return format_result(ce_client.send_command("aob_scan_module_unique", {
        "pattern": pattern,
        "module_name": module_name,
        "protection": protection
    }))

@tool("scan", "analysis")
def pointer_rescan(value: str, previous_results_file: str = None) -> str:
    """Re-scan an existing pointer scan for a new value. Requires a prior pointer scan in CE.
    Returns {success, result_count}. Run a Pointer Scanner scan in CE first."""
    params = {"value": value}
    if previous_results_file:
        params["previous_results_file"] = previous_results_file
    return format_result(ce_client.send_command("pointer_rescan", params))

@tool("scan", "analysis")
def create_persistent_scan(name: str) -> str:
    """Create a named, stateful memory scan session. Use the name with persistent_scan_* tools.
    Returns {success, scan_name}."""
    return format_result(ce_client.send_command("create_persistent_scan", {"name": name}))

@tool("scan", "analysis")
def persistent_scan_first_scan(name: str, value: str = None, type: str = "dword", scan_option: str = "exact", value2: str = None) -> str:
    """Run the first scan on a named persistent scan session.
    Types: byte, word, dword, qword, float, double, string.
    Scan options: exact, unknown, between, bigger, smaller.
    'between' needs two bounds: pass value2, or put both in value as "min,max" (e.g. value="0,1").
    'unknown' takes no value.
    Returns {success, scan_name, count}."""
    params = {"name": name, "type": type, "scan_option": scan_option}
    if value is not None:
        params["value"] = value
    if value2 is not None:
        params["value2"] = value2
    return format_result(ce_client.send_command("persistent_scan_first_scan", params))

@tool("scan", "analysis")
def persistent_scan_next_scan(name: str, value: str = None, scan_option: str = "exact", value2: str = None) -> str:
    """Narrow down results with a next scan on a named persistent scan session.
    Scan options: exact, between, bigger, smaller, increased, decreased, increased_by, decreased_by, changed, unchanged.
    'between' needs two bounds: pass value2, or put both in value as "min,max".
    Returns {success, scan_name, count}."""
    params = {"name": name, "scan_option": scan_option}
    if value is not None:
        params["value"] = value
    if value2 is not None:
        params["value2"] = value2
    return format_result(ce_client.send_command("persistent_scan_next_scan", params))

@tool("scan", "read")
def persistent_scan_get_results(name: str, offset: int = 0, limit: int = 100) -> str:
    """Get paginated results from a named persistent scan session.
    Returns {success, total, offset, limit, results: [{address, value}]}."""
    return format_result(ce_client.send_command("persistent_scan_get_results", {
        "name": name,
        "offset": offset,
        "limit": limit
    }))

@tool("scan", "analysis")
def persistent_scan_destroy(name: str) -> str:
    """Destroy a named persistent scan session and free its memory.
    Returns {success, scan_name, destroyed}."""
    return format_result(ce_client.send_command("persistent_scan_destroy", {"name": name}))
# --- MEMORY OPERATIONS (Unit 14) ---

@tool("memory", "write")
def copy_memory(source: str, size: int, dest: str = None, method: int = 0) -> str:
    """Copy memory between addresses. Methods: 0=target→target, 1=target→CE, 2=CE→target, 3=CE→CE. Returns dest_address allocated by CE if dest is None."""
    return format_result(ce_client.send_command("copy_memory", {
        "source": source, "size": size, "dest": dest, "method": method
    }))

@tool("memory", "read")
def compare_memory(addr1: str, addr2: str, size: int, method: int = 0) -> str:
    """Compare two memory regions. Methods: 0=target/target, 1=addr1=target addr2=CE, 2=both CE. Returns equal flag and first_diff byte index (-1 if equal)."""
    return format_result(ce_client.send_command("compare_memory", {
        "addr1": addr1, "addr2": addr2, "size": size, "method": method
    }))

@tool("memory", "write")
def write_region_to_file(address: str, size: int, filename: str) -> str:
    """Write a memory region to a file. Filename must be an absolute path and must not contain '..' components."""
    return format_result(ce_client.send_command("write_region_to_file", {
        "address": address, "size": size, "filename": filename
    }))

@tool("memory", "write")
def read_region_from_file(filename: str, destination: str) -> str:
    """Read a file into memory at the given destination address. Filename must be an absolute path and must not contain '..' components."""
    return format_result(ce_client.send_command("read_region_from_file", {
        "filename": filename, "destination": destination
    }))

@tool("memory", "read")
def md5_memory(address: str, size: int) -> str:
    """Calculate the MD5 hash of a memory region. Returns the hash as a hex string."""
    return format_result(ce_client.send_command("md5_memory", {
        "address": address, "size": size
    }))

@tool("memory", "read")
def md5_file(filename: str) -> str:
    """Calculate the MD5 hash of a file on the CE host. Filename must not contain '..' components."""
    return format_result(ce_client.send_command("md5_file", {"filename": filename}))

@tool("memory", "write")
def create_section(size: int) -> str:
    """Create a Windows section (shared memory) of the given size. Returns a handle as a hex string."""
    return format_result(ce_client.send_command("create_section", {"size": size}))

@tool("memory", "write")
def map_view_of_section(handle: str, address: str = None, size: int = 0) -> str:
    """Map a section into the target process. 'handle' is from create_section. 'address' is optional preferred base. Returns mapped_address."""
    return format_result(ce_client.send_command("map_view_of_section", {
        "handle": handle, "address": address, "size": size
    }))

# >>> BEGIN UNIT-12 Symbol Management <<<
@tool("analysis", "analysis")
def register_symbol(name: str, address: str, do_not_save: bool = False) -> str:
    """Register a user-defined symbol with a given name and address.

    Args:
        name: Symbol name to register.
        address: Address to bind to the symbol (hex string or decimal).
        do_not_save: If True, this symbol is not persisted when the CE table is saved.

    Returns JSON with: success, name, address.
    """
    return format_result(ce_client.send_command("register_symbol", {
        "name": name, "address": address, "do_not_save": do_not_save
    }))

@tool("analysis", "analysis")
def unregister_symbol(name: str) -> str:
    """Remove a previously registered user-defined symbol.

    Args:
        name: Symbol name to unregister.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("unregister_symbol", {"name": name}))

@tool("analysis", "read")
def enum_registered_symbols() -> str:
    """List all user-registered symbols.

    Returns JSON with: success, count, symbols (list of {name, address, module}).
    """
    return format_result(ce_client.send_command("enum_registered_symbols"))

@tool("analysis", "analysis")
def delete_all_registered_symbols() -> str:
    """Delete every user-registered symbol (both AA and Lua).

    Returns JSON with: success, deleted_count.
    """
    return format_result(ce_client.send_command("delete_all_registered_symbols"))

@tool("analysis", "analysis")
def enable_windows_symbols() -> str:
    """Trigger download and load of Windows PDB symbol files.

    Note: The actual PDB download and indexing is asynchronous; this call returns
    immediately once the process has been initiated by Cheat Engine.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("enable_windows_symbols"))

@tool("analysis", "analysis")
def enable_kernel_symbols() -> str:
    """Enable kernel-mode symbol resolution (requires DBK driver).

    Returns JSON with: success.
    On failure returns error_code DBK_NOT_LOADED if the kernel driver is absent.
    """
    return format_result(ce_client.send_command("enable_kernel_symbols"))

@tool("analysis", "read")
def get_symbol_info(name: str) -> str:
    """Retrieve detailed information about a known symbol.

    Requires an attached process.

    Args:
        name: Symbol or export name to look up.

    Returns JSON with: success, name, address, module, size.
    Returns error_code NOT_FOUND if the symbol is unknown.
    """
    return format_result(ce_client.send_command("get_symbol_info", {"name": name}))

@tool("analysis", "read")
def get_module_size(module_name: str) -> str:
    """Get the in-memory size of a loaded module.

    Requires an attached process.

    Args:
        module_name: Module filename (e.g. 'kernel32.dll').

    Returns JSON with: success, size.
    """
    return format_result(ce_client.send_command("get_module_size", {"module_name": module_name}))

@tool("analysis", "analysis")
def load_new_symbols() -> str:
    """Scan for newly loaded modules and import their symbols.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("load_new_symbols"))

@tool("analysis", "analysis")
def reinitialize_symbol_handler() -> str:
    """Perform a full reset and reload of the Cheat Engine symbol handler.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("reinitialize_symbol_handler"))
# >>> END UNIT-12 <<<
# --- UNIT-11: DEBUG CONTEXT + PER-THREAD BREAKPOINTS ---

@tool("debug", "read")
def debug_get_context(extra_regs: bool = False) -> str:
    """Get the current thread's CPU register context. Set extra_regs=True to include XMM0-15 and FP0-7."""
    return format_result(ce_client.send_command("debug_get_context", {"extra_regs": extra_regs}))

@tool("debug", "write")
def debug_set_context(registers: dict) -> str:
    """Set CPU register values in the paused thread. Pass a dict like {\"RAX\": \"0x1234\", \"RIP\": \"0x140001000\"}."""
    return format_result(ce_client.send_command("debug_set_context", {"registers": registers}))

@tool("debug", "read")
def debug_get_xmm_pointer(xmm_nr: int = 0) -> str:
    """Return the CE-local memory address of an XMM register (0-15) for the currently broken thread."""
    return format_result(ce_client.send_command("debug_get_xmm_pointer", {"xmm_nr": xmm_nr}))

@tool("debug", "write")
def debug_set_last_branch_recording(enable: bool) -> str:
    """Enable or disable Intel LBR (Last Branch Recording). Requires kernel-mode debugger."""
    return format_result(ce_client.send_command("debug_set_last_branch_recording", {"enable": enable}))

@tool("debug", "read")
def debug_get_last_branch_record(index: int) -> str:
    """Get the from/to addresses of a Last Branch Record entry at the given index."""
    return format_result(ce_client.send_command("debug_get_last_branch_record", {"index": index}))

@tool("debug", "write")
def debug_set_breakpoint_for_thread(thread_id: int, address: str, size: int = 1, trigger: str = "execute", max_hits: int = 1000) -> str:
    """Set a breakpoint that fires only on a specific thread. trigger: execute|write|read|access.

    max_hits: Hit buffer size (1-100000, default 1000); only the newest hits are kept.
    """
    return format_result(ce_client.send_command("debug_set_breakpoint_for_thread", {
        "thread_id": thread_id,
        "address": address,
        "size": size,
        "trigger": trigger,
        "max_hits": max_hits,
    }))

@tool("debug", "write")
def debug_remove_breakpoint_for_thread(thread_id: int, address: str) -> str:
    """Remove a per-thread breakpoint at the given address for the given thread."""
    return format_result(ce_client.send_command("debug_remove_breakpoint_for_thread", {
        "thread_id": thread_id,
        "address": address,
    }))

# --- DEBUGGER CONTROL (Unit 10) ---

@tool("debug", "write")
def debug_process(interface: int = 0) -> str:
    """Start the CE debugger for the currently opened process.

    interface: CE debugger interface enum.
      0 = default, 1 = Windows native, 2 = VEH debugger,
      3 = kernel debugger (DBK), 4 = DBVM.
    Requires a process to be attached. Returns {success, interface_used, interface_name}.
    """
    return format_result(ce_client.send_command("debug_process", {"interface": interface}))

@tool("debug", "read")
def debug_is_debugging() -> str:
    """Check whether the CE debugger has been started.

    Always safe to call; no process guard. Returns {success, is_debugging: bool}.
    """
    return format_result(ce_client.send_command("debug_is_debugging"))

@tool("debug", "read")
def debug_get_current_debugger_interface() -> str:
    """Return the active debugger interface used by CE.

    Returns {success, interface: int | null, interface_name: str}.
    interface_name values: 'windows_native', 'veh', 'kernel', 'mac_native', 'gdb', 'none'.
    """
    return format_result(ce_client.send_command("debug_get_current_debugger_interface"))

@tool("debug", "write")
def debug_break_thread(thread_id: int) -> str:
    """Break a specific thread by its thread ID.

    The thread may not stop instantly — it must be scheduled to run first.
    Requires the debugger to be attached. Returns {success}.
    """
    return format_result(ce_client.send_command("debug_break_thread", {"thread_id": thread_id}))

@tool("debug", "write")
def debug_continue(method: str = "run") -> str:
    """Continue execution from a breakpoint.

    method: one of 'run' (co_run), 'step_into' (co_stepinto), 'step_over' (co_stepover).
    Requires the debugger to be attached. Returns {success}.
    Resumes a thread stopped by a mode="break" breakpoint ("run" ends the stop; a step keeps it under bridge
    control, see get_halted_state).
    """
    return format_result(ce_client.send_command("debug_continue", {"method": method}))

@tool("debug", "write")
def debug_detach() -> str:
    """Detach the debugger from the target process if possible.

    Returns {success, detached: bool}. Safe to call when no debugger is active.
    """
    return format_result(ce_client.send_command("debug_detach"))

@tool("debug", "write")
def pause_process() -> str:
    """Pause (freeze) the currently opened process using CE's global pause() function.

    Requires a process to be attached. Returns {success}.
    """
    return format_result(ce_client.send_command("pause_process"))

@tool("debug", "write")
def unpause_process() -> str:
    """Resume (unfreeze) the currently opened process using CE's global unpause() function.

    Requires a process to be attached. Returns {success}.
    """
    return format_result(ce_client.send_command("unpause_process"))
# --- CODE INJECTION & EXECUTION ---

@tool("scripting", "exec")
def inject_dll(filepath: str, skip_symbol_reload: bool = False) -> str:
    """Inject a DLL into the currently attached target process.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    Args:
        filepath: Absolute path to the DLL or dylib to inject.
        skip_symbol_reload: If True, skips waiting for symbol reload after injection.

    Returns:
        JSON with {success}.
    """
    return format_result(ce_client.send_command("inject_dll", {
        "filepath": filepath,
        "skip_symbol_reload": skip_symbol_reload,
    }))

@tool("scripting", "exec")
def inject_dotnet_dll(
    filepath: str,
    class_name: str,
    method_name: str,
    param: str = "",
    timeout: int = -1,
) -> str:
    """Inject a .NET DLL and invoke a static method in the target process.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    The method must be declared as: public static int MethodName(string parameters).

    Args:
        filepath: Absolute path to the managed (.NET) DLL.
        class_name: Fully-qualified class name (e.g. 'MyNamespace.MyClass').
        method_name: Name of the static method to call.
        param: String parameter passed to the method.
        timeout: Milliseconds to wait for return (-1 = wait indefinitely).

    Returns:
        JSON with {success, result} where result is the integer return value.
    """
    return format_result(ce_client.send_command("inject_dotnet_dll", {
        "filepath":    filepath,
        "class_name":  class_name,
        "method_name": method_name,
        "param":       param,
        "timeout":     timeout,
    }))

@tool("scripting", "exec")
def execute_code(address: str, param: int = 0, timeout: int = -1) -> str:
    """Call a stdcall function with one argument at the given address in the target process.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    Args:
        address: Address (hex string or symbol) of the function to call.
        param: Integer argument passed as the single parameter.
        timeout: Milliseconds to wait (-1 = indefinitely).

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(ce_client.send_command("execute_code", {
        "address": address,
        "param":   param,
        "timeout": timeout,
    }))

@tool("scripting", "exec")
def execute_code_ex(
    call_method: int,
    timeout: int,
    address: str,
    args: list = None,
) -> str:
    """Call a function with an explicit calling convention and multiple arguments.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    call_method values:
        0 = stdcall
        1 = cdecl
        2 = thiscall
        3 = fastcall

    Args:
        call_method: Integer calling convention identifier.
        timeout: Milliseconds to wait (-1 = indefinitely, 0 = fire-and-forget).
        address: Address (hex string or symbol) of the function to call.
        args: List of arguments. Each element can be a raw value (CE guesses type)
              or a dict with keys 'type' and 'value'.

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(ce_client.send_command("execute_code_ex", {
        "call_method": call_method,
        "timeout":     timeout,
        "address":     address,
        "args":        args or [],
    }))

@tool("scripting", "exec")
def execute_method(
    address: str,
    instance: str,
    args: list = None,
    call_method: int = 0,
    timeout: int = -1,
) -> str:
    """Call a C++ instance method with an implicit 'this' pointer in the target process.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    The instance pointer is placed into the register selected by call_method (ECX by default
    for thiscall). If instance is None the call behaves like execute_code_ex.

    Args:
        address: Address (hex string or symbol) of the method to call.
        instance: Address of the object instance ('this' pointer).
        args: List of additional arguments passed after 'this'.
        call_method: Calling convention (0=stdcall, 1=cdecl, 2=thiscall, 3=fastcall).
        timeout: Milliseconds to wait (-1 = indefinitely).

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(ce_client.send_command("execute_method", {
        "address":     address,
        "instance":    instance,
        "args":        args or [],
        "call_method": call_method,
        "timeout":     timeout,
    }))

@tool("scripting", "exec")
def execute_code_local(address: str, param: int = 0) -> str:
    """Call a stdcall function inside Cheat Engine's own process (NOT the target).

    Security warning: Executes arbitrary code in the CE process. Use with caution.

    Useful for calling CE internal helpers or code loaded into CE itself.

    Args:
        address: Address within CE's memory space to call.
        param: Integer argument passed as the single parameter.

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(ce_client.send_command("execute_code_local", {
        "address": address,
        "param":   param,
    }))

@tool("scripting", "exec")
def execute_code_local_ex(
    address: str,
    args: list = None,
    call_method: int = 0,
) -> str:
    """Call a function inside Cheat Engine's own process with explicit calling convention.

    Security warning: Executes arbitrary code in the CE process. Use with caution.

    call_method values:
        0 = stdcall
        1 = cdecl
        2 = thiscall
        3 = fastcall

    Args:
        address: Address within CE's memory space to call.
        args: List of arguments passed to the function.
        call_method: Integer calling convention identifier.

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(ce_client.send_command("execute_code_local_ex", {
        "address":     address,
        "args":        args or [],
        "call_method": call_method,
    }))

# >>> BEGIN UNIT-08 Memory Allocation <<<

@tool("memory", "write")
def allocate_memory(size: int, base_address: str = None, protection: str = "rwx") -> str:
    """Allocate memory in the target process.

    Args:
        size: Number of bytes to allocate.
        base_address: Preferred base address as hex string (e.g. "0x140000000"). Optional.
        protection: Access flags — "r" (read-only), "rw" (read-write),
                    "rx" (read-execute), "rwx" (read-write-execute, default).

    Returns JSON with: success, address.
    """
    params = {"size": size, "protection": protection}
    if base_address is not None:
        params["base_address"] = base_address
    return format_result(ce_client.send_command("allocate_memory", params))

@tool("memory", "write")
def free_memory(address: str, size: int = 0) -> str:
    """Free memory previously allocated in the target process.

    Args:
        address: Address of the region to free as hex string.
        size: Size of the region in bytes. Use 0 to let the OS determine it (default).

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("free_memory", {"address": address, "size": size}))

@tool("memory", "write")
def allocate_shared_memory(name: str, size: int) -> str:
    """Create and map a shared memory region in the target process.

    The region is allocated with non-executable protection by default.

    Args:
        name: Unique name for the shared memory object.
        size: Size in bytes. Defaults to 4096 if the region does not yet exist.

    Returns JSON with: success, address.
    """
    return format_result(ce_client.send_command("allocate_shared_memory", {"name": name, "size": size}))

@tool("memory", "read")
def get_memory_protection(address: str) -> str:
    """Query the protection flags of a memory page in the target process.

    Args:
        address: Address to query as hex string.

    Returns JSON with: success, read (bool), write (bool), execute (bool), raw (PAGE_* name).
    """
    return format_result(ce_client.send_command("get_memory_protection", {"address": address}))

@tool("memory", "write")
def set_memory_protection(address: str, size: int, read: bool = True, write: bool = True, execute: bool = True) -> str:
    """Change the protection flags of a memory region in the target process.

    Args:
        address: Start address as hex string.
        size: Size in bytes of the region to protect.
        read: Allow read access (default True).
        write: Allow write access (default True).
        execute: Allow execute access (default True).

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("set_memory_protection", {
        "address": address, "size": size, "read": read, "write": write, "execute": execute
    }))

@tool("memory", "write")
def full_access(address: str, size: int) -> str:
    """Grant full read-write-execute access to a memory region (convenience wrapper).

    Args:
        address: Start address as hex string.
        size: Size in bytes of the region.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("full_access", {"address": address, "size": size}))

@tool("kernel", "write")
def allocate_kernel_memory(size: int) -> str:
    """Allocate non-paged kernel memory via the DBK driver.

    Requires the Cheat Engine kernel driver (DBK) to be loaded.

    Args:
        size: Number of bytes to allocate.

    Returns JSON with: success, address.
    Error codes: DBK_NOT_LOADED if the kernel driver is not active.
    """
    return format_result(ce_client.send_command("allocate_kernel_memory", {"size": size}))

# >>> END UNIT-08 <<<
# >>> BEGIN UNIT-07 Process Lifecycle <<<

@tool("process", "analysis")
def open_process(process_id_or_name: str) -> str:
    """Open a process by PID or name and attach Cheat Engine to it.

    Args:
        process_id_or_name: Numeric PID as string (e.g. "12345") or process name (e.g. "notepad.exe").

    Returns:
        JSON with {success, process_id, process_name}.
    """
    return format_result(ce_client.send_command("open_process", {"process_id_or_name": process_id_or_name}))

@tool("process", "read")
def get_process_list() -> str:
    """Get the list of running processes on the system.

    Returns:
        JSON with {success, count, processes: [{pid: int, name: str}, ...]}.
    """
    return format_result(ce_client.send_command("get_process_list"))

@tool("process", "read")
def get_processid_from_name(name: str) -> str:
    """Look up the PID of a process by its executable name.

    Args:
        name: Process name to search for (e.g. "notepad.exe").

    Returns:
        JSON with {success, process_id} or {success=false, error, error_code="NOT_FOUND"}.
    """
    return format_result(ce_client.send_command("get_processid_from_name", {"name": name}))

@tool("process", "read")
def get_foreground_process() -> str:
    """Get the PID and window handle of the process currently in the foreground.

    Returns:
        JSON with {success, process_id, window_handle}.
    """
    return format_result(ce_client.send_command("get_foreground_process"))

@tool("process", "exec")
def create_process(path: str, args: str = "", debug: bool = False, break_on_entry: bool = False) -> str:
    """Create and optionally debug a new process.

    Args:
        path: Full path to the executable.
        args: Command-line arguments string (default empty).
        debug: Attach Windows debugger if True.
        break_on_entry: Break on entry point if True (requires debug=True).

    Returns:
        JSON with {success, process_id}.
    """
    return format_result(ce_client.send_command("create_process", {
        "path": path,
        "args": args,
        "debug": debug,
        "break_on_entry": break_on_entry,
    }))

@tool("process", "read")
def get_opened_process_id() -> str:
    """Get the PID of the process currently attached to Cheat Engine.

    Returns:
        JSON with {success, process_id} or {success=false, error_code="NO_PROCESS"}.
    """
    return format_result(ce_client.send_command("get_opened_process_id"))

@tool("process", "read")
def get_opened_process_handle() -> str:
    """Get the OS handle of the process currently attached to Cheat Engine as a hex string.

    Returns:
        JSON with {success, handle} where handle is a hex string.
    """
    return format_result(ce_client.send_command("get_opened_process_handle"))

# >>> END UNIT-07 <<<

# >>> BEGIN UNIT-25 Operations: bridge_status, read_struct, batch, async jobs <<<

MAX_WAIT_FOR_JOB_SECONDS = 90.0   # keep below typical MCP host tool timeouts (e.g. 120 s)


@tool("process", "read")
def bridge_status() -> str:
    """Health/diagnostics report for the Cheat Engine bridge. Works even when CE is unreachable.

    Returns bridge version, uptime, attached process (pid/name/arch), DBK/DBVM state, breakpoint and
    hardware-slot usage, async job counts, request statistics (count, errors, slowest/last command),
    the 'Query memory region routines' safety setting (best effort) and a `warnings` list.
    `python_side` shows this MCP server's own transport, timeouts and last connection error. When CE
    cannot be reached the result has reachable=false plus a `hint` explaining the likely cause
    (CE not running, bridge script not loaded, or another MCP client already holding the pipe).
    """
    python_side = {
        "transport": CE_MCP_TRANSPORT,
        "endpoint": PIPE_NAME if CE_MCP_TRANSPORT == "pipe" else f"{CE_MCP_HOST}:{CE_MCP_PORT}",
        "timeout_seconds": CE_MCP_TIMEOUT_SECONDS,
        "profile": CE_MCP_PROFILE,
        "toolsets": sorted(ENABLED_TOOLSETS),
        "python": sys.version.split()[0],
        "server_pid": os.getpid(),
    }
    try:
        result = ce_client.send_command("bridge_status")
    except (OSError, ConnectionError, TimeoutError) as exc:
        reason = str(exc)
        python_side["last_error"] = reason
        if "busy" in reason:
            hint = ("Another MCP server/client already holds the bridge's single pipe (for example Claude Desktop and "
                    "Claude Code both configured with this bridge). Close the other client first.")
        elif "not found" in reason or "not reachable" in reason:
            hint = ("The bridge is not reachable: start Cheat Engine and load ce_mcp_bridge.lua "
                    "(its Lua console should print 'MCP Server Listening').")
        else:
            hint = "Cheat Engine did not answer; see `error` and check CE's Lua console."
        return format_result({
            "success": False, "reachable": False, "error": reason,
            "error_code": "CE_API_UNAVAILABLE", "hint": hint, "python_side": python_side,
        })
    if isinstance(result, dict):
        result["reachable"] = True
        result["python_side"] = python_side
    return format_result(result)


@tool("memory", "read")
def read_struct(address: str, fields: list[dict]) -> str:
    """Read several typed fields with ONE memory read (much cheaper than many read_integer calls).

    Args:
        fields: [{"name", "type", "offset"?, "size"?}]. Without offset a field follows the previous one (packed), so
                give offsets for real structs. Types: i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 ptr bool bytes cstring
                wstring (also byte word dword qword float double int short pointer string utf16). size = byte length
                for bytes/cstring, characters for wstring.

    Returns fields[{name, type, offset, value, hex?, error?}]; pointers and u64 > 2^63 as hex. An unreadable field gets
    an error instead of failing the call. Max 512 fields, 64 KB span.
    """
    return format_result(ce_client.send_command("read_struct", {"address": address, "fields": fields}))


# Wire methods that are dispatcher aliases of a tool.
_WIRE_ALIASES = {
    "read_bytes": "read_memory", "pattern_scan": "aob_scan",
    "set_execution_breakpoint": "set_breakpoint", "set_write_breakpoint": "set_data_breakpoint",
    "find_what_writes_safe": "start_dbvm_watch", "find_what_accesses_safe": "start_dbvm_watch",
    "get_watch_results": "stop_dbvm_watch",
}


def _batch_gate(requests):
    """Reasons a batch must be refused. A batch runs inside the bridge, past the per-tool registration that
    CE_MCP_TOOLSETS / CE_MCP_PROFILE decide, so each request is judged as the tool it stands for: it must be
    registered here, and a name that is not a tool at all is refused."""
    problems = []
    for i, req in enumerate(requests):
        method = req["method"]
        tool_name = _WIRE_ALIASES.get(method, method)
        if tool_name not in TOOL_TOOLSET:
            problems.append(f"requests[{i}]: '{method}' is not a tool of this server")
        elif _registration_status(tool_name) != "enabled":
            problems.append(f"requests[{i}]: '{method}' is not available ({_registration_status(tool_name)}; "
                            f"profile={CE_MCP_PROFILE}, toolsets={','.join(sorted(ENABLED_TOOLSETS))})")
    return problems


@tool("process", "write")
def batch_commands(requests: list[dict], stop_on_error: bool = False) -> str:
    """Run several bridge commands in ONE round trip (and one slot on CE's main thread).

    Args:
        requests: List of {"method": "<tool name>", "params": {...}} using the same names/params as the
                  individual tools, e.g. [{"method": "read_integer", "params": {"address": "0x1000"}}].
                  Max 100; nesting batch_commands is not allowed. Every method must be a tool that is registered
                  under the active CE_MCP_TOOLSETS / CE_MCP_PROFILE, otherwise the whole batch is refused.
        stop_on_error: Stop at the first failing request (default: run all).

    Returns JSON with: success, requested, executed, failed, results[] (one result object per request, in order).
    """
    problems = []
    for i, req in enumerate(requests):
        method = req.get("method") if isinstance(req, dict) else None
        if not isinstance(method, str) or not method:
            problems.append(f"requests[{i}] needs a 'method'")
        elif method == "batch":
            problems.append(f"requests[{i}]: batch cannot be nested")
    if problems:
        return format_result({"success": False, "error": "; ".join(problems), "error_code": "INVALID_PARAMS"})
    denied = _batch_gate(requests)
    if denied:
        return format_result({"success": False, "error": "; ".join(denied), "error_code": "PERMISSION_DENIED"})
    return format_result(ce_client.send_command("batch", {"requests": requests, "stop_on_error": stop_on_error}))


@tool("analysis", "analysis")
def start_job(kind: str, params: dict = None) -> str:
    """Start a long-running operation in the background; returns a job_id at once (CE stays responsive, the
    call cannot time out). Poll get_job or block with wait_for_job, then get_job_result. Up to 4 jobs at once.

    Args:
        kind: scan_all | next_scan | aob_scan | find_references | find_call_references | find_xrefs | rtti_scan |
              find_string_refs | find_code_caves | find_pointer_path.
        params: The parameters of the matching blocking tool, e.g. scan_all {"value": "100", "type": "dword"}.

    While a scan_all/next_scan job runs, scan_all, next_scan and get_scan_results answer BUSY; cancelling a
    next_scan discards the scan session.
    """
    return format_result(ce_client.send_command("start_job", {"kind": kind, "params": params or {}}))


@tool("analysis", "read")
def get_job(job_id: str) -> str:
    """Status of a job: state (running|done|failed|cancelled), phase, progress {current,total,percent},
    elapsed_seconds, and a small result_summary once done. Use get_job_result for the full data."""
    return format_result(ce_client.send_command("get_job", {"job_id": job_id}))


@tool("analysis", "read")
def get_job_result(job_id: str, offset: int = 0, limit: int = 100) -> str:
    """Result of a finished job, shaped like the blocking tool's reply (e.g. count for scans; total/offset/
    limit/returned + addresses|references|callers for list results). `offset`/`limit` page through lists.
    A job that is still running answers error_code BUSY."""
    return format_result(ce_client.send_command("get_job_result", {"job_id": job_id, "offset": offset, "limit": limit}))


@tool("analysis", "read")
def wait_for_job(job_id: str, timeout_seconds: float = 30.0, poll_interval: float = 0.5) -> str:
    """Wait (polling get_job) until a job leaves the 'running' state or the timeout passes.

    Returns the final get_job status, or the latest status with timed_out=true if it is still running
    (just call again). timeout_seconds is capped at 90. CE is not blocked while waiting.
    """
    timeout = max(0.0, min(float(timeout_seconds), MAX_WAIT_FOR_JOB_SECONDS))
    poll = max(0.1, min(float(poll_interval), 5.0))
    deadline = time.monotonic() + timeout
    while True:
        status = ce_client.send_command("get_job", {"job_id": job_id})
        if not isinstance(status, dict) or not status.get("success") or status.get("state") != "running":
            return format_result(status)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            status["timed_out"] = True
            status["hint"] = "Job is still running; call wait_for_job or get_job again."
            return format_result(status)
        time.sleep(min(poll, remaining))


@tool("analysis", "analysis")
def cancel_job(job_id: str) -> str:
    """Cancel a running job and free its resources. Cancelling a next_scan discards the active scan
    session (run scan_all again). Cancelling a finished job is a harmless no-op."""
    return format_result(ce_client.send_command("cancel_job", {"job_id": job_id}))


@tool("analysis", "read")
def list_jobs() -> str:
    """List tracked jobs (running ones plus the 20 most recent finished) with their status."""
    return format_result(ce_client.send_command("list_jobs"))

# >>> END UNIT-25 <<<

# >>> BEGIN UNIT-26 Analysis: PE/modules, address translation, RTTI, string refs, code caves, pointer paths, snapshots <<<


def _params(**kw):
    """Keyword arguments -> bridge params, dropping None / empty strings so Lua sees 'not given'."""
    return {k: v for k, v in kw.items() if v is not None and v != ""}


def _run_job(kind, params, wait_seconds, limit, offset=0):
    """start_job + wait up to `wait_seconds` + get_job_result. Returns the job id and status if still running."""
    started = ce_client.send_command("start_job", {"kind": kind, "params": params})
    if not isinstance(started, dict) or not started.get("success"):
        return started
    job_id = started["job_id"]
    deadline = time.monotonic() + max(0.0, min(float(wait_seconds), MAX_WAIT_FOR_JOB_SECONDS))
    while True:
        status = ce_client.send_command("get_job", {"job_id": job_id})
        if not isinstance(status, dict) or not status.get("success"):
            return status
        state = status.get("state")
        if state == "running":
            if time.monotonic() >= deadline:
                status["timed_out"] = True
                status["hint"] = (f"Still running in the background. Call wait_for_job('{job_id}') and then "
                                  f"get_job_result('{job_id}') for the data.")
                return status
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
            continue
        if state == "done":
            return ce_client.send_command("get_job_result", {"job_id": job_id, "offset": offset, "limit": limit})
        return status


# ---- PE / modules ---------------------------------------------------------------------------------

@tool("analysis", "read")
def pe_info(module: str = "") -> str:
    """Parse a loaded module's PE headers from memory: architecture, entry point, preferred vs actual base
    (relocated?), sections with rwx flags and addresses, data directories, subsystem, timestamp.

    Args:
        module: Module name (case-insensitive, substring ok) or an address inside it. Empty = the main module.
    """
    return format_result(ce_client.send_command("pe_info", _params(module=module)))


@tool("analysis", "read")
def pe_imports(module: str = "", dll: str = "", offset: int = 0, limit: int = 100) -> str:
    """List a module's imports: dll, function name (or ordinal + hint), IAT slot address, and the address the
    IAT currently holds (`resolved`, plus the module that contains it, so you can spot hooked imports).

    Args:
        module: Module name or address inside it (empty = main module).
        dll: Only imports from DLLs whose name contains this text.
        offset, limit: Pagination (default 100 per page).
    """
    return format_result(ce_client.send_command("pe_imports", _params(module=module, dll=dll, offset=offset, limit=limit)))


@tool("analysis", "read")
def pe_exports(module: str = "", name_contains: str = "", offset: int = 0, limit: int = 100) -> str:
    """List a module's exports: name, ordinal, RVA, address and forwarder text for forwarded exports.

    Args:
        module: Module name or address inside it (empty = main module).
        name_contains: Case-insensitive name filter.
        offset, limit: Pagination (default 100 per page).
    """
    return format_result(ce_client.send_command("pe_exports", _params(module=module, name_contains=name_contains, offset=offset, limit=limit)))


@tool("analysis", "read")
def pe_tls_callbacks(module: str = "") -> str:
    """List a module's TLS callbacks (code that runs before the entry point; common in packers and anti-debug).
    Returns each callback's address, RVA, section and owning module, plus the TLS directory fields."""
    return format_result(ce_client.send_command("pe_tls_callbacks", _params(module=module)))


# ---- address translation / IDA exchange -----------------------------------------------------------

@tool("analysis", "read")
def va_to_rva(address: str = "", addresses: list[str] = None, ida_image_base: str = "", include_section: bool = True) -> str:
    """Convert runtime addresses to module + RVA (and section). Give `address` or a list in `addresses`.

    If `ida_image_base` is given (IDA's image base, from IDA's metadata), each result also carries
    `ida_address` = ida_image_base + rva, i.e. the address to jump to in IDA.
    Result `expression` is a CE-usable "module+0xRVA" string.
    """
    return format_result(ce_client.send_command("va_to_rva", _params(
        address=address, addresses=addresses, ida_image_base=ida_image_base, include_section=include_section)))


@tool("analysis", "read")
def rva_to_va(module: str = "", rva: str = "", rvas: list[str] = None, ida_image_base: str = "") -> str:
    """Convert RVAs of a module into runtime addresses (give `rva` or `rvas`; hex strings like "0x1A2B" or numbers).
    With `ida_image_base` also returns the matching IDA address."""
    return format_result(ce_client.send_command("rva_to_va", _params(module=module, rva=rva, rvas=rvas, ida_image_base=ida_image_base)))


@tool("analysis", "read")
def rebase_address(address: str = "", addresses: list[str] = None, from_base: str = "", from_module: str = "",
                   to_base: str = "", to_module: str = "") -> str:
    """Move addresses between two images loaded at different bases, e.g. an IDA address into the running
    process: from_base="0x140000000" (IDA image base), to_module="game.exe". Each side is a base address
    or a module name. Returns the new address and the shared RVA."""
    return format_result(ce_client.send_command("rebase_address", _params(
        address=address, addresses=addresses, from_base=from_base, from_module=from_module, to_base=to_base, to_module=to_module)))


@tool("analysis", "read")
def export_names(module: str = "", sources: list[str] = None, format: str = "json", ida_image_base: str = "",
                 include_types: bool = True) -> str:
    """Export names for use in IDA: CE registered symbols and/or RTTI vtables of one module.

    Args:
        module: Module name (empty = main module).
        sources: any of "symbols" (CE registered symbols inside the module) and "rtti" (vtables found by the last
                 rtti_scan_module of this module). Default both.
        format: "json" (entries with rva, name, ida_name, kind) or "idapython" (a ready-to-run IDAPython script that
                renames and comments each address relative to the loaded image base).
        ida_image_base: Adds `ida_address` to each entry.
        include_types: Also return `c_declarations` (vtable/class struct skeletons built from RTTI) that can be fed
                       to IDA's declare_c_type.
    """
    return format_result(ce_client.send_command("export_names", _params(
        module=module, sources=sources, format=format, ida_image_base=ida_image_base, include_types=include_types)))


@tool("analysis", "read")
def export_structures(name: str = "") -> str:
    """C declarations for Cheat Engine's structure definitions (all, or the one called `name`), with padding for gaps
    and a trailing pad up to the declared size. Paste into IDA's Local Types / declare_c_type."""
    return format_result(ce_client.send_command("export_structures", _params(name=name)))


@tool("analysis", "analysis")
def import_names(names: list[dict], module: str = "", ida_image_base: str = "", address_is_ida: bool = False,
                 prefix: str = "", do_not_save: bool = True) -> str:
    """Register names (e.g. renamed functions from IDA) as CE symbols so they show up in disassembly and can be used
    in address expressions. At most 5000 per call.

    Args:
        names: [{"name": "Player::Update", "rva": "0x1A2B30"}, {"name": "x", "address": "0x7FF6..."}].
               `rva` needs `module`. With address_is_ida=true an `address` is treated as an IDA address and rebased
               using ida_image_base into `module`.
        prefix: Prepended to every name.
        do_not_save: Keep the symbols out of saved cheat tables (default true).
    """
    return format_result(ce_client.send_command("import_names", _params(
        names=names, module=module, ida_image_base=ida_image_base, address_is_ida=address_is_ida or None,
        prefix=prefix, do_not_save=do_not_save)))


# ---- long-running analysis (background jobs; each waits up to wait_seconds, then returns the job id) ----

@tool("analysis", "analysis")
def rtti_scan_module(module: str = "", max_vtable_entries: int = 256, wait_seconds: float = 30.0, limit: int = 200, offset: int = 0) -> str:
    """Find every MSVC RTTI class in a module: class name (demangled + raw), vtable address/RVA, number of virtual
    functions, this-pointer offset (non-zero = secondary base vtable) and the base-class chain. x64 and x86.
    Results are cached so export_names can emit them for IDA.

    Runs as a background job. Returns the classes when finished within `wait_seconds`; otherwise returns
    {state:"running", job_id, progress} - call wait_for_job / get_job_result later.
    """
    return format_result(_run_job("rtti_scan", _params(module=module, max_vtable_entries=max_vtable_entries), wait_seconds, limit, offset))


@tool("analysis", "analysis")
def find_string_refs(text: str = "", address: str = "", module: str = "", wide: bool = False, match: str = "start",
                     include_data: bool = True, wait_seconds: float = 30.0, limit: int = 100) -> str:
    """Find the code and data that reference a string.

    Give `text` (looked up in the module's data sections; wide=true for UTF-16) or the string's `address`.
    `match`: "start" (default, the text must begin a string) or "any" (also mid-string hits).
    Finds x64 rip-relative `lea reg,[rip+disp]` (how compilers load string addresses), absolute pointers in code
    (x86 push/mov imm32) and, with include_data, absolute pointers stored in data sections.
    Each reference has kind (rip_lea | abs_code | abs_data), address, module+RVA expression, section and disassembly.
    Background job; see rtti_scan_module for the wait/timeout behaviour.
    """
    return format_result(_run_job("find_string_refs", _params(
        text=text, address=address, module=module, wide=wide or None, match=match, include_data=include_data), wait_seconds, limit))


@tool("analysis", "analysis")
def find_xrefs(address: str, size: int = 1, module: str = "", kinds: str = "", max_results: int = 5000,
               wait_seconds: float = 30.0, limit: int = 100, offset: int = 0) -> str:
    """Find what references `address` (or [address, address+size)): who calls a function, who touches a
    variable, which table points at it. Static references in module code and data: call/jmp/jcc (rel32, rel8), x64
    rip-relative operands (`access`: read|write|read/write|address|call|jump), absolute pointers in code (abs_code) and
    data (abs_data), 32-bit RVAs in data (rva). Each hit has address, module+RVA expression, section, instruction and
    function_start; `functions` counts the referencing functions. Heap/stack pointers are not found (find_pointer_path).
    Background job; waiting works as in rtti_scan_module.

    Args:
        size: Target range length (absolute pointers in code are only searched up to 16).
        module: A module name, "all", or empty = the module containing address (else the main module).
        kinds: Comma separated subset of call, jmp, jcc, rip, abs, abs_code, abs_data, rva (default all).
        max_results: Stop after this many raw hits (default 5000; sets `truncated`).
    """
    return format_result(_run_job("find_xrefs", _params(address=address, size=size if size != 1 else None, module=module,
                                                        kinds=kinds, max_results=max_results if max_results != 5000 else None),
                                  wait_seconds, limit, offset))


@tool("analysis", "analysis")
def find_code_caves(module: str = "", byte: int = 204, min_size: int = 16, sections: str = "exec", wait_seconds: float = 30.0, limit: int = 100) -> str:
    """Find runs of padding bytes (default 0xCC; also 0x00 or 0x90) of at least `min_size` bytes where you can place
    patches or hooks. `sections`: "exec" (executable sections only, default) or "all". Largest first.
    Background job; see rtti_scan_module for the wait/timeout behaviour."""
    return format_result(_run_job("find_code_caves", _params(module=module, byte=byte, min_size=min_size, sections=sections), wait_seconds, limit))


@tool("analysis", "analysis")
def find_pointer_path(address: str, max_depth: int = 3, max_offset: int = 1024, max_per_level: int = 16,
                      max_results: int = 100, protection: str = "+W", save_as: str = "", wait_seconds: float = 30.0,
                      limit: int = 100) -> str:
    """Find static pointer chains to `address` (a value that moves between runs) by scanning backwards:
    each level searches for pointers within max_offset below the current holders (nearby holders share one scan),
    keeps the best max_per_level, and stops at holders inside a module (the module+RVA base). Every chain is verified.
    Results: base, offsets (outermost first), expression ("[[game.exe+0x1234]+0x40]+0x100"). Far less thorough than
    CE's pointer scanner; each scan covers the whole process (seconds to minutes).

    save_as="hp" keeps the chains as a pointer set for compare_pointer_paths after the target restarts (sets are saved
    to disk and survive reloads). Background job; waiting works as in rtti_scan_module, cancel_job stops it.
    """
    return format_result(_run_job("find_pointer_path", _params(
        address=address, max_depth=max_depth, max_offset=max_offset, max_per_level=max_per_level,
        max_results=max_results, protection=protection, save_as=save_as), wait_seconds, limit))


# ---- snapshots ----------------------------------------------------------------------------------------

@tool("analysis", "analysis")
def snapshot_region(address: str = "", size: int = 0, name: str = "", module: str = "", section: str = "") -> str:
    """Save a copy of a memory region (max 64 MB each, 128 MB / 16 snapshots in total) so you can later diff it:
    take one, change something in the game, take another, then diff_snapshots to see which values changed - without
    running a first scan over the whole process. Give address+size, or module+section (e.g. module="game.exe",
    section=".data"). Unreadable pages are zero-filled and reported in `unreadable_bytes`. Re-using a name replaces it."""
    return format_result(ce_client.send_command("snapshot_region", _params(address=address, size=size or None, name=name, module=module, section=section)))


@tool("analysis", "read")
def list_snapshots() -> str:
    """List saved snapshots (name, address, size, unreadable bytes) and the memory they use."""
    return format_result(ce_client.send_command("list_snapshots"))


@tool("analysis", "analysis")
def delete_snapshot(name: str = "", all: bool = False) -> str:
    """Delete one snapshot by name, or all of them with all=true."""
    return format_result(ce_client.send_command("delete_snapshot", _params(name=name, all=all or None)))


@tool("analysis", "read")
def diff_snapshots(snapshots: list[str], pattern: str = "", unit: int = 4, offset: int = 0, length: int = 0,
                   merge_gap: int = 0, limit: int = 200) -> str:
    """Compare 2+ snapshots of one region ("live" = current memory) and list the units that changed as
    described: the unknown-value workflow without scans.

    Args:
        snapshots: Names in time order, e.g. ["before", "after_hit", "after_heal"].
        pattern: One letter per consecutive pair: C changed, U unchanged, ? any (default all C).
        unit: 1, 2, 4 (default, adds float views) or 8 (double views) bytes.
        offset, length: Sub-range of the region. merge_gap: merge matches this close into `groups` (default unit).

    Returns total_matches, matches[{address, offset, old, new, ...}] and groups (likely fields).
    """
    return format_result(ce_client.send_command("diff_snapshots", _params(
        snapshots=snapshots, pattern=pattern, unit=unit, offset=offset or None, length=length or None,
        merge_gap=merge_gap or None, limit=limit)))

# >>> END UNIT-26 <<<

# >>> BEGIN UNIT-27 Functions (.pdata), struct recovery, breakpoint control <<<

@tool("analysis", "read")
def pe_functions(module: str = "", address: str = "", offset: int = 0, limit: int = 100, include_unwind: bool = False) -> str:
    """x64 function table (.pdata) of a module (default: the one containing address, else the main module).
    With `address`: the function containing it (begin/end/size, expression, handler, unwind info; cold fragments are
    resolved to their primary function). found=false: no entry (leaf function), use find_function_boundaries.
    Without: a page of the table; include_unwind adds prolog/handler info. x86 modules have none (available=false).
    """
    return format_result(ce_client.send_command("pe_functions", _params(
        module=module, address=address, offset=offset, limit=limit, include_unwind=include_unwind or None)))

@tool("analysis", "analysis")
def recover_struct(address: str = "", addresses: list[str] = None, size: int = 0, name: str = "", create: bool = False,
                   max_vtable_entries: int = 0) -> str:
    """Recover the layout of a polymorphic MSVC class from live instance(s): RTTI class name, bases,
    vtable and virtual functions (x64: exact sizes from .pdata), and fields inferred from memory (typed pointers,
    floats, doubles, ints, inline text, zero gaps). Several instances of the SAME class give much better guesses.

    Args:
        address / addresses: 1 to 16 object addresses of one class.
        size: Bytes to analyse (default 0x100, max 0x4000; the all-zero tail is dropped).
        create: Also create a CE structure (named `name`, default the class name).
        max_vtable_entries: Cap for the virtual function list (default 64).

    Returns class_name, bases, vtable, fields[{offset,size,kind,type,name,samples}], virtual_functions and a
    c_declaration for IDA. Heuristic: check the samples (int/float and float pairs can be misjudged).
    """
    return format_result(ce_client.send_command("recover_struct", _params(
        address=address, addresses=addresses, size=size or None, name=name, create=create or None,
        max_vtable_entries=max_vtable_entries or None)))

@tool("debug", "read")
def get_halted_state(stack_depth: int = 16, extend_ms: int = 0) -> str:
    """State of a thread stopped by a mode="break" breakpoint (or by stepping from one).

    Returns halted=false when nothing is stopped (last_halt says how the last stop ended: resumed, timeout,
    breakpoint removed, resumed outside the bridge). When halted: fresh registers, the instruction at RIP, the stack,
    the memory the breakpoint asked to inspect, the hit, and auto_resume_in_seconds (the watchdog countdown).
    extend_ms postpones the watchdog. Resume with debug_continue(method="run" | "step_into" | "step_over"); after a step,
    call this again to see the new position.
    """
    return format_result(ce_client.send_command("get_halted_state", _params(stack_depth=stack_depth, extend_ms=extend_ms or None)))

# >>> END UNIT-27 <<<

# >>> BEGIN UNIT-30 Pointer path sets: comparing pointer chains across runs <<<

@tool("analysis", "analysis")
def compare_pointer_paths(target: str, name: str = "", chains: list[dict] = None, save_as: str = "", near_delta: int = 256,
                          near_limit: int = 10, offset: int = 0, limit: int = 100) -> str:
    """Two-run pointer comparison: which chains from an earlier run still reach the value now?
    Run 1: find_pointer_path(save_as="hp") (or pass chains from CE's pointer scanner). Restart the target, find the
    value again, then call this with `target` = its new address: chains are re-resolved from their module+RVA base and
    those landing exactly on target survive (runs+1). Reads memory only.

    Args:
        target: Address of the same value in the current process.
        name / chains: A stored set (list_pointer_sets) OR inline [{"base": "game.exe+0x1A2B3C" | address,
                "offsets": [0x40, 0x10]}] (offsets outermost first, applied after each dereference).
        save_as: Store the survivors under this name (= name narrows that set). Empty results never overwrite a set.
        near_delta, near_limit: Chains ending within +-near_delta bytes are listed as near_misses with suggested_offsets.

    Returns hits, missed, unreadable, module_missing, same_process (target not restarted: weak evidence) and the
    surviving chains, most-confirmed first.
    """
    return format_result(ce_client.send_command("compare_pointer_paths", _params(
        target=target, name=name, chains=chains, save_as=save_as, near_delta=near_delta if near_delta != 256 else None,
        near_limit=near_limit if near_limit != 10 else None, offset=offset or None, limit=limit)))


@tool("analysis", "read")
def list_pointer_sets() -> str:
    """List the stored pointer chain sets (name, chain_count, runs, history of the runs that produced them).
    Sets are saved to a file (saved_to; save_error if that failed), so they survive a reload of the bridge and a restart
    of Cheat Engine."""
    return format_result(ce_client.send_command("list_pointer_sets"))


@tool("analysis", "read")
def get_pointer_set(name: str, offset: int = 0, limit: int = 100) -> str:
    """The chains of a stored set (base, offsets, expression, runs) plus its run history. Feed them to
    validate_pointer_chains or write them into a cheat table; runs says in how many separate runs a chain reached its value."""
    return format_result(ce_client.send_command("get_pointer_set", {"name": name, "offset": offset, "limit": limit}))


@tool("analysis", "analysis")
def drop_pointer_set(name: str = "", all: bool = False) -> str:
    """Delete one stored pointer set by name, or all of them with all=true."""
    return format_result(ce_client.send_command("drop_pointer_set", _params(name=name, all=all or None)))

# >>> END UNIT-30 <<<

# >>> BEGIN UNIT-31 Patch journal and undo <<<

@tool("memory", "read")
def list_patches(active_only: bool = False, offset: int = 0, limit: int = 50) -> str:
    """The patch journal, newest first: every write through write_memory, write_integer, write_string,
    copy_memory (with dest) and auto_assemble, with the bytes it replaced (a write's reply carries its patch_id).
    state: applied | changed (overwritten since) | undone | not_undoable (see reason) | other_process | unreadable.
    Not journaled: memory records, kernel/physical writes, injected code. Saved to disk (saved_to): after a reload of
    the bridge byte patches stay undoable while the same process is attached; script patches do not.
    """
    return format_result(ce_client.send_command("list_patches", _params(active_only=active_only or None, offset=offset or None, limit=limit)))


@tool("memory", "write")
def undo_patch(id: str = "", all: bool = False, force: bool = False) -> str:
    """Undo a journaled write: put the original bytes back (an auto_assemble patch runs its script's [DISABLE] section).

    Args:
        id: The patch id ("p12") from a write tool's reply or list_patches.
        all: Undo every active patch of the current process instead, newest first (so stacked patches unwind cleanly).
        force: Restore even if the bytes changed since the patch (by the game, another tool or a later patch). Without
               it such an undo is refused with conflict=true, so a newer patch is never silently torn out underneath.
    """
    return format_result(ce_client.send_command("undo_patch", _params(id=id, all=all or None, force=force or None)))


@tool("memory", "analysis")
def drop_patches(which: str = "inactive") -> str:
    """Forget patch journal entries; the target's memory is not touched, but a forgotten patch can no longer be undone.

    Args:
        which: "inactive" (default) forgets the undone ones, those made in another process and those that cannot be
               undone; "all" empties the journal.
    """
    return format_result(ce_client.send_command("drop_patches", {"which": which}))

# >>> END UNIT-31 <<<

if __name__ == "__main__":
    try:
        debug_log("Starting FastMCP server (v12/v99 compatible)...")
        mcp.run()
    except Exception as e:
        debug_log(f"Fatal Crash: {e}")
        traceback.print_exc(file=sys.stderr)
