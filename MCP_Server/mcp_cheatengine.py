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
        """
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


def tool(toolset):
    """Register an MCP tool in a toolset (replaces a bare @mcp.tool())."""
    if toolset not in TOOLSETS:
        raise ValueError(f"unknown toolset {toolset!r}")

    def decorator(fn):
        TOOL_TOOLSET[fn.__name__] = toolset
        if toolset in ENABLED_TOOLSETS:
            mcp.tool()(_run_off_event_loop(fn))
        return fn
    return decorator


@tool("process")
def list_toolsets() -> str:
    """List tool groups and which are enabled. Disabled groups are enabled by
    setting CE_MCP_TOOLSETS in the MCP server's environment and restarting it.
    """
    groups = {}
    for name, group in TOOL_TOOLSET.items():
        groups.setdefault(group, []).append(name)
    return format_result({
        "success": True,
        "enabled": sorted(ENABLED_TOOLSETS),
        "toolsets": {
            group: {
                "enabled": group in ENABLED_TOOLSETS,
                "description": TOOLSETS[group],
                "tools": sorted(groups.get(group, [])),
            }
            for group in TOOLSETS
        },
        "how_to_enable": "Set CE_MCP_TOOLSETS (e.g. 'memory,scan,debug' or 'all') in the MCP server config and restart it.",
    })

# --- PROCESS & MODULES ---

@tool("process")
def get_process_info() -> str:
    """Get current process ID, name, modules count and architecture."""
    return format_result(ce_client.send_command("get_process_info"))

@tool("process")
def enum_modules(offset: int = 0, limit: int = 100) -> str:
    """List all loaded modules (DLLs) with their base addresses and sizes.

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum modules to return (default 100, max 10000).

    Returns JSON with: success, total, offset, limit, returned, modules.
    """
    return format_result(ce_client.send_command("enum_modules", {"offset": offset, "limit": limit}))

@tool("process")
def get_thread_list(offset: int = 0, limit: int = 100) -> str:
    """Get list of threads in the attached process.

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum threads to return (default 100, max 10000).

    Returns JSON with: success, total, offset, limit, returned, threads.
    """
    return format_result(ce_client.send_command("get_thread_list", {"offset": offset, "limit": limit}))

@tool("process")
def get_symbol_address(symbol: str) -> str:
    """Resolve a symbol name (e.g., 'Engine.GameEngine') to an address."""
    return format_result(ce_client.send_command("get_symbol_address", {"symbol": symbol}))

@tool("process")
def get_address_info(address: str, include_modules: bool = True, include_symbols: bool = True, include_sections: bool = False) -> str:
    """Get symbolic name and module info for an address (Reverse of get_symbol_address)."""
    return format_result(ce_client.send_command("get_address_info", {
        "address": address, 
        "include_modules": include_modules, 
        "include_symbols": include_symbols,
        "include_sections": include_sections
    }))

@tool("process")
def get_rtti_classname(address: str) -> str:
    """Try to identify the class name of an object at address using Run-Time Type Information."""
    return format_result(ce_client.send_command("get_rtti_classname", {"address": address}))

# --- MEMORY READING ---

@tool("memory")
def read_memory(address: str, size: int = 256) -> str:
    """Read raw bytes from memory."""
    return format_result(ce_client.send_command("read_memory", {"address": address, "size": size}))

@tool("memory")
def read_integer(address: str, type: str = "dword") -> str:
    """Read a number from memory. Types: byte, word, dword, qword, float, double."""
    return format_result(ce_client.send_command("read_integer", {"address": address, "type": type}))

@tool("memory")
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

@tool("memory")
def read_pointer(address: str, offsets: list[int] = None) -> str:
    """Read a pointer chain. Returns the final address and value."""
    # Bridge supports 'read_pointer' for single dereference or 'read_pointer_chain' for multiple
    if offsets:
        return format_result(ce_client.send_command("read_pointer_chain", {"base": address, "offsets": offsets}))
    else:
        return format_result(ce_client.send_command("read_pointer_chain", {"base": address, "offsets": [0]}))

@tool("memory")
def read_pointer_chain(base: str, offsets: list[int]) -> str:
    """Follow a multi-level pointer chain and return analysis of every step."""
    return format_result(ce_client.send_command("read_pointer_chain", {"base": base, "offsets": offsets}))

@tool("memory")
def analyze_pointer_access(instruction: str, registers: dict, accessed_address: str = None, is_64bit: bool = None) -> str:
    """Parse a captured memory access (instruction + register snapshot from a breakpoint/DBVM hit) into base register, displacement, and the concrete struct-base address for pointer-chain walk-back. Pure analysis; no process access. next_scan_value is the address to scan for (as a pointer) to find the next level up."""
    return format_result(ce_client.send_command("analyze_pointer_access", {
        "instruction": instruction,
        "registers": registers,
        "accessed_address": accessed_address,
        "is_64bit": is_64bit,
    }))

@tool("memory")
def validate_pointer_chains(chains: list, target: str, include_misses: bool = False) -> str:
    """Resolve a list of candidate pointer chains and report which currently land on `target`. Each chain is {"base": <addr|symbol>, "offsets": [int,...]}. Returns only matches by default (token-frugal); set include_misses=true to also list non-matches. Re-run after a game restart with the new target to find chains that stay valid (the stable pointer). Max 5000 chains per call."""
    return format_result(ce_client.send_command("validate_pointer_chains", {
        "chains": chains,
        "target": target,
        "include_misses": include_misses,
    }))

@tool("memory")
def checksum_memory(address: str, size: int) -> str:
    """Calculate MD5 checksum of a memory region to detect changes."""
    return format_result(ce_client.send_command("checksum_memory", {"address": address, "size": size}))

# --- SCANNING ---

@tool("scan")
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

@tool("scan")
def get_scan_results(offset: int = 0, limit: int = 100, max: int = None) -> str:
    """Get results from the last 'scan_all' operation.

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum results to return (default 100, max 10000). Preferred over 'max'.
        max: Deprecated alias for 'limit'. Use 'limit' instead.

    Returns JSON with: success, total, offset, limit, returned, results.
    """
    return format_result(ce_client.send_command("get_scan_results", {"offset": offset, "limit": limit, "max": max}))

@tool("scan")
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

@tool("memory")
def write_integer(address: str, value: int, type: str = "dword") -> str:
    """Write a number to memory. Types: byte, word, dword, qword, float, double."""
    return format_result(ce_client.send_command("write_integer", {"address": address, "value": value, "type": type}))

@tool("memory")
def write_memory(address: str, bytes: list[int]) -> str:
    """Write raw bytes to memory."""
    return format_result(ce_client.send_command("write_memory", {"address": address, "bytes": bytes}))

@tool("memory")
def write_string(address: str, value: str, wide: bool = False) -> str:
    """Write a string to memory (ASCII or Wide/UTF-16)."""
    return format_result(ce_client.send_command("write_string", {"address": address, "value": value, "wide": wide}))


@tool("scan")
def aob_scan(pattern: str, protection: str = "+X", limit: int = 100) -> str:
    """Scan for an Array of Bytes (AOB) pattern. Example: '48 89 5C 24'."""
    return format_result(ce_client.send_command("aob_scan", {"pattern": pattern, "protection": protection, "limit": limit}))

@tool("scan")
def search_string(string: str, wide: bool = False, limit: int = 100) -> str:
    """Quickly search for a text string in memory."""
    return format_result(ce_client.send_command("search_string", {"string": string, "wide": wide, "limit": limit}))

@tool("scan")
def generate_signature(address: str) -> str:
    """Generate a unique AOB signature that can find this specific address again."""
    return format_result(ce_client.send_command("generate_signature", {"address": address}))

@tool("scan")
def get_memory_regions(max: int = 100) -> str:
    """Get list of valid memory regions nearby common bases."""
    return format_result(ce_client.send_command("get_memory_regions", {"max": max}))

@tool("scan")
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

@tool("analysis")
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

@tool("analysis")
def get_instruction_info(address: str) -> str:
    """Get detailed info about a single instruction (size, bytes, opcode)."""
    return format_result(ce_client.send_command("get_instruction_info", {"address": address}))

@tool("analysis")
def find_function_boundaries(address: str, max_search: int = 4096) -> str:
    """Attempt to find the start and end of a function containing the address."""
    return format_result(ce_client.send_command("find_function_boundaries", {"address": address, "max_search": max_search}))

@tool("analysis")
def analyze_function(address: str) -> str:
    """Analyze a function to find all CALL instructions output (calls made by this function)."""
    return format_result(ce_client.send_command("analyze_function", {"address": address}))

@tool("analysis")
def find_references(address: str, offset: int = 0, limit: int = 50) -> str:
    """Find instructions that access (reference) this address.

    Args:
        address: Target address to find references to.
        offset: Start index for pagination (default 0).
        limit: Maximum references to return (default 50, max 10000).

    Returns JSON with: success, target, total, offset, limit, returned, references, arch.
    """
    return format_result(ce_client.send_command("find_references", {"address": address, "offset": offset, "limit": limit}))

@tool("analysis")
def find_call_references(function_address: str, offset: int = 0, limit: int = 100) -> str:
    """Find all locations that CALL this function.

    Args:
        function_address: Address of the function to find callers of.
        offset: Start index for pagination (default 0).
        limit: Maximum callers to return (default 100, max 10000).

    Returns JSON with: success, function_address, total, offset, limit, returned, callers.
    """
    return format_result(ce_client.send_command("find_call_references", {"address": function_address, "offset": offset, "limit": limit}))

@tool("analysis")
def dissect_structure(address: str, size: int = 256) -> str:
    """Use CE's auto-guess feature to interpret memory at address as a structure."""
    return format_result(ce_client.send_command("dissect_structure", {"address": address, "size": size}))

# --- DEBUGGING & BREAKPOINTS ---

@tool("debug")
def set_breakpoint(address: str, id: str = None, capture_registers: bool = True, capture_stack: bool = False, stack_depth: int = 16, max_hits: int = 1000) -> str:
    """Set a hardware execution breakpoint. Non-breaking/Logging only.

    Args:
        capture_stack: Record stack slots; hit.stack[0] is [SP+0] (the return
            address on a function-entry breakpoint).
        max_hits: Hit buffer size (1-100000, default 1000). Only the newest
            hits are kept; hit_count/dropped_hits report the overflow.
    """
    return format_result(ce_client.send_command("set_breakpoint", {
        "address": address,
        "id": id,
        "capture_registers": capture_registers,
        "capture_stack": capture_stack,
        "stack_depth": stack_depth,
        "max_hits": max_hits,
    }))

@tool("debug")
def set_data_breakpoint(address: str, id: str = None, access_type: str = "w", size: int = 4, max_hits: int = 1000) -> str:
    """Set a hardware data breakpoint (watchpoint). Types: 'r' (read), 'w' (write), 'rw' (access).

    max_hits: Hit buffer size (1-100000, default 1000); only the newest hits are kept.
    """
    return format_result(ce_client.send_command("set_data_breakpoint", {
        "address": address,
        "id": id,
        "access_type": access_type,
        "size": size,
        "max_hits": max_hits,
    }))

@tool("debug")
def remove_breakpoint(id: str) -> str:
    """Remove a breakpoint by its ID."""
    return format_result(ce_client.send_command("remove_breakpoint", {"id": id}))

@tool("debug")
def list_breakpoints() -> str:
    """List all active breakpoints."""
    return format_result(ce_client.send_command("list_breakpoints"))

@tool("debug")
def clear_all_breakpoints() -> str:
    """Remove ALL breakpoints."""
    return format_result(ce_client.send_command("clear_all_breakpoints"))

@tool("debug")
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

@tool("kernel")
def get_physical_address(address: str) -> str:
    """Translate Virtual Address to Physical Address (requires DBVM)."""
    return format_result(ce_client.send_command("get_physical_address", {"address": address}))

@tool("kernel")
def start_dbvm_watch(address: str, mode: str = "w", max_entries: int = 1000) -> str:
    """Start invisible DBVM hypervisor watch. Modes: 'w' (writes), 'r' (reads), 'x' (execute)."""
    return format_result(ce_client.send_command("start_dbvm_watch", {"address": address, "mode": mode, "max_entries": max_entries}))

@tool("kernel")
def stop_dbvm_watch(address: str) -> str:
    """Stop DBVM watch and return results."""
    return format_result(ce_client.send_command("stop_dbvm_watch", {"address": address}))

@tool("kernel")
def poll_dbvm_watch(address: str, max_results: int = 1000) -> str:
    """Poll DBVM watch logs WITHOUT stopping. Returns register state at each execution hit."""
    return format_result(ce_client.send_command("poll_dbvm_watch", {
        "address": address, 
        "max_results": max_results
    }))

# --- KERNEL MODE / DBVM EXTENSIONS (Unit 21) ---

@tool("kernel")
def dbk_get_cr0() -> str:
    """Read Control Register 0 (CR0) via the DBK kernel driver.

    Requires the DBK kernel driver to be loaded (CE Settings -> Debugger -> Kernelmode).
    Returns cr0 as a hex string.
    """
    return format_result(ce_client.send_command("dbk_get_cr0"))

@tool("kernel")
def dbk_get_cr3() -> str:
    """Read Control Register 3 (CR3 — page-table base) via DBK or DBVM.

    Works when either the DBK kernel driver or the DBVM hypervisor is loaded.
    Returns cr3 as a hex string.
    """
    return format_result(ce_client.send_command("dbk_get_cr3"))

@tool("kernel")
def dbk_get_cr4() -> str:
    """Read Control Register 4 (CR4) via the DBK kernel driver.

    Requires the DBK kernel driver to be loaded (CE Settings -> Debugger -> Kernelmode).
    Returns cr4 as a hex string.
    """
    return format_result(ce_client.send_command("dbk_get_cr4"))

@tool("kernel")
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

@tool("kernel")
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

@tool("kernel")
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

@tool("kernel")
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

@tool("kernel")
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

@tool("kernel")
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

@tool("scripting")
def evaluate_lua(code: str) -> str:
    """Execute arbitrary Lua code in Cheat Engine.

    Returns JSON with: success, result (tostring of the first return value),
    results (every return value as structured JSON; tables are converted with
    depth/size limits and cycle detection), result_count.
    """
    return format_result(ce_client.send_command("evaluate_lua", {"code": code}))

@tool("scripting")
def auto_assemble(script: str) -> str:
    """Run an AutoAssembler script (injection, code caves, etc)."""
    return format_result(ce_client.send_command("auto_assemble", {"script": script}))

@tool("scripting")
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


@tool("scripting")
def auto_assemble_check(
    script: str,
    enable: bool = True,
    target_self: bool = False,
) -> str:
    """Validate an Auto Assembler script for syntax errors without executing it.

    Returns {success, valid: bool, errors: [str]}.
    enable: True checks the [Enable] section; False checks [Disable].
    target_self: if True, validates against CE's own process instead of the target.
    """
    return format_result(ce_client.send_command("auto_assemble_check", {
        "script": script,
        "enable": enable,
        "target_self": target_self,
    }))


@tool("scripting")
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


@tool("scripting")
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


@tool("scripting")
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


@tool("scripting")
def generate_code_injection_script(address: str) -> str:
    """Generate a boilerplate code-injection Auto Assembler script for an address.

    Requires an attached process.
    Returns {success, script: str} — the script can be used as a starting point
    for patching code at that location.
    """
    return format_result(ce_client.send_command("generate_code_injection_script", {
        "address": address,
    }))


@tool("process")
def ping() -> str:
    """Check connectivity and get version info."""
    return format_result(ce_client.send_command("ping"))

# --- DEBUG OUTPUT & MULTIMEDIA (Unit 23) ---

@tool("gui")
def output_debug_string(message: str) -> str:
    """Post a message to the Windows debugger via OutputDebugString (readable with tools like DebugView)."""
    return format_result(ce_client.send_command("output_debug_string", {"message": message}))

@tool("gui")
def speak_text(text: str, english_only: bool = False) -> str:
    """Speak text via Windows SAPI text-to-speech. Set english_only=True to force the English voice."""
    return format_result(ce_client.send_command("speak_text", {"text": text, "english_only": english_only}))

@tool("gui")
def play_sound(filename: str) -> str:
    """Play a WAV sound file by filename. Path must not contain '..' directory traversal."""
    return format_result(ce_client.send_command("play_sound", {"filename": filename}))

@tool("gui")
def beep() -> str:
    """Play a simple system beep sound."""
    return format_result(ce_client.send_command("beep", {}))

@tool("gui")
def set_progress_state(state: str) -> str:
    """Set the Cheat Engine taskbar progress state. Valid states: none, normal, paused, error, indeterminate."""
    return format_result(ce_client.send_command("set_progress_state", {"state": state}))

@tool("gui")
def set_progress_value(current: int, max: int) -> str:
    """Set the Cheat Engine taskbar progress bar position. Provide current value and maximum value."""
    return format_result(ce_client.send_command("set_progress_value", {"current": current, "max": max}))
# --- THREADING & SYNCHRONIZATION (Unit-22) ---

@tool("scripting")
def create_thread(code: str, arg: str = "") -> str:
    """Execute Lua code in a new CE thread.

    SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process,
    carrying the same risk as evaluate_lua. Only use with trusted code.

    Returns {success, thread_id}.
    """
    return format_result(ce_client.send_command("create_thread", {"code": code, "arg": arg}))

@tool("scripting")
def get_global_variable(name: str) -> str:
    """Read a global variable from CE's main Lua state.

    Useful for reading values set by scripts running in other threads.
    Returns {success, value} where value is stringified via tostring().
    """
    return format_result(ce_client.send_command("get_global_variable", {"name": name}))

@tool("scripting")
def set_global_variable(name: str, value: str) -> str:
    """Write a global variable in CE's main Lua state.

    Useful for passing values to scripts running in other threads.
    Returns {success}.
    """
    return format_result(ce_client.send_command("set_global_variable", {"name": name, "value": value}))

@tool("scripting")
def queue_to_main_thread(code: str) -> str:
    """Queue Lua code to run on CE's main thread without waiting for its result.

    SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process
    on the main thread, carrying the same risk as evaluate_lua. Only use with
    trusted code.

    Returns {success}.
    """
    return format_result(ce_client.send_command("queue_to_main_thread", {"code": code}))

@tool("scripting")
def check_synchronize() -> str:
    """Process queued main-thread calls (checkSynchronize).

    Call this from an infinite loop in the main thread when using threading
    and synchronize calls. Returns {success}.
    """
    return format_result(ce_client.send_command("check_synchronize"))

@tool("scripting")
def in_main_thread() -> str:
    """Check whether the current code is running in CE's main thread.

    Returns {success, is_main_thread}.
    """
    return format_result(ce_client.send_command("in_main_thread"))
# >>> BEGIN UNIT-20b Shell Execution <<<
def _check_shell_gate():
    if os.environ.get("CE_MCP_ALLOW_SHELL") != "1":
        return json.dumps({
            "success": False,
            "error": "Shell execution disabled. Set environment variable CE_MCP_ALLOW_SHELL=1 to enable.",
            "error_code": "PERMISSION_DENIED"
        })
    return None

@tool("system")
def run_command(command: str, args: str = "") -> str:
    """Execute a shell command in the host OS. SECURITY: Arbitrary code execution.

    REQUIRES environment variable CE_MCP_ALLOW_SHELL=1 at server startup.
    By default, this tool returns a PERMISSION_DENIED error.

    Args:
        command: Command path or name (e.g. "notepad.exe", "cmd.exe").
        args: Arguments string.

    Returns JSON with: success, output, exit_code.
    """
    blocked = _check_shell_gate()
    if blocked:
        return blocked
    return format_result(ce_client.send_command("run_command", {"command": command, "args": args}))

@tool("system")
def shell_execute(command: str, args: str = "", verb: str = "open", working_dir: str = "", showcommand: int = None) -> str:
    """Invoke Windows ShellExecute. SECURITY: Arbitrary code execution.

    REQUIRES environment variable CE_MCP_ALLOW_SHELL=1 at server startup.

    Args:
        command: Command or file to execute.
        args: Arguments string.
        verb: ShellExecute verb. CE currently supports "open" only.
        working_dir: Working directory (empty for current).
        showcommand: Optional Win32 show command integer.

    Returns JSON with: success.
    """
    blocked = _check_shell_gate()
    if blocked:
        return blocked
    params = {
        "command": command,
        "args": args,
        "verb": verb,
        "working_dir": working_dir,
    }
    if showcommand is not None:
        params["showcommand"] = showcommand
    return format_result(ce_client.send_command("shell_execute", params))
# >>> END UNIT-20b <<<
# >>> BEGIN UNIT-20a File IO Clipboard <<<

@tool("system")
def file_exists(filename: str) -> str:
    """Check whether a file exists at the given path. Returns {success, exists: bool}."""
    return format_result(ce_client.send_command("file_exists", {"filename": filename}))

@tool("system")
def delete_file(filename: str) -> str:
    """Delete a file at the given path. Returns {success}.

    WARNING: This is a destructive operation. The file will be permanently deleted
    from disk. Path traversal sequences ('..') are blocked by the bridge. Use with
    extreme caution — there is no undo.
    """
    return format_result(ce_client.send_command("delete_file", {"filename": filename}))

@tool("system")
def get_file_list(path: str) -> str:
    """List files in the given directory path. Returns {success, count, files: [str]}."""
    return format_result(ce_client.send_command("get_file_list", {"path": path}))

@tool("system")
def get_directory_list(path: str) -> str:
    """List subdirectories in the given directory path. Returns {success, count, directories: [str]}."""
    return format_result(ce_client.send_command("get_directory_list", {"path": path}))

@tool("system")
def get_temp_folder() -> str:
    """Return the path to the system temp folder. Returns {success, path: str}."""
    return format_result(ce_client.send_command("get_temp_folder"))

@tool("system")
def get_file_version(filename: str) -> str:
    """Get the version info of a file (major, minor, release, build). Returns {success, major, minor, release, build, version_string}."""
    return format_result(ce_client.send_command("get_file_version", {"filename": filename}))

@tool("system")
def read_clipboard() -> str:
    """Read text from the system clipboard. Returns {success, text: str}."""
    return format_result(ce_client.send_command("read_clipboard"))

@tool("system")
def write_clipboard(text: str) -> str:
    """Write text to the system clipboard. Returns {success}."""
    return format_result(ce_client.send_command("write_clipboard", {"text": text}))

# >>> END UNIT-20a <<<
# >>> BEGIN UNIT-19 Structure Management <<<

@tool("analysis")
def create_structure(name: str) -> str:
    """Create a new empty CE structure definition and add it to the global list.

    Args:
        name: The name for the new structure.

    Returns JSON with: success, structure_id.
    """
    return format_result(ce_client.send_command("create_structure", {"name": name}))


@tool("analysis")
def get_structure_by_name(name: str) -> str:
    """Find a CE structure by name in the global structure list.

    Args:
        name: The structure name to search for.

    Returns JSON with: success, structure_id, name, element_count, size.
    """
    return format_result(ce_client.send_command("get_structure_by_name", {"name": name}))


@tool("analysis")
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


@tool("analysis")
def get_structure_elements(structure_id: int) -> str:
    """Get all elements of a CE structure.

    Args:
        structure_id: The structure ID.

    Returns JSON with: success, structure_id, elements (list of {name, offset, type, size}).
    """
    return format_result(ce_client.send_command("get_structure_elements", {"structure_id": structure_id}))


@tool("analysis")
def export_structure_to_xml(structure_id: int) -> str:
    """Export a CE structure definition as XML.

    Args:
        structure_id: The structure ID.

    Returns JSON with: success, xml (XML string representation of the structure).
    """
    return format_result(ce_client.send_command("export_structure_to_xml", {"structure_id": structure_id}))


@tool("analysis")
def delete_structure(structure_id: int) -> str:
    """Delete a CE structure from the global list and free it.

    Args:
        structure_id: The structure ID to delete.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("delete_structure", {"structure_id": structure_id}))

# >>> END UNIT-19 <<<
# >>> BEGIN UNIT-18 Cheat Table Records <<<

@tool("table")
def load_table(filename: str, merge: bool = False) -> str:
    """Load a Cheat Engine table (.ct) file into the current session.

    Args:
        filename: Path to the .ct or .cetrainer file to load.
        merge: If True, merge with the current table instead of replacing it.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("load_table", {"filename": filename, "merge": merge}))

@tool("table")
def save_table(filename: str, protect: bool = False) -> str:
    """Save the current cheat table to a file.

    Args:
        filename: Destination path for the .ct or .cetrainer file.
        protect: If True and the filename has a .cetrainer extension, protect it from normal reading.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("save_table", {"filename": filename, "protect": protect}))

@tool("table")
def get_address_list(offset: int = 0, limit: int = 100) -> str:
    """List memory records in the current cheat table's address list.

    Args:
        offset: Zero-based index of the first record to return.
        limit: Maximum number of records to return (default 100).

    Returns JSON with: success, total, offset, limit, returned, records (list of
    {id, description, address, type, value, offsets, enabled}).
    """
    return format_result(ce_client.send_command("get_address_list", {"offset": offset, "limit": limit}))

@tool("table")
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

@tool("table")
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

@tool("table")
def delete_memory_record(id: int) -> str:
    """Delete a memory record from the cheat table address list by ID.

    Args:
        id: Unique numeric ID of the memory record to delete.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("delete_memory_record", {"id": id}))

@tool("table")
def get_memory_record_value(id: int) -> str:
    """Read the current value of a memory record as a string.

    Args:
        id: Unique numeric ID of the memory record.

    Returns JSON with: success, value (string representation of the current value).
    """
    return format_result(ce_client.send_command("get_memory_record_value", {"id": id}))

@tool("table")
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

@tool("gui")
def get_pixel(x: int, y: int) -> str:
    """Get the colour of a screen pixel at (x, y). Returns r, g, b channels and the raw COLORREF integer."""
    return format_result(ce_client.send_command("get_pixel", {"x": x, "y": y}))

@tool("gui")
def get_mouse_pos() -> str:
    """Get the current mouse cursor position. Returns x and y screen coordinates."""
    return format_result(ce_client.send_command("get_mouse_pos"))

@tool("gui")
def set_mouse_pos(x: int, y: int) -> str:
    """Move the mouse cursor to screen position (x, y)."""
    return format_result(ce_client.send_command("set_mouse_pos", {"x": x, "y": y}))

@tool("gui")
def is_key_pressed(vk: int) -> str:
    """Check whether a key is currently held down.
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space, 0x01 for left mouse button).
    Returns pressed: bool."""
    return format_result(ce_client.send_command("is_key_pressed", {"vk": vk}))

@tool("gui")
def key_down(vk: int) -> str:
    """Simulate pressing a key down (does NOT release it automatically).
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space)."""
    return format_result(ce_client.send_command("key_down", {"vk": vk}))

@tool("gui")
def key_up(vk: int) -> str:
    """Release a key that was pressed with key_down.
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space)."""
    return format_result(ce_client.send_command("key_up", {"vk": vk}))

@tool("gui")
def do_key_press(vk: int) -> str:
    """Simulate a full key press (down + up) for the given key.
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space)."""
    return format_result(ce_client.send_command("do_key_press", {"vk": vk}))

@tool("gui")
def get_screen_info() -> str:
    """Get the primary screen dimensions and DPI. Returns width, height (pixels) and dpi."""
    return format_result(ce_client.send_command("get_screen_info"))
# --- WINDOW / GUI TOOLS (Unit-16) ---

@tool("gui")
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

@tool("gui")
def get_window_caption(handle: str) -> str:
    """Return the caption (title bar text) of a window given its handle (hex string)."""
    return format_result(ce_client.send_command("get_window_caption", {"handle": handle}))

@tool("gui")
def get_window_class_name(handle: str) -> str:
    """Return the window class name of a window given its handle (hex string)."""
    return format_result(ce_client.send_command("get_window_class_name", {"handle": handle}))

@tool("gui")
def get_window_process_id(handle: str) -> str:
    """Return the process ID that owns a window given its handle (hex string)."""
    return format_result(ce_client.send_command("get_window_process_id", {"handle": handle}))

@tool("gui")
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

@tool("gui")
def show_message(message: str) -> str:
    """Show a modal message dialog in Cheat Engine.

    WARNING — NOT SAFE FOR AUTOMATED WORKFLOWS:
    This call BLOCKS the CE main thread until the user dismisses the dialog by
    clicking OK.  Do not invoke from automation that expects a timely response.

    Returns {success} after the user closes the dialog.
    """
    return format_result(ce_client.send_command("show_message", {"message": message}))

@tool("gui")
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

@tool("gui")
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

@tool("scan")
def aob_scan_unique(pattern: str, protection: str = "+X") -> str:
    """Scan for an AOB pattern that must match exactly once. Returns {success, address} or error with count.
    Use this when you expect a signature to be unique in the process."""
    return format_result(ce_client.send_command("aob_scan_unique", {"pattern": pattern, "protection": protection}))

@tool("scan")
def aob_scan_module(pattern: str, module_name: str, protection: str = "+X") -> str:
    """Scan for an AOB pattern restricted to a specific module's memory range.
    Returns {success, count, addresses: [str]}."""
    return format_result(ce_client.send_command("aob_scan_module", {
        "pattern": pattern,
        "module_name": module_name,
        "protection": protection
    }))

@tool("scan")
def aob_scan_module_unique(pattern: str, module_name: str, protection: str = "+X") -> str:
    """Scan for an AOB pattern in a specific module that must match exactly once.
    Returns {success, address} or error with count."""
    return format_result(ce_client.send_command("aob_scan_module_unique", {
        "pattern": pattern,
        "module_name": module_name,
        "protection": protection
    }))

@tool("scan")
def pointer_rescan(value: str, previous_results_file: str = None) -> str:
    """Re-scan an existing pointer scan for a new value. Requires a prior pointer scan in CE.
    Returns {success, result_count}. Run a Pointer Scanner scan in CE first."""
    params = {"value": value}
    if previous_results_file:
        params["previous_results_file"] = previous_results_file
    return format_result(ce_client.send_command("pointer_rescan", params))

@tool("scan")
def create_persistent_scan(name: str) -> str:
    """Create a named, stateful memory scan session. Use the name with persistent_scan_* tools.
    Returns {success, scan_name}."""
    return format_result(ce_client.send_command("create_persistent_scan", {"name": name}))

@tool("scan")
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

@tool("scan")
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

@tool("scan")
def persistent_scan_get_results(name: str, offset: int = 0, limit: int = 100) -> str:
    """Get paginated results from a named persistent scan session.
    Returns {success, total, offset, limit, results: [{address, value}]}."""
    return format_result(ce_client.send_command("persistent_scan_get_results", {
        "name": name,
        "offset": offset,
        "limit": limit
    }))

@tool("scan")
def persistent_scan_destroy(name: str) -> str:
    """Destroy a named persistent scan session and free its memory.
    Returns {success, scan_name, destroyed}."""
    return format_result(ce_client.send_command("persistent_scan_destroy", {"name": name}))
# --- MEMORY OPERATIONS (Unit 14) ---

@tool("memory")
def copy_memory(source: str, size: int, dest: str = None, method: int = 0) -> str:
    """Copy memory between addresses. Methods: 0=target→target, 1=target→CE, 2=CE→target, 3=CE→CE. Returns dest_address allocated by CE if dest is None."""
    return format_result(ce_client.send_command("copy_memory", {
        "source": source, "size": size, "dest": dest, "method": method
    }))

@tool("memory")
def compare_memory(addr1: str, addr2: str, size: int, method: int = 0) -> str:
    """Compare two memory regions. Methods: 0=target/target, 1=addr1=target addr2=CE, 2=both CE. Returns equal flag and first_diff byte index (-1 if equal)."""
    return format_result(ce_client.send_command("compare_memory", {
        "addr1": addr1, "addr2": addr2, "size": size, "method": method
    }))

@tool("memory")
def write_region_to_file(address: str, size: int, filename: str) -> str:
    """Write a memory region to a file. Filename must be an absolute path and must not contain '..' components."""
    return format_result(ce_client.send_command("write_region_to_file", {
        "address": address, "size": size, "filename": filename
    }))

@tool("memory")
def read_region_from_file(filename: str, destination: str) -> str:
    """Read a file into memory at the given destination address. Filename must be an absolute path and must not contain '..' components."""
    return format_result(ce_client.send_command("read_region_from_file", {
        "filename": filename, "destination": destination
    }))

@tool("memory")
def md5_memory(address: str, size: int) -> str:
    """Calculate the MD5 hash of a memory region. Returns the hash as a hex string."""
    return format_result(ce_client.send_command("md5_memory", {
        "address": address, "size": size
    }))

@tool("memory")
def md5_file(filename: str) -> str:
    """Calculate the MD5 hash of a file on the CE host. Filename must not contain '..' components."""
    return format_result(ce_client.send_command("md5_file", {"filename": filename}))

@tool("memory")
def create_section(size: int) -> str:
    """Create a Windows section (shared memory) of the given size. Returns a handle as a hex string."""
    return format_result(ce_client.send_command("create_section", {"size": size}))

@tool("memory")
def map_view_of_section(handle: str, address: str = None, size: int = 0) -> str:
    """Map a section into the target process. 'handle' is from create_section. 'address' is optional preferred base. Returns mapped_address."""
    return format_result(ce_client.send_command("map_view_of_section", {
        "handle": handle, "address": address, "size": size
    }))

# >>> BEGIN UNIT-12 Symbol Management <<<
@tool("analysis")
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

@tool("analysis")
def unregister_symbol(name: str) -> str:
    """Remove a previously registered user-defined symbol.

    Args:
        name: Symbol name to unregister.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("unregister_symbol", {"name": name}))

@tool("analysis")
def enum_registered_symbols() -> str:
    """List all user-registered symbols.

    Returns JSON with: success, count, symbols (list of {name, address, module}).
    """
    return format_result(ce_client.send_command("enum_registered_symbols"))

@tool("analysis")
def delete_all_registered_symbols() -> str:
    """Delete every user-registered symbol (both AA and Lua).

    Returns JSON with: success, deleted_count.
    """
    return format_result(ce_client.send_command("delete_all_registered_symbols"))

@tool("analysis")
def enable_windows_symbols() -> str:
    """Trigger download and load of Windows PDB symbol files.

    Note: The actual PDB download and indexing is asynchronous; this call returns
    immediately once the process has been initiated by Cheat Engine.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("enable_windows_symbols"))

@tool("analysis")
def enable_kernel_symbols() -> str:
    """Enable kernel-mode symbol resolution (requires DBK driver).

    Returns JSON with: success.
    On failure returns error_code DBK_NOT_LOADED if the kernel driver is absent.
    """
    return format_result(ce_client.send_command("enable_kernel_symbols"))

@tool("analysis")
def get_symbol_info(name: str) -> str:
    """Retrieve detailed information about a known symbol.

    Requires an attached process.

    Args:
        name: Symbol or export name to look up.

    Returns JSON with: success, name, address, module, size.
    Returns error_code NOT_FOUND if the symbol is unknown.
    """
    return format_result(ce_client.send_command("get_symbol_info", {"name": name}))

@tool("analysis")
def get_module_size(module_name: str) -> str:
    """Get the in-memory size of a loaded module.

    Requires an attached process.

    Args:
        module_name: Module filename (e.g. 'kernel32.dll').

    Returns JSON with: success, size.
    """
    return format_result(ce_client.send_command("get_module_size", {"module_name": module_name}))

@tool("analysis")
def load_new_symbols() -> str:
    """Scan for newly loaded modules and import their symbols.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("load_new_symbols"))

@tool("analysis")
def reinitialize_symbol_handler() -> str:
    """Perform a full reset and reload of the Cheat Engine symbol handler.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("reinitialize_symbol_handler"))
# >>> END UNIT-12 <<<
# --- UNIT-11: DEBUG CONTEXT + PER-THREAD BREAKPOINTS ---

@tool("debug")
def debug_get_context(extra_regs: bool = False) -> str:
    """Get the current thread's CPU register context. Set extra_regs=True to include XMM0-15 and FP0-7."""
    return format_result(ce_client.send_command("debug_get_context", {"extra_regs": extra_regs}))

@tool("debug")
def debug_set_context(registers: dict) -> str:
    """Set CPU register values in the paused thread. Pass a dict like {\"RAX\": \"0x1234\", \"RIP\": \"0x140001000\"}."""
    return format_result(ce_client.send_command("debug_set_context", {"registers": registers}))

@tool("debug")
def debug_get_xmm_pointer(xmm_nr: int = 0) -> str:
    """Return the CE-local memory address of an XMM register (0-15) for the currently broken thread."""
    return format_result(ce_client.send_command("debug_get_xmm_pointer", {"xmm_nr": xmm_nr}))

@tool("debug")
def debug_set_last_branch_recording(enable: bool) -> str:
    """Enable or disable Intel LBR (Last Branch Recording). Requires kernel-mode debugger."""
    return format_result(ce_client.send_command("debug_set_last_branch_recording", {"enable": enable}))

@tool("debug")
def debug_get_last_branch_record(index: int) -> str:
    """Get the from/to addresses of a Last Branch Record entry at the given index."""
    return format_result(ce_client.send_command("debug_get_last_branch_record", {"index": index}))

@tool("debug")
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

@tool("debug")
def debug_remove_breakpoint_for_thread(thread_id: int, address: str) -> str:
    """Remove a per-thread breakpoint at the given address for the given thread."""
    return format_result(ce_client.send_command("debug_remove_breakpoint_for_thread", {
        "thread_id": thread_id,
        "address": address,
    }))

# --- DEBUGGER CONTROL (Unit 10) ---

@tool("debug")
def debug_process(interface: int = 0) -> str:
    """Start the CE debugger for the currently opened process.

    interface: CE debugger interface enum.
      0 = default, 1 = Windows native, 2 = VEH debugger,
      3 = kernel debugger (DBK), 4 = DBVM.
    Requires a process to be attached. Returns {success, interface_used, interface_name}.
    """
    return format_result(ce_client.send_command("debug_process", {"interface": interface}))

@tool("debug")
def debug_is_debugging() -> str:
    """Check whether the CE debugger has been started.

    Always safe to call; no process guard. Returns {success, is_debugging: bool}.
    """
    return format_result(ce_client.send_command("debug_is_debugging"))

@tool("debug")
def debug_get_current_debugger_interface() -> str:
    """Return the active debugger interface used by CE.

    Returns {success, interface: int | null, interface_name: str}.
    interface_name values: 'windows_native', 'veh', 'kernel', 'mac_native', 'gdb', 'none'.
    """
    return format_result(ce_client.send_command("debug_get_current_debugger_interface"))

@tool("debug")
def debug_break_thread(thread_id: int) -> str:
    """Break a specific thread by its thread ID.

    The thread may not stop instantly — it must be scheduled to run first.
    Requires the debugger to be attached. Returns {success}.
    """
    return format_result(ce_client.send_command("debug_break_thread", {"thread_id": thread_id}))

@tool("debug")
def debug_continue(method: str = "run") -> str:
    """Continue execution from a breakpoint.

    method: one of 'run' (co_run), 'step_into' (co_stepinto), 'step_over' (co_stepover).
    Requires the debugger to be attached. Returns {success}.
    """
    return format_result(ce_client.send_command("debug_continue", {"method": method}))

@tool("debug")
def debug_detach() -> str:
    """Detach the debugger from the target process if possible.

    Returns {success, detached: bool}. Safe to call when no debugger is active.
    """
    return format_result(ce_client.send_command("debug_detach"))

@tool("debug")
def pause_process() -> str:
    """Pause (freeze) the currently opened process using CE's global pause() function.

    Requires a process to be attached. Returns {success}.
    """
    return format_result(ce_client.send_command("pause_process"))

@tool("debug")
def unpause_process() -> str:
    """Resume (unfreeze) the currently opened process using CE's global unpause() function.

    Requires a process to be attached. Returns {success}.
    """
    return format_result(ce_client.send_command("unpause_process"))
# --- CODE INJECTION & EXECUTION ---

@tool("scripting")
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

@tool("scripting")
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

@tool("scripting")
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

@tool("scripting")
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

@tool("scripting")
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

@tool("scripting")
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

@tool("scripting")
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

@tool("memory")
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

@tool("memory")
def free_memory(address: str, size: int = 0) -> str:
    """Free memory previously allocated in the target process.

    Args:
        address: Address of the region to free as hex string.
        size: Size of the region in bytes. Use 0 to let the OS determine it (default).

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("free_memory", {"address": address, "size": size}))

@tool("memory")
def allocate_shared_memory(name: str, size: int) -> str:
    """Create and map a shared memory region in the target process.

    The region is allocated with non-executable protection by default.

    Args:
        name: Unique name for the shared memory object.
        size: Size in bytes. Defaults to 4096 if the region does not yet exist.

    Returns JSON with: success, address.
    """
    return format_result(ce_client.send_command("allocate_shared_memory", {"name": name, "size": size}))

@tool("memory")
def get_memory_protection(address: str) -> str:
    """Query the protection flags of a memory page in the target process.

    Args:
        address: Address to query as hex string.

    Returns JSON with: success, read (bool), write (bool), execute (bool), raw (PAGE_* name).
    """
    return format_result(ce_client.send_command("get_memory_protection", {"address": address}))

@tool("memory")
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

@tool("memory")
def full_access(address: str, size: int) -> str:
    """Grant full read-write-execute access to a memory region (convenience wrapper).

    Args:
        address: Start address as hex string.
        size: Size in bytes of the region.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("full_access", {"address": address, "size": size}))

@tool("kernel")
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

@tool("process")
def open_process(process_id_or_name: str) -> str:
    """Open a process by PID or name and attach Cheat Engine to it.

    Args:
        process_id_or_name: Numeric PID as string (e.g. "12345") or process name (e.g. "notepad.exe").

    Returns:
        JSON with {success, process_id, process_name}.
    """
    return format_result(ce_client.send_command("open_process", {"process_id_or_name": process_id_or_name}))

@tool("process")
def get_process_list() -> str:
    """Get the list of running processes on the system.

    Returns:
        JSON with {success, count, processes: [{pid: int, name: str}, ...]}.
    """
    return format_result(ce_client.send_command("get_process_list"))

@tool("process")
def get_processid_from_name(name: str) -> str:
    """Look up the PID of a process by its executable name.

    Args:
        name: Process name to search for (e.g. "notepad.exe").

    Returns:
        JSON with {success, process_id} or {success=false, error, error_code="NOT_FOUND"}.
    """
    return format_result(ce_client.send_command("get_processid_from_name", {"name": name}))

@tool("process")
def get_foreground_process() -> str:
    """Get the PID and window handle of the process currently in the foreground.

    Returns:
        JSON with {success, process_id, window_handle}.
    """
    return format_result(ce_client.send_command("get_foreground_process"))

@tool("process")
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

@tool("process")
def get_opened_process_id() -> str:
    """Get the PID of the process currently attached to Cheat Engine.

    Returns:
        JSON with {success, process_id} or {success=false, error_code="NO_PROCESS"}.
    """
    return format_result(ce_client.send_command("get_opened_process_id"))

@tool("process")
def get_opened_process_handle() -> str:
    """Get the OS handle of the process currently attached to Cheat Engine as a hex string.

    Returns:
        JSON with {success, handle} where handle is a hex string.
    """
    return format_result(ce_client.send_command("get_opened_process_handle"))

# >>> END UNIT-07 <<<

if __name__ == "__main__":
    try:
        debug_log("Starting FastMCP server (v12/v99 compatible)...")
        mcp.run()
    except Exception as e:
        debug_log(f"Fatal Crash: {e}")
        traceback.print_exc(file=sys.stderr)
