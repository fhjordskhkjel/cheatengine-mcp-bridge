"""Static drift checks between the files that must agree (no runtime needed)."""
import re
from collections import Counter

from conftest import SERVER_DIR

REPO = SERVER_DIR.parent
PY = (SERVER_DIR / "mcp_cheatengine.py").read_text(encoding="utf-8")
LUA = (SERVER_DIR / "ce_mcp_bridge.lua").read_text(encoding="utf-8")
RELAY = (SERVER_DIR / "ce_tcp_relay.py").read_text(encoding="utf-8")


def _command_handlers():
    start = LUA.index("local commandHandlers = {")
    end = LUA.index("\n}", start)
    return dict(re.findall(r"^\s*([a-z0-9_]+)\s*=\s*([A-Za-z0-9_]+)\s*,", LUA[start:end], re.M))


def test_every_python_command_has_a_lua_handler():
    sent = set(re.findall(r'send_command\(\s*"([a-z0-9_]+)"', PY))
    missing = sorted(sent - set(_command_handlers()))
    assert not missing, f"Python sends commands the Lua dispatcher does not know: {missing}"


def test_every_dispatcher_entry_points_at_a_defined_handler():
    defined = set(re.findall(r"^function (cmd_\w+)\(", LUA, re.M))
    undefined = sorted({v for v in _command_handlers().values() if v not in defined})
    assert not undefined, f"commandHandlers references undefined functions: {undefined}"


def test_no_duplicate_handlers_or_chunk_locals():
    dup_cmds = [n for n, c in Counter(re.findall(r"^function (cmd_\w+)\(", LUA, re.M)).items() if c > 1]
    dup_locals = [n for n, c in Counter(re.findall(r"^local function (\w+)\(", LUA, re.M)).items() if c > 1]
    assert not dup_cmds, f"cmd_* defined more than once: {dup_cmds}"
    assert not dup_locals, f"chunk-level local functions defined more than once: {dup_locals}"


def test_pipe_name_matches():
    lua = re.search(r'local PIPE_NAME = "([^"]+)"', LUA).group(1)
    for text in (PY, RELAY):
        assert re.search(r'PIPE_NAME = r"\\\\\.\\pipe\\(\S+)"', text).group(1) == lua


def test_frame_limit_matches():
    def mb(pattern, text):
        return int(re.search(pattern, text).group(1))
    assert mb(r"MAX_RESPONSE_SIZE_BYTES = (\d+) \* 1024 \* 1024", PY) \
        == mb(r"MAX_FRAME_SIZE_BYTES = (\d+) \* 1024 \* 1024", RELAY) \
        == mb(r"local MAX_FRAME_BYTES = (\d+) \* 1024 \* 1024", LUA)


def test_every_tool_is_in_a_toolset():
    assert not re.search(r"^@mcp\.tool\(", PY, re.M), "register tools with @tool(\"<toolset>\", \"<access>\"), not @mcp.tool()"
    decorators = re.findall(r"^@tool\(.*\)$", PY, re.M)
    well_formed = [d for d in decorators if re.fullmatch(r'@tool\("\w+", "(read|analysis|write|exec)"\)', d)]
    assert len(decorators) >= 176 and decorators == well_formed, \
        "every tool needs @tool(\"<toolset>\", \"<access>\") with a literal access class"


def test_claude_md_and_agents_md_in_sync():
    """AGENTS.md is CLAUDE.md for Codex; only the title and intro line differ."""
    claude = (REPO / "CLAUDE.md").read_text(encoding="utf-8").splitlines()
    agents = (REPO / "AGENTS.md").read_text(encoding="utf-8").splitlines()
    assert claude[3:] == agents[3:], "CLAUDE.md and AGENTS.md diverged; apply the same edit to both"
