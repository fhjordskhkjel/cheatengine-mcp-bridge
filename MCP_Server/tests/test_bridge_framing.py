"""serveOneRequest(): the bridge's per-request pipe framing, with a fake pipe."""
import json
import struct

import pytest

from conftest import frame

FAKE_PIPE = b"""
function makePipe(input, failWrites)
  local p = { buf = input, pos = 1, out = {}, Connected = true }
  p.readBytes = function(n)
    if p.pos + n - 1 > #p.buf then return nil end
    local t = { p.buf:byte(p.pos, p.pos + n - 1) }; p.pos = p.pos + n; return t
  end
  p.readString = function(n)
    if p.pos > #p.buf then return nil end
    local s = p.buf:sub(p.pos, p.pos + n - 1); p.pos = p.pos + n; return s
  end
  p.writeBytes = function(t) if failWrites then return nil end p.out[#p.out+1] = string.char(table.unpack(t)); return #t end
  p.writeString = function(s) if failWrites then return nil end p.out[#p.out+1] = s; return #s end
  p.output = function() return table.concat(p.out) end
  return p
end
fakeThread = { synchronize = function(fn) fn() end, Terminated = false }
"""


@pytest.fixture
def serve(bridge):
    bridge.L.execute(FAKE_PIPE)
    G = bridge.G

    def run(data, fail_writes=False):
        pipe = G[b"makePipe"](data, fail_writes)
        keep = bridge.serve(G[b"fakeThread"], pipe)
        return keep, pipe[b"output"]()
    return run


def parse(out):
    n = struct.unpack("<I", out[:4])[0]
    assert len(out) == 4 + n
    return json.loads(out[4:].decode())


def req(method, rid, **params):
    return json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": rid}).encode()


def test_valid_frame(serve):
    keep, out = serve(frame(req("ping", 42)))
    r = parse(out)
    assert keep is True and r["id"] == 42 and "result" in r


@pytest.mark.parametrize("length", [0, 0x7FFFFFFF])
def test_bad_length_gets_error_frame_then_drop(serve, length):
    keep, out = serve(struct.pack("<I", length) + b"xx")
    r = parse(out)
    assert keep is False and r["error"]["code"] == -32600


def test_short_body_drops_without_reply(serve):
    keep, out = serve(struct.pack("<I", 100) + b"short")
    assert keep is False and out == b""


def test_disconnected_and_write_failure_drop(serve):
    assert serve(b"")[0] is False
    assert serve(frame(req("ping", 1)), fail_writes=True)[0] is False


def test_parse_error_has_position(serve):
    keep, out = serve(frame(b"{not json"))
    r = parse(out)
    assert keep is True and r["error"]["code"] == -32700 and "byte" in r["error"]["message"]


def test_unknown_method(serve):
    r = parse(serve(frame(req("nope", 5)))[1])
    assert r["error"]["code"] == -32601 and r["id"] == 5


def test_oversized_response_becomes_error(serve):
    keep, out = serve(frame(req("evaluate_lua", 9, code="return string.rep('a', 33*1024*1024)")))
    r = parse(out)
    assert keep is True and r["error"]["code"] == -32001 and r["id"] == 9
