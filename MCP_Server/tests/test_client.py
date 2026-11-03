"""CEBridgeClient retry / timeout / protocol semantics, over the TCP transport."""
import time

import pytest

pytest.importorskip("mcp.server.fastmcp")
import mcp_cheatengine as m  # noqa: E402

from fake_bridge import FakeBridge  # noqa: E402


@pytest.fixture
def fake():
    fb = FakeBridge()
    yield fb
    fb.close()


@pytest.fixture
def client(fake):
    c = m.CETcpBridgeClient("127.0.0.1", fake.port)
    c.timeout_seconds = 1.0
    yield c
    c.close()


def test_echo_raw_utf8(client):
    assert client.send_command("echo", {"s": "日本 é"})["echo"] == {"s": "日本 é"}


def test_stale_connection_is_replaced_and_sent_once(client, fake):
    fake.close_idle_after_reply = True
    client.send_command("echo")
    time.sleep(0.1)
    fake.execs.clear()
    assert client.send_command("count")["success"]
    assert fake.execs["count"] == 1


def test_timeout_is_not_retried(client, fake):
    t0 = time.time()
    with pytest.raises(TimeoutError, match=r"timed out after 1s.*not retried"):
        client.send_command("slow", {"secs": 2})
    assert time.time() - t0 < 1.8
    assert fake.execs["slow"] == 1 and not client.connected
    time.sleep(1.5)  # the late reply lands on the abandoned connection, not ours
    assert client.send_command("echo", {"after": 1})["echo"] == {"after": 1}
    assert fake.execs["slow"] == 1


def test_lost_after_send_is_not_retried(client, fake):
    with pytest.raises(ConnectionError, match="not retried"):
        client.send_command("close_after_read")
    assert fake.execs["close_after_read"] == 1


def test_bad_json_is_protocol_error(client, fake):
    with pytest.raises(ConnectionError, match="Protocol error"):
        client.send_command("bad_json")
    assert fake.execs["bad_json"] == 1


def test_id_mismatch_detected(client):
    with pytest.raises(ConnectionError, match="does not match"):
        client.send_command("wrong_id")


def test_rpc_error_mapping(client):
    assert client.send_command("rpc_error") == {
        "success": False, "error": "Method not found: x",
        "error_code": "NOT_FOUND", "jsonrpc_code": -32601,
    }


def test_unreachable_message():
    c = m.CETcpBridgeClient("127.0.0.1", 1)
    with pytest.raises(ConnectionError, match="not reachable.*ce_tcp_relay"):
        c.send_command("echo")


def test_queued_call_gives_up_after_timeout(client, fake):
    import threading
    outcome = []

    def slow_call():
        try:
            client.send_command("slow", {"secs": 3})
            outcome.append("returned")
        except TimeoutError:
            outcome.append("timeout")

    t = threading.Thread(target=slow_call)
    t.start()
    time.sleep(0.2)
    client.timeout_seconds = 0.5  # the queued call waits at most this long for the lock
    with pytest.raises(TimeoutError, match="busy with another command"):
        client.send_command("echo")
    t.join()
    assert outcome == ["timeout"] and fake.execs["echo"] == 0


@pytest.mark.parametrize("raw,expected", [
    (None, set(m.TOOLSETS)), ("", set(m.TOOLSETS)), ("all", set(m.TOOLSETS)),
    ("memory, scan", {"memory", "scan", "process"}), ("DEBUG", {"debug", "process"}),
])
def test_parse_toolsets(raw, expected):
    assert m._parse_toolsets(raw) == expected


def test_parse_toolsets_rejects_unknown():
    with pytest.raises(ValueError, match="unknown toolset"):
        m._parse_toolsets("memory,bogus")


def test_every_tool_has_a_toolset():
    assert len(m.TOOL_TOOLSET) >= 176
    assert set(m.TOOL_TOOLSET.values()) == set(m.TOOLSETS)
