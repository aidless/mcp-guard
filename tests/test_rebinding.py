"""P-A3: close the DNS-rebinding window.

The guard used to resolve a name, check the answer, then hand the *name* to
urllib — which resolved it again when connecting. An attacker controlling DNS
only had to answer "public IP" to the check and "169.254.169.254" to the
connect. snyk documents this window and leaves it open; we can close it by
pinning the address we validated and connecting to that address.

The proof is structural: the request path performs exactly ONE resolution.
"""

import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from guard.netguard import BlockedUpstream, resolve_pinned  # noqa: E402
from guard.http_proxy import (  # noqa: E402
    _PinnedHTTPConnection,
    _forward,
)


def test_resolve_pinned_returns_the_validated_address() -> None:
    scheme, host, port, ip = resolve_pinned(
        "http://mcp.example.com/mcp", resolver=lambda h, p: ["93.184.216.34"])
    assert scheme == "http"
    assert host == "mcp.example.com"
    assert port == 80
    assert ip == "93.184.216.34"


def test_resolve_pinned_refuses_metadata() -> None:
    with pytest.raises(BlockedUpstream) as exc:
        resolve_pinned("http://mcp.example.com/mcp",
                       resolver=lambda h, p: ["169.254.169.254"])
    assert exc.value.kind == "metadata"


def test_resolve_pinned_refuses_when_any_answer_is_metadata() -> None:
    """One poisoned record is enough — the check must not stop at the first."""
    with pytest.raises(BlockedUpstream):
        resolve_pinned("http://mcp.example.com/mcp",
                       resolver=lambda h, p: ["93.184.216.34", "169.254.169.254"])


def test_resolve_pinned_reports_unresolvable_separately() -> None:
    def boom(host, port):
        raise OSError("no such host")
    with pytest.raises(BlockedUpstream) as exc:
        resolve_pinned("http://mcp.invalid/mcp", resolver=boom)
    assert exc.value.kind == "unresolvable"


def test_resolve_pinned_handles_literal_ip_without_resolver() -> None:
    def must_not_be_called(host, port):
        raise AssertionError("a literal IP needs no resolver")
    _, _, _, ip = resolve_pinned("http://10.1.2.3:8080/mcp",
                                 resolver=must_not_be_called)
    assert ip == "10.1.2.3"


# --- pinned connection ------------------------------------------------------

class _Echo(BaseHTTPRequestHandler):
    seen: list[dict] = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        _Echo.seen.append({"host": self.headers.get("Host"), "body": body.decode()})
        payload = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


@pytest.fixture()
def echo_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _Echo.seen = []
    yield srv.server_address[1]
    srv.shutdown()


def test_pinned_connection_uses_the_ip_not_the_name(echo_server) -> None:
    """The hostname here does not resolve at all; if the connection still tries
    to resolve it, nothing happens. Connecting proves the pinned IP is used."""
    port = echo_server
    conn = _PinnedHTTPConnection("does-not-resolve.invalid", port, "127.0.0.1")
    try:
        conn.request("POST", "/mcp", body=b'{"x":1}',
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        assert resp.status == 200
    finally:
        conn.close()
    # Host header stays the real name so the upstream routes correctly.
    assert _Echo.seen[0]["host"] == f"does-not-resolve.invalid:{port}"


def test_forward_resolves_exactly_once(monkeypatch) -> None:
    """The whole point: no second lookup can happen between check and connect,
    because connect never looks the name up."""
    calls = []

    def resolver(host, port):
        calls.append(host)
        # A rebinding attacker answers "public" first and "metadata" second.
        return ["127.0.0.1"] if len(calls) == 1 else ["169.254.169.254"]

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    _Echo.seen = []
    try:
        status, ctype, body = _forward(f"http://rebind.example:{port}/mcp",
                                       b'{"x":1}', {}, resolver=resolver)
        assert status == 200
        assert json.loads(body) == {"ok": True}
    finally:
        srv.shutdown()

    assert calls == ["rebind.example"], f"resolved {len(calls)}x — window is open"


def test_forward_refuses_metadata_even_though_resolution_succeeds() -> None:
    with pytest.raises(BlockedUpstream):
        _forward("http://rebind.example/mcp", b"{}", {},
                 resolver=lambda h, p: ["169.254.169.254"])
