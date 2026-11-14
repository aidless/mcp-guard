"""SSRF / cloud-metadata guards for the HTTP proxy (borrowed from snyk-agent-scan).

snyk-agent-scan refuses to connect to link-local and cloud-metadata endpoints and
does not follow HTTP redirects, because a scanner that connects to whatever URL it
is handed becomes an SSRF launchpad.  Our HTTP proxy had none of that: `_forward`
called `urlopen(upstream)` with zero destination validation and urllib's default
opener follows 30x hops, so a malicious MCP config could point us at
`http://169.254.169.254/latest/meta-data/iam/security-credentials/` and we would
happily relay the credentials.

These tests pin the three behaviours:
  1. metadata / link-local destinations are refused (v4, v6, Alibaba);
  2. loopback, RFC1918 private and ordinary public hosts stay allowed;
  3. redirects are not followed, and `main()` refuses to start on a metadata URL.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guard.netguard import (  # noqa: E402
    BlockedUpstream,
    check_upstream,
    describe_block,
)
from guard import http_proxy  # noqa: E402


# ---------------------------------------------------------------- refusals


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.170.2/v2/credentials",  # ECS task metadata
        "http://[fe80::1]/mcp",  # IPv6 link-local
        "http://[fd00:ec2::254]/latest/meta-data/",  # AWS IMDS IPv6
        "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud metadata
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    ],
)
def test_metadata_and_link_local_are_refused(url: str) -> None:
    with pytest.raises(BlockedUpstream):
        check_upstream(url)


def test_block_message_names_the_reason() -> None:
    """The error has to say WHY, or the operator will just add an escape hatch."""
    with pytest.raises(BlockedUpstream) as exc:
        check_upstream("http://169.254.169.254/latest/meta-data/")
    msg = str(exc.value)
    assert "169.254.169.254" in msg
    assert "metadata" in msg or "link-local" in msg


# ---------------------------------------------------------------- allowances


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080/mcp",
        "http://localhost:3000/mcp",
        "http://10.1.2.3:9000/mcp",
        "http://192.168.1.50:8080/mcp",
        "http://172.16.5.5:8080/mcp",
    ],
)
def test_local_and_private_upstreams_stay_allowed(url: str) -> None:
    """MCP servers normally live on loopback / the LAN; refusing them would make
    the proxy unusable.  snyk allows these too."""
    check_upstream(url)  # must not raise


def test_public_host_stays_allowed() -> None:
    check_upstream("http://93.184.216.34/mcp")  # literal public IP, no DNS needed


def test_dns_name_resolving_to_metadata_is_refused() -> None:
    """A hostname is not a defence: rebinding `evil.example` at 169.254.169.254
    must still be caught.  We stub the resolver rather than hit the network."""
    def fake_resolve(host: str, port: int) -> list[str]:
        return ["169.254.169.254"]

    with pytest.raises(BlockedUpstream):
        check_upstream("http://evil.example/mcp", resolver=fake_resolve)


def test_dns_name_resolving_to_public_is_allowed() -> None:
    def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    check_upstream("http://example.com/mcp", resolver=fake_resolve)


def test_escape_hatch_is_explicit_and_allows_link_local() -> None:
    """Tests and odd lab setups need a way through, but it must be an explicit
    opt-in flag, and it must not silently widen to metadata by default."""
    with pytest.raises(BlockedUpstream):
        check_upstream("http://169.254.169.254/latest/meta-data/")
    check_upstream("http://169.254.169.254/latest/meta-data/", allow_link_local=True)
    assert "link-local" in describe_block("169.254.169.254")


# ---------------------------------------------------------------- redirects


class _Redirecting(BaseHTTPRequestHandler):
    def __init__(self, target_port_holder, *a, **kw):
        self._holder = target_port_holder
        super().__init__(*a, **kw)

    def do_POST(self):  # noqa: N802
        self.send_response(302)
        self.send_header("Location", f"http://127.0.0.1:{self._holder[0]}/landed")
        self.end_headers()

    def log_message(self, *a):
        pass


def _serve(handler) -> tuple[ThreadingHTTPServer, threading.Thread, int]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, t, srv.server_address[1]


def test_forward_does_not_follow_redirects() -> None:
    """A followed 30x turns any allowed upstream into a hop somewhere else.

    The redirect points at a *local* second server rather than the real metadata
    IP: when the guard is broken we must fail in milliseconds, not sit in a
    60-second connect timeout against 169.254.169.254 (which is what a real
    metadata target does on a machine with no such route).
    """
    hits: list[str] = []

    class _Landing(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"jsonrpc":"2.0","id":1,"result":{}}')

        def log_message(self, *a):
            pass

    landing, _lt, landing_port = _serve(_Landing)
    holder = [landing_port]
    # Bind the redirector to a handler class that knows the landing port.
    import functools

    redir_srv = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        functools.partial(_Redirecting, holder),
    )
    rt = threading.Thread(target=redir_srv.serve_forever, daemon=True)
    rt.start()
    try:
        status, _ctype, _body = http_proxy._forward(
            f"http://127.0.0.1:{redir_srv.server_address[1]}/mcp", b"{}", {})
        assert status == 302, f"expected the 302 to be surfaced, got {status}"
        assert hits == [], f"redirect was followed to {hits}"
    finally:
        redir_srv.shutdown()
        landing.shutdown()


# ---------------------------------------------------------------- main()


def test_main_refuses_to_start_on_metadata_upstream(tmp_path: Path) -> None:
    """Run the real CLI in a subprocess.

    Driving `main()` in-process looks tempting but hangs the whole suite when the
    guard is broken: `main()` falls through to `serve_forever()` and the test
    never returns.  A timeout turns "guard disabled" into a clean red instead of a
    dead pytest run — which is exactly what the mutation check needs.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "guard.http_proxy",
         "--upstream", "http://169.254.169.254/latest/meta-data/",
         "--log-dir", str(tmp_path)],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True, text=True, timeout=20,
    )
    assert proc.returncode != 0, "proxy must not start on a metadata upstream"
    assert "169.254.169.254" in proc.stderr
    assert "metadata" in proc.stderr or "link-local" in proc.stderr
