"""P-C: a long session must not grow the log without bound.

A proxy that appends every call forever is a memory leak with a nice name. A
10k-call agent run would hold 10k entries in memory and rewrite all of them on
every flush. The cap has to roll (keep the newest) and the count has to stay
truthful: "n_calls: 10000, calls: [last 200]" is honest, while silently keeping
the first 200 is not.

The HTTP proxy is threaded, so the list is also touched from several threads at
once — appending from handlers while the flush walks it is a real data race, not
a theoretical one.
"""

import json
import subprocess
import sys
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from guard.proxy import CallLog  # noqa: E402


def test_call_log_keeps_the_newest_entries() -> None:
    log = CallLog(max_calls=5)
    for i in range(12):
        log.append({"seq": i, "tool": f"t{i}"})
    assert log.n_calls == 12
    assert log.dropped == 7
    assert [c["seq"] for c in log.entries] == [7, 8, 9, 10, 11]


def test_call_log_without_a_cap_keeps_everything() -> None:
    log = CallLog()
    for i in range(50):
        log.append({"seq": i})
    assert log.n_calls == 50
    assert log.dropped == 0
    assert len(log.entries) == 50


def test_call_log_is_thread_safe_under_concurrent_appends() -> None:
    log = CallLog()

    def worker(base: int) -> None:
        for i in range(100):
            log.append({"seq": base + i})

    threads = [threading.Thread(target=worker, args=(n * 100,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert log.n_calls == 800
    assert len(log.entries) == 800
    assert sorted(c["seq"] for c in log.entries) == list(range(800))


def test_flush_reports_both_the_true_count_and_what_survived(tmp_path) -> None:
    log = CallLog(max_calls=3)
    for i in range(10):
        log.append({"seq": i, "tool": "x"})
    path = tmp_path / "tool_calls.json"
    log.flush(path, extra={"source": "proxy"})
    doc = json.loads(path.read_text())
    assert doc["n_calls"] == 10
    assert doc["calls_retained"] == 3
    assert doc["calls_dropped"] == 7
    assert [c["seq"] for c in doc["calls"]] == [7, 8, 9]


def test_stdio_proxy_honours_the_cap_end_to_end(tmp_path) -> None:
    """Driving the real proxy: 6 calls, --max-calls 2, and the log says so."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    server = REPO / "tests" / "fake_mcp_server.py"
    proc = subprocess.Popen(
        [sys.executable, "-m", "guard.proxy", "--log-dir", str(log_dir),
         "--max-calls", "2", "--", sys.executable, str(server)],
        cwd=str(REPO), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1)

    def rpc(obj) -> dict:
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())

    try:
        rpc({"jsonrpc": "2.0", "id": 0, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "t", "version": "0"}}})
        rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        for i in range(6):
            rpc({"jsonrpc": "2.0", "id": 10 + i, "method": "tools/call",
                 "params": {"name": "echo", "arguments": {"text": f"m{i}"}}})
    finally:
        proc.stdin.close()
        proc.wait(timeout=30)

    doc = json.loads((log_dir / "tool_calls.json").read_text())
    assert doc["n_calls"] == 6
    assert doc["calls_retained"] == 2
    assert doc["calls_dropped"] == 4
    assert [c["seq"] for c in doc["calls"]] == [4, 5]


def test_http_proxy_records_under_concurrency_without_losing_calls(tmp_path) -> None:
    """The threaded server hammers one log from many handlers; nothing may be
    lost and nothing may be reported twice."""
    import http.client
    import threading as th
    from http.server import ThreadingHTTPServer

    sys.path.insert(0, str(REPO / "tests"))
    from test_proxy_http import _Upstream, _free_port, _stop

    _Upstream.mode = "clean"
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    upstream_url = f"http://127.0.0.1:{srv.server_address[1]}/mcp"
    th.Thread(target=srv.serve_forever, daemon=True).start()

    port = _free_port()
    log_dir = tmp_path / "http"
    proc = subprocess.Popen(
        [sys.executable, "-m", "guard.http_proxy", "--upstream", upstream_url,
         "--host", "127.0.0.1", "--port", str(port), "--log-dir", str(log_dir)],
        cwd=str(REPO), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    import socket, time
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                break
        except OSError:
            if proc.poll() is not None:
                raise AssertionError(f"proxy died: {proc.stderr.read()}")
            time.sleep(0.05)

    def worker(n: int) -> None:
        for i in range(10):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
            conn.request("POST", "/mcp", json.dumps({
                "jsonrpc": "2.0", "id": n * 100 + i, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": f"{n}-{i}"}}}),
                {"Content-Type": "application/json"})
            conn.getresponse().read()
            conn.close()

    threads = [th.Thread(target=worker, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    _stop(proc)
    srv.shutdown()

    doc = json.loads((log_dir / "tool_calls.json").read_text())
    assert doc["n_calls"] == 60
    assert doc["calls_dropped"] == 0
    assert len({c["call_digest"] for c in doc["calls"]}) == 60


def test_log_size_stays_flat_as_the_session_grows(tmp_path) -> None:
    """Ten times the calls, same cap, same file size — that is what "bounded"
    means. A leak would show up here as linear growth."""
    sizes = []
    for calls in (2_000, 20_000):
        log = CallLog(max_calls=200)
        for i in range(calls):
            log.append({"tool": "t", "call_digest": f"{i:016x}", "blocked": False})
        path = tmp_path / f"calls_{calls}.json"
        log.flush(path)
        sizes.append(path.stat().st_size)
    assert sizes[1] <= sizes[0] * 1.05, sizes
