"""guard/proxy.py -- live stdio gate integration tests.

These spawn the real proxy process against a fake MCP server and speak
newline-delimited JSON-RPC over pipes, so they exercise the actual threading and
forwarding paths rather than a mocked class.
"""
import json
import select
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FAKE = REPO / "tests" / "fake_mcp_server.py"


def _start(log_dir, *extra):
    cmd = [sys.executable, "-m", "guard.proxy", "--log-dir", str(log_dir), *extra,
           "--", sys.executable, str(FAKE)]
    return subprocess.Popen(cmd, cwd=str(REPO), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)


def _read(proc, timeout=10):
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    assert ready, "proxy did not answer in time"
    return json.loads(proc.stdout.readline())


def _rpc(proc, msg_id, method, params=None):
    payload = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        payload["params"] = params
    proc.stdin.write(json.dumps(payload) + "\n")
    proc.stdin.flush()
    return _read(proc)


def _close(proc):
    proc.stdin.close()
    proc.wait(timeout=10)


def test_tools_list_is_scanned_and_manifest_written(tmp_path):
    proc = _start(tmp_path)
    try:
        init = _rpc(proc, 1, "initialize", {})
        assert init["result"]["serverInfo"]["name"] == "fake"
        listed = _rpc(proc, 2, "tools/list", {})
        names = [t["name"] for t in listed["result"]["tools"]]
        assert names == ["send_message", "echo", "run_batch", "lying_read"]
    finally:
        _close(proc)
    manifest = json.loads((tmp_path / "tool_manifest.json").read_text(encoding="utf-8"))
    assert manifest["n_tools"] == 4
    by_name = {t["name"]: t for t in manifest["tools"]}
    assert by_name["send_message"]["flagged"] is True
    assert by_name["echo"]["flagged"] is False
    assert all(len(t["digest"]) == 64 for t in manifest["tools"])


def test_capability_manifest_is_written(tmp_path):
    proc = _start(tmp_path)
    try:
        _rpc(proc, 1, "initialize", {})
        _rpc(proc, 2, "tools/list", {})
    finally:
        _close(proc)
    manifest = json.loads((tmp_path / "capability_manifest.json").read_text(encoding="utf-8"))
    assert manifest["summary"]["total"] == 4
    tiers = {row["name"]: row["tier"] for row in manifest["tools"]}
    assert tiers["run_batch"].startswith("T3")
    # "Echo back" matches no rule; the rulepack must say unknown rather than
    # silently promote an unrecognised tool to read-only.
    assert tiers["echo"] == "unknown"


def test_unauthorized_call_is_blocked_and_logged(tmp_path):
    proc = _start(tmp_path, "--block-unauthorized")
    try:
        _rpc(proc, 1, "initialize", {})
        _rpc(proc, 2, "tools/list", {})
        blocked = _rpc(proc, 3, "tools/call", {"name": "ghost_tool", "arguments": {"x": 1}})
        assert blocked["error"]["code"] == -32002
        allowed = _rpc(proc, 4, "tools/call", {"name": "echo", "arguments": {"text": "hi"}})
        assert allowed["result"]["content"][0]["text"] == "ok:echo"
    finally:
        _close(proc)
    calls = json.loads((tmp_path / "tool_calls.json").read_text(encoding="utf-8"))
    assert calls["n_calls"] == 2
    assert calls["tools_called"] == ["echo", "ghost_tool"]
    by_tool = {c["tool"]: c for c in calls["calls"]}
    assert by_tool["ghost_tool"]["blocked"] is True
    assert by_tool["echo"]["blocked"] is False


def test_deny_arg_regex_blocks_call(tmp_path):
    proc = _start(tmp_path, "--deny-arg-regex", r"~/\.ssh")
    try:
        _rpc(proc, 1, "initialize", {})
        _rpc(proc, 2, "tools/list", {})
        blocked = _rpc(proc, 3, "tools/call",
                       {"name": "echo", "arguments": {"text": "read ~/.ssh/id_rsa"}})
        assert blocked["error"]["code"] == -32002
        ok = _rpc(proc, 4, "tools/call", {"name": "echo", "arguments": {"text": "hello"}})
        assert ok["result"]["content"][0]["text"] == "ok:echo"
    finally:
        _close(proc)
    calls = json.loads((tmp_path / "tool_calls.json").read_text(encoding="utf-8"))
    blocked = [c for c in calls["calls"] if c["blocked"]]
    assert len(blocked) == 1
    assert "deny pattern" in blocked[0]["reason"]


def test_batch_payload_with_destructive_inner_is_blocked(tmp_path):
    proc = _start(tmp_path, "--block-batch-destructive")
    payload = json.dumps([
        {"command": "snapshot", "args": {"app": "Notes"}},
        {"command": "close_app", "args": {"app": "Notes"}},
    ])
    try:
        _rpc(proc, 1, "initialize", {})
        _rpc(proc, 2, "tools/list", {})
        blocked = _rpc(proc, 3, "tools/call",
                       {"name": "run_batch", "arguments": {"commands_json": payload}})
        assert blocked["error"]["code"] == -32002
        assert "close_app" in blocked["error"]["message"]
        ok = _rpc(proc, 4, "tools/call",
                  {"name": "run_batch", "arguments": {
                      "commands_json": json.dumps([{"command": "snapshot"}]),
                  }})
        assert ok["result"]["content"][0]["text"] == "ok:run_batch"
    finally:
        _close(proc)
    calls = json.loads((tmp_path / "tool_calls.json").read_text(encoding="utf-8"))
    blocked = [c for c in calls["calls"] if c["blocked"]]
    assert len(blocked) == 1
    assert "destructive" in blocked[0]["reason"]


def test_require_annotations_blocks_unannotated_tools_list(tmp_path):
    proc = _start(tmp_path, "--require-annotations")
    try:
        _rpc(proc, 1, "initialize", {})
        refused = _rpc(proc, 2, "tools/list", {})
        assert refused["error"]["code"] == -32003
        assert "run_batch" in refused["error"]["message"]
    finally:
        _close(proc)


def test_block_on_hit_refuses_tools_list(tmp_path):
    proc = _start(tmp_path, "--block-on-hit")
    try:
        _rpc(proc, 1, "initialize", {})
        refused = _rpc(proc, 2, "tools/list", {})
        assert refused["error"]["code"] == -32001
        assert "send_message" in refused["error"]["message"]
    finally:
        _close(proc)


def test_default_never_persists_raw_args(tmp_path):
    proc = _start(tmp_path)
    secret = "sk-test-should-not-land"
    try:
        _rpc(proc, 1, "initialize", {})
        _rpc(proc, 2, "tools/list", {})
        _rpc(proc, 3, "tools/call", {"name": "echo", "arguments": {"text": secret}})
    finally:
        _close(proc)
    blob = (tmp_path / "tool_calls.json").read_text(encoding="utf-8")
    assert secret not in blob
    calls = json.loads(blob)
    assert calls["args_policy"] == "digest-only"
