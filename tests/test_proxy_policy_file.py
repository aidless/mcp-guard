"""Declarative policy file: allow_tools, max_tier, and block-section merge.

The policy file is the operator's single declaration; CLI flags stay useful
for one-off runs. Merge semantics: a block is active if the CLI flag OR the
policy declaration says so. max_tier is fail-closed: a tool whose tier is
unknown exceeds every declared ceiling until it can be classified.
"""
from __future__ import annotations
import json
import select
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FAKE = REPO / "tests" / "fake_mcp_server.py"


def _start(log_dir, policy_path, *extra):
    cmd = [sys.executable, "-m", "guard.proxy", "--log-dir", str(log_dir),
           "--policy", str(policy_path), *extra,
           "--", sys.executable, str(FAKE)]
    return subprocess.Popen(cmd, cwd=str(REPO), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)


def _rpc(proc, msg_id, method, params=None):
    payload = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        payload["params"] = params
    proc.stdin.write(json.dumps(payload) + "\n")
    proc.stdin.flush()
    ready, _, _ = select.select([proc.stdout], [], [], 10)
    assert ready, "proxy did not answer in time"
    return json.loads(proc.stdout.readline())


def _close(proc):
    proc.stdin.close()
    proc.wait(timeout=10)


def test_policy_allow_tools_blocks_ghost(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"allow_tools": ["echo"]}))
    proc = _start(tmp_path, policy)
    try:
        _rpc(proc, 1, "initialize", {})
        _rpc(proc, 2, "tools/list", {})
        blocked = _rpc(proc, 3, "tools/call", {"name": "run_batch", "arguments": {}})
        assert blocked["error"]["code"] == -32002
        ok = _rpc(proc, 4, "tools/call", {"name": "echo", "arguments": {"text": "hi"}})
        assert ok["result"]["content"][0]["text"] == "ok:echo"
    finally:
        _close(proc)


def test_policy_max_tier_blocks_higher_and_unknown(tmp_path):
    """max_tier T2: T3 blocked, unknown fail-closed, T2 allowed."""
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"max_tier": "T2_mutate"}))
    proc = _start(tmp_path, policy)
    try:
        _rpc(proc, 1, "initialize", {})
        _rpc(proc, 2, "tools/list", {})
        # run_batch is T3 -> blocked
        blocked = _rpc(proc, 3, "tools/call", {"name": "run_batch", "arguments": {}})
        assert blocked["error"]["code"] == -32002
        assert "max_tier" in blocked["error"]["message"]
        # echo is capability-unknown -> fail-closed blocked
        unknown = _rpc(proc, 4, "tools/call", {"name": "echo", "arguments": {"text": "hi"}})
        assert unknown["error"]["code"] == -32002
        # send_message is T2 -> allowed by the ceiling
        ok = _rpc(proc, 5, "tools/call", {"name": "send_message", "arguments": {"body": "x"}})
        assert ok["result"]["content"][0]["text"] == "ok:send_message"
    finally:
        _close(proc)


def test_policy_block_section_merges_with_cli(tmp_path):
    """block.batch_destructive in the policy file activates without the CLI flag."""
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"block": {"batch_destructive": True}}))
    payload = json.dumps([
        {"command": "snapshot"},
        {"command": "close_app", "args": {"app": "Notes"}},
    ])
    proc = _start(tmp_path, policy)
    try:
        _rpc(proc, 1, "initialize", {})
        _rpc(proc, 2, "tools/list", {})
        blocked = _rpc(proc, 3, "tools/call",
                       {"name": "run_batch", "arguments": {"commands_json": payload}})
        assert blocked["error"]["code"] == -32002
        assert "destructive" in blocked["error"]["message"]
    finally:
        _close(proc)
