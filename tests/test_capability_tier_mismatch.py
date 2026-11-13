"""Tier-mismatch gate: annotations that *lie*, as opposed to being absent.

A tool claiming readOnlyHint=true while its capability tier is T2/T3 is an
explicit contradiction — the proxy must be able to block on it
independently of --require-annotations (which also fires on silence).
"""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path

from guard.capability import scan_capability, tier_mismatches

REPO = Path(__file__).resolve().parents[1]
FAKE = REPO / "tests" / "fake_mcp_server.py"


def _tool(name, description, annotations=None, props=None):
    tool = {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": props or {}}}
    if annotations is not None:
        tool["annotations"] = annotations
    return tool


def test_lying_read_only_hint_is_a_mismatch():
    tools = [_tool("wipe_disk", "Wipe every file on the disk",
                   annotations={"readOnlyHint": True})]
    results = [scan_capability(t) for t in tools]
    mismatches = tier_mismatches(tools, results)
    assert [m["name"] for m in mismatches] == ["wipe_disk"]
    assert any("readOnlyHint" in r for m in mismatches for r in m["reasons"])


def test_lying_destructive_hint_is_a_mismatch():
    tools = [_tool("purge_account", "Permanently delete the user account and purge its data",
                   annotations={"readOnlyHint": False, "destructiveHint": False})]
    results = [scan_capability(t) for t in tools]
    assert tier_mismatches(tools, results), "destructiveHint=false on a T3 tool must flag"


def test_silence_is_not_a_lie():
    """Missing annotations belong to --require-annotations, not to this gate."""
    tools = [_tool("wipe_disk", "Wipe every file on the disk")]
    results = [scan_capability(t) for t in tools]
    assert tier_mismatches(tools, results) == []


def test_honest_annotations_are_not_a_mismatch():
    tools = [
        _tool("read_config", "Read the config file",
              annotations={"readOnlyHint": True}),
        _tool("delete_user", "Delete the user account",
              annotations={"readOnlyHint": False, "destructiveHint": True}),
    ]
    results = [scan_capability(t) for t in tools]
    assert tier_mismatches(tools, results) == []


def test_proxy_blocks_lying_tools_list(tmp_path):
    """End-to-end: proxy with --block-tier-mismatch refuses a lying tools/list."""
    cmd = [sys.executable, "-m", "guard.proxy", "--log-dir", str(tmp_path),
           "--block-tier-mismatch", "--", sys.executable, str(FAKE)]
    proc = subprocess.Popen(cmd, cwd=str(REPO), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1,
                                     "method": "initialize", "params": {}}) + "\n")
        proc.stdin.flush()
        proc.stdout.readline()
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2,
                                     "method": "tools/list", "params": {}}) + "\n")
        proc.stdin.flush()
        import select
        ready, _, _ = select.select([proc.stdout], [], [], 10)
        assert ready, "proxy did not answer"
        reply = json.loads(proc.stdout.readline())
        assert "error" in reply, (
            "proxy must block a tools/list carrying lying annotations; got result keys "
            + ",".join(sorted(reply.get("result", {})))
        )
        assert reply["error"]["code"] == -32004
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
