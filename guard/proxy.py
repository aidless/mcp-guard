"""mcp-guard-proxy -- stdio MCP proxy with an inline BEFORE gate.

The offline scanner answers "are these tool definitions poisoned" for a JSON
file. This proxy answers it for a *live* server, and keeps answering while the
agent runs:

  client <--newline JSON--> proxy <--newline JSON--> upstream MCP server

What it does:
  * on the `tools/list` response: scans every tool, writes `tool_manifest.json`
    (name + digest), and with `--block-on-hit` refuses to hand poisoned tools to
    the client;
  * on the `tools/list` response also writes `capability_manifest.json`: a
    deterministic T0..T3 classification of what each tool can do;
  * on every `tools/call`: checks the tool is in the manifest (allowlist) and
    that no string argument matches a deny regex; with `--block-unauthorized`
    the call is answered with a JSON-RPC error instead of being forwarded;
    with `--block-batch-destructive` it unwraps an opaque batch payload and
    blocks a call whose inner command is T3;
  * records every call, redacted by default (keys + digest, never raw values),
    into `tool_calls.json` -- the same shape `agent-platform trace` consumes.

Transport: MCP stdio is newline-delimited JSON-RPC 2.0. Content-Length framing
is not handled (the current MCP stdio spec uses newline framing).

Usage:
    mcp-guard-proxy --log-dir runs/gate1 --block-unauthorized -- <server-cmd...>
    mcp-guard-proxy --log-dir runs/gate1 --policy policy.json -- npx -y some-mcp
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import threading
from pathlib import Path

from .scan import digest_tool, scan_tool
from .capability import (
    T3_DESTRUCTIVE,
    TIER_RANK,
    annotation_violations,
    scan_capability,
    summarise,
    tier_mismatches,
    unwrap_payload,
)
from .capability import BATCH_KEYS
from .rules import scan_text


def response_scan(result) -> dict:
    """P-R1: scan the TEXT CONTENT of a tools/call RESULT with the same poison
    rules used on tool descriptions. Shared by the stdio and the Streamable
    HTTP transports. Default posture is observe-only; --block-response-hits
    turns a flagged result into a JSON-RPC error instead of relaying it.

    Only `content[].text` entries are scanned (the standard result text
    channel); non-text content parts are counted, not judged.
    """
    texts: list[str] = []
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" \
                        and isinstance(part.get("text"), str):
                    texts.append(part["text"])
    rule_ids: set[str] = set()
    hits: list[dict] = []
    for text in texts:
        for h in scan_text(text):
            rule_ids.add(h["rule"])
            hits.append(h)
    return {"texts_scanned": len(texts), "flagged": bool(rule_ids),
            "rule_ids": sorted(rule_ids), "hits": hits}


def _canon_args(args: dict) -> str:
    return json.dumps(args or {}, sort_keys=True, ensure_ascii=False)


def _call_digest(tool: str, args: dict) -> str:
    payload = json.dumps({"tool": tool, "args": args or {}},
                         sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _strings(value, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _strings(v, out)
    elif isinstance(value, list):
        for v in value:
            _strings(v, out)


class Policy:
    def __init__(self, deny_global: list[str] | None = None,
                 deny_by_tool: dict[str, list[str]] | None = None,
                 allow_tools: list[str] | None = None,
                 max_tier: str | None = None,
                 block: dict | None = None):
        self.deny_global = [re.compile(p, re.I) for p in (deny_global or [])]
        self.deny_by_tool = {name: [re.compile(p, re.I) for p in pats]
                             for name, pats in (deny_by_tool or {}).items()}
        self.allow_tools = set(allow_tools) if allow_tools else None
        self.max_tier = max_tier
        self.max_tier_rank = TIER_RANK.get(max_tier) if max_tier else None
        self.block = {key: bool(value) for key, value in (block or {}).items()}

    @classmethod
    def load(cls, path: Path | None, cli_patterns: list[str] | None = None) -> "Policy":
        deny_global = list(cli_patterns or [])
        deny_by_tool: dict[str, list[str]] = {}
        allow_tools = max_tier = None
        block: dict = {}
        if path and path.exists():
            doc = json.loads(path.read_text(encoding="utf-8"))
            deny_global += doc.get("deny_arg_regex", [])
            for name, spec in doc.get("tools", {}).items():
                deny_by_tool[name] = spec.get("deny_arg_regex", [])
            allow_tools = doc.get("allow_tools")
            max_tier = doc.get("max_tier")
            block = doc.get("block") or {}
        return cls(deny_global, deny_by_tool, allow_tools, max_tier, block)

    def violation(self, tool: str, args: dict) -> str | None:
        values: list[str] = []
        _strings(args, values)
        for rx in self.deny_global + self.deny_by_tool.get(tool, []):
            for value in values:
                if rx.search(value):
                    return f"argument matches deny pattern {rx.pattern!r}"
        return None


def tools_scan(tools: list[dict]) -> dict:
    """Pure request-side tools/list evaluation, shared by the stdio and the
    Streamable HTTP transports. Returns everything both gates need: digests,
    poison flags, capability tiers, annotation violations/mismatches and both
    manifests. Transport layers only decide which verdicts become blocks."""
    entries, flagged = [], []
    for tool in tools:
        res = scan_tool(tool)
        entries.append({"name": tool.get("name", "?"),
                        "digest": digest_tool(tool),
                        "flagged": bool(res["flagged"]),
                        "rule_ids": sorted({h["rule"] for h in res["hits"]})})
        if res["flagged"]:
            flagged.append(tool.get("name", "?"))
    capabilities = [scan_capability(tool) for tool in tools]
    violations, warnings = annotation_violations(tools, capabilities)
    mismatches = tier_mismatches(tools, capabilities)
    capability_manifest = {
        "source": "proxy",
        "summary": summarise(capabilities),
        "annotation_violations": violations,
        "annotation_warnings": warnings,
        "tier_mismatches": mismatches,
        "tools": capabilities,
    }
    manifest = {"source": "proxy", "n_tools": len(entries),
                "tools": entries,
                "digest_algo": "sha256(canonical-json)"}
    return {"entries": entries, "flagged": flagged, "capabilities": capabilities,
            "violations": violations, "warnings": warnings, "mismatches": mismatches,
            "capability_manifest": capability_manifest, "manifest": manifest,
            "allowlist": {e["name"] for e in entries}}


def batch_payload_violation(args: dict) -> str | None:
    """Unwrap batch payloads and name inner T3 commands (P1 --block-batch-destructive)."""
    for key in BATCH_KEYS:
        if key not in args:
            continue
        inner = unwrap_payload(args[key])
        destructive = [item["name"] for item in inner if item["tier"] == T3_DESTRUCTIVE]
        if destructive:
            return ("batch payload contains destructive command(s): "
                    + ", ".join(sorted(set(destructive))))
    return None


def call_decision(state, params: dict) -> tuple[dict, str | None]:
    """Pure request-side tools/call evaluation, shared by both transports.

    state must expose: policy, block_unauthorized, allowlist, capabilities,
    calls, store_raw_args, block_batch_destructive. Returns (log_entry, reason)
    — reason is None when the call may pass."""
    tool = params.get("name", "?")
    args = params.get("arguments", {}) or {}
    blocked, reason = False, ""
    if state.block_unauthorized and state.allowlist is not None and tool not in state.allowlist:
        blocked, reason = True, f"tool {tool!r} is not in the tools/list allowlist"
    elif state.policy.allow_tools is not None and tool not in state.policy.allow_tools:
        blocked, reason = True, f"tool {tool!r} is not in the policy allow_tools"
    elif state.policy.max_tier_rank is not None:
        tier = next((c["tier"] for c in state.capabilities if c["name"] == tool),
                    "unknown")
        rank = TIER_RANK.get(tier)
        if rank is None:
            blocked, reason = True, (f"tier unknown exceeds policy max_tier "
                                     f"{state.policy.max_tier} (fail-closed)")
        elif rank > state.policy.max_tier_rank:
            blocked, reason = True, (f"tier {tier} exceeds policy max_tier "
                                     f"{state.policy.max_tier}")
    if not blocked:
        violation = state.policy.violation(tool, args)
        if violation:
            blocked, reason = True, violation
    if not blocked and state.block_batch_destructive:
        batch_reason = batch_payload_violation(args)
        if batch_reason:
            blocked, reason = True, batch_reason

    entry = {"seq": len(state.calls), "tool": tool,
             "arg_keys": sorted(args) if isinstance(args, dict) else [],
             "call_digest": _call_digest(tool, args),
             "blocked": blocked}
    if blocked:
        entry["reason"] = reason
    if state.store_raw_args:
        entry["args"] = args
    else:
        entry["args_redacted"] = True
    return entry, (reason if blocked else None)


class Proxy:
    def __init__(self, upstream: list[str], log_dir: Path,
                 policy: Policy, block_on_hit: bool, block_unauthorized: bool,
                 store_raw_args: bool = False,
                 block_batch_destructive: bool = False,
                 require_annotations: bool = False,
                 block_tier_mismatch: bool = False,
                 block_response_hits: bool = False):
        self.upstream = upstream
        self.log_dir = log_dir
        self.policy = policy
        self.block_on_hit = block_on_hit
        self.block_unauthorized = block_unauthorized
        self.block_batch_destructive = block_batch_destructive
        self.require_annotations = require_annotations
        self.block_tier_mismatch = block_tier_mismatch
        self.block_response_hits = block_response_hits
        self.store_raw_args = store_raw_args
        self.allowlist: set[str] | None = None
        self.manifest: dict | None = None
        self.capabilities: list[dict] = []
        self.calls: list[dict] = []
        self.pending: dict[object, str] = {}
        self.lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.proc: subprocess.Popen | None = None

    # -- output helpers -------------------------------------------------
    def _to_client(self, message: dict) -> None:
        with self.write_lock:
            sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
            sys.stdout.flush()

    def _to_upstream(self, message: dict) -> None:
        assert self.proc and self.proc.stdin
        with self.write_lock:
            self.proc.stdin.write(json.dumps(message, ensure_ascii=False) + "\n")
            self.proc.stdin.flush()

    def _error(self, msg_id, code: int, text: str) -> None:
        self._to_client({"jsonrpc": "2.0", "id": msg_id,
                         "error": {"code": code, "message": text}})

    # -- tools/list -----------------------------------------------------
    def _handle_tools(self, msg_id, result: dict) -> bool:
        tools = result.get("tools", []) if isinstance(result, dict) else []
        s = tools_scan(tools)
        self.capabilities = s["capabilities"]
        self.manifest = s["manifest"]
        self.allowlist = s["allowlist"]
        self.log_dir.mkdir(parents=True, exist_ok=True)
        (self.log_dir / "tool_manifest.json").write_text(
            json.dumps(self.manifest, sort_keys=True, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        (self.log_dir / "capability_manifest.json").write_text(
            json.dumps(s["capability_manifest"], sort_keys=True, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        if s["flagged"] and self.block_on_hit:
            self._error(msg_id, -32001,
                        "mcp-guard blocked tools/list: poisoned tool(s) " + ", ".join(s["flagged"]))
            return False
        if s["violations"] and self.require_annotations:
            self._error(msg_id, -32003,
                        "mcp-guard blocked tools/list: missing or wrong capability annotations: "
                        + ", ".join(sorted({v["name"] for v in s["violations"]})))
            return False
        if s["mismatches"] and self.block_tier_mismatch:
            self._error(msg_id, -32004,
                        "mcp-guard blocked tools/list: annotations contradict capability tier: "
                        + ", ".join(sorted({m["name"] for m in s["mismatches"]})))
            return False
        return True

    def _batch_violation(self, args: dict) -> str | None:
        if not self.block_batch_destructive or not isinstance(args, dict):
            return None
        return batch_payload_violation(args)

    # -- tools/call -----------------------------------------------------
    def _handle_call(self, msg: dict) -> bool:
        entry, reason = call_decision(self, msg.get("params", {}) or {})
        self.calls.append(entry)
        if reason:
            self._error(msg.get("id"), -32002, "mcp-guard blocked tools/call: " + reason)
            return False
        return True

    # -- io loops -------------------------------------------------------
    def _client_loop(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                # Not ours to judge; pass the raw line through untouched.
                with self.write_lock:
                    assert self.proc and self.proc.stdin
                    self.proc.stdin.write(line + "\n")
                    self.proc.stdin.flush()
                continue
            method = msg.get("method")
            if method == "tools/list" and "id" in msg:
                with self.lock:
                    self.pending[msg["id"]] = ("tools/list", None)
            elif method == "tools/call" and "id" in msg:
                seq = len(self.calls)  # _handle_call appends exactly one entry
                if not self._handle_call(msg):
                    continue
                with self.lock:
                    self.pending[msg["id"]] = ("tools/call", seq)
            self._to_upstream(msg)
        if self.proc and self.proc.stdin:
            self.proc.stdin.close()

    def _upstream_loop(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                with self.write_lock:
                    sys.stdout.write(line + "\n")
                    sys.stdout.flush()
                continue
            msg_id = msg.get("id")
            pending = None
            if msg_id is not None:
                with self.lock:
                    pending = self.pending.pop(msg_id, None)
            method = pending[0] if pending else None
            if method == "tools/list":
                if not self._handle_tools(msg_id, msg.get("result", {})):
                    continue
            elif method == "tools/call":
                seq = pending[1]
                result = msg.get("result")
                if isinstance(result, dict):
                    scan = response_scan(result)
                    entry = self.calls[seq]
                    entry["response_texts_scanned"] = scan["texts_scanned"]
                    entry["response_flagged"] = scan["flagged"]
                    entry["response_rule_ids"] = scan["rule_ids"]
                    if scan["flagged"] and self.block_response_hits:
                        self._error(msg_id, -32007,
                                    "mcp-guard blocked tools/call result: response content "
                                    "matched rule(s) " + ", ".join(scan["rule_ids"])
                                    + " (result-content injection)")
                        self._flush_calls()
                        continue
            self._to_client(msg)

    def run(self) -> int:
        self.proc = subprocess.Popen(
            self.upstream, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=sys.stderr, text=True, bufsize=1)
        t_client = threading.Thread(target=self._client_loop, daemon=True)
        t_upstream = threading.Thread(target=self._upstream_loop, daemon=True)
        t_client.start()
        t_upstream.start()
        t_upstream.join()
        t_client.join(timeout=2)
        self._flush_calls()
        return 0 if self.proc.returncode in (0, None) else 1

    def _flush_calls(self) -> None:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        tools_called = sorted({c["tool"] for c in self.calls})
        record = {
            "source": "proxy",
            "n_calls": len(self.calls),
            "n_tools_called": len(tools_called),
            "tools_called": tools_called,
            "args_policy": "raw" if self.store_raw_args else "digest-only",
            "calls": self.calls,
        }
        (self.log_dir / "tool_calls.json").write_text(
            json.dumps(record, sort_keys=True, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mcp-guard-proxy", description=__doc__.split("\n\n")[0])
    ap.add_argument("--log-dir", required=True, type=Path,
                    help="where tool_manifest.json / tool_calls.json are written")
    ap.add_argument("--policy", type=Path, default=None,
                    help="JSON policy: {deny_arg_regex: [...], tools: {name: {...}}}")
    ap.add_argument("--deny-arg-regex", action="append", default=[],
                    help="global regex; any string argument matching it blocks the call")
    ap.add_argument("--block-on-hit", action="store_true",
                    help="refuse tools/list when any tool is poisoned")
    ap.add_argument("--block-unauthorized", action="store_true",
                    help="refuse tools/call for a tool not in the tools/list manifest")
    ap.add_argument("--block-batch-destructive", action="store_true",
                    help="unwrap batch payloads and refuse inner T3 commands")
    ap.add_argument("--require-annotations", action="store_true",
                    help="refuse tools/list when mutating tools lack explicit capability annotations")
    ap.add_argument("--block-tier-mismatch", action="store_true",
                    help="refuse tools/list when annotations explicitly contradict the capability tier (readOnlyHint=true on a T2/T3 tool, destructiveHint=false on a T3 tool)")
    ap.add_argument("--block-response-hits", action="store_true",
                    help="scan tools/call RESULT text content with the poison rules; a flagged result is replaced with a JSON-RPC error (-32007) instead of being relayed (default: observe-only, hits recorded in tool_calls.json)")
    ap.add_argument("--store-raw-args", action="store_true",
                    help="debug only: persist raw call arguments (default: digest-only)")
    ap.add_argument("upstream", nargs=argparse.REMAINDER,
                    help="-- <upstream command...>")
    args = ap.parse_args(argv)

    upstream = args.upstream
    if upstream and upstream[0] == "--":
        upstream = upstream[1:]
    if not upstream:
        ap.error("missing upstream command after --")
    policy = Policy.load(args.policy, args.deny_arg_regex)
    if policy.max_tier is not None and policy.max_tier_rank is None:
        ap.error(f"policy max_tier {policy.max_tier!r} is not a known capability tier "
                 f"(one of {sorted(TIER_RANK)})")
    # CLI flag OR policy declaration: a block is active when either says so.
    declared = policy.block
    proxy = Proxy(upstream, args.log_dir, policy,
                  block_on_hit=args.block_on_hit or declared.get("on_hit", False),
                  block_unauthorized=(args.block_unauthorized
                                      or policy.allow_tools is not None
                                      or declared.get("unauthorized", False)),
                  store_raw_args=args.store_raw_args,
                  block_batch_destructive=(args.block_batch_destructive
                                           or declared.get("batch_destructive", False)),
                  require_annotations=(args.require_annotations
                                       or declared.get("require_annotations", False)),
                  block_tier_mismatch=(args.block_tier_mismatch
                                       or declared.get("tier_mismatch", False)),
                  block_response_hits=(args.block_response_hits
                                       or declared.get("response_hits", False)))
    return proxy.run()


if __name__ == "__main__":
    raise SystemExit(main())
