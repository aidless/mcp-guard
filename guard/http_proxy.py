#!/usr/bin/env python3
"""mcp-guard-http-proxy — Streamable HTTP transport proxy (P-D1).

MCP 2025-06-18 起 Streamable HTTP 是推荐的远程传输：客户端 POST JSON-RPC 到
服务器 HTTP 端点。本代理把 stdio 代理的请求侧门禁原样搬到 HTTP 面：

- tools/list：转发到上游 → 扫描响应 → 落 tool_manifest.json /
  capability_manifest.json → 按旗标以 JSON-RPC error 替换响应。
- tools/call：先过门（allowlist / policy.allow_tools / max_tier / deny-regex /
  batch 内层）再转发；阻断时回 -32002，不触碰上游。放行的调用转发后，其
  响应 result.content[].text 过同一套投毒规则（P-R1）：默认只观测，命中记进
  tool_calls.json；--block-response-hits 命中即以 -32007 替换响应不转发。
- 其余方法原样中继。

与 stdio 共享同一套纯决策函数（guard.proxy.tools_scan / call_decision /
response_scan），两个传输面的门禁语义不会漂移。

上游目的地校验（P-SSRF）：`--upstream` 指向云实例元数据或 link-local 地址时
拒绝启动（见 guard/netguard.py），转发不跟随 HTTP redirect。理由很简单——一个
会连到别人递给它的 URL 的安全扫描器本身就是 SSRF 跳板。loopback / RFC1918 /
公网照常放行（MCP server 本来就在本机或内网）。

诚实边界：tools/list 与 tools/call 的 JSON 响应会被扫描；text/event-stream
（SSE 分帧）原样中继不做重扫；无鉴权、无会话管理（上游回什么头就转发什么头）；
仅 JSON 断言覆盖。目的地校验发生在连接之前，解析器二次应答不同（DNS rebinding）
仍有窗口。
"""
from __future__ import annotations

import argparse
import http.client
import json
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from guard.capability import TIER_RANK  # noqa: E402
from guard.netguard import BlockedUpstream, check_upstream, resolve_pinned  # noqa: E402
from guard.proxy import (
    SURFACE_METHODS,
    Policy,
    call_decision,
    response_scan,
    surface_scan,
    tools_scan,
)


class GateState:
    """The decision surface call_decision/tools_scan expect, transport-agnostic."""

    def __init__(self, log_dir: Path, policy: Policy, flags: dict):
        self.log_dir = Path(log_dir)
        self.policy = policy
        self.block_on_hit = flags["block_on_hit"]
        self.block_unauthorized = flags["block_unauthorized"]
        self.block_batch_destructive = flags["block_batch_destructive"]
        self.require_annotations = flags["require_annotations"]
        self.block_tier_mismatch = flags["block_tier_mismatch"]
        self.block_response_hits = flags["block_response_hits"]
        self.store_raw_args = flags["store_raw_args"]
        self.allowlist: set[str] | None = None
        self.capabilities: list[dict] = []
        self.calls: list[dict] = []
        self.surfaces: dict[str, dict] = {}

    # -- tools/list gate ------------------------------------------------
    def handle_tools_response(self, resp: dict) -> dict | None:
        """Scan an upstream tools/list response. Returns the JSON-RPC error to
        send the client instead of the response, or None to relay verbatim."""
        result = resp.get("result") if isinstance(resp, dict) else None
        tools = result.get("tools", []) if isinstance(result, dict) else []
        s = tools_scan(tools)
        self.capabilities = s["capabilities"]
        self.allowlist = s["allowlist"]
        self.log_dir.mkdir(parents=True, exist_ok=True)
        (self.log_dir / "tool_manifest.json").write_text(
            json.dumps(s["manifest"], sort_keys=True, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        (self.log_dir / "capability_manifest.json").write_text(
            json.dumps(s["capability_manifest"], sort_keys=True, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        if s["flagged"] and self.block_on_hit:
            return {"jsonrpc": "2.0", "id": resp.get("id"),
                    "error": {"code": -32001,
                              "message": "mcp-guard blocked tools/list: poisoned tool(s) "
                                         + ", ".join(s["flagged"])}}
        if s["violations"] and self.require_annotations:
            return {"jsonrpc": "2.0", "id": resp.get("id"),
                    "error": {"code": -32003,
                              "message": "mcp-guard blocked tools/list: missing or wrong "
                                         "capability annotations: "
                                         + ", ".join(sorted({v["name"] for v in s["violations"]}))}}
        if s["mismatches"] and self.block_tier_mismatch:
            return {"jsonrpc": "2.0", "id": resp.get("id"),
                    "error": {"code": -32004,
                              "message": "mcp-guard blocked tools/list: annotations contradict "
                                         "capability tier: "
                                         + ", ".join(sorted({m["name"] for m in s["mismatches"]}))}}
        return None

    # -- tools/call gate ------------------------------------------------
    # -- prompts / resources gate ---------------------------------------
    def handle_surface_response(self, kind: str, resp) -> dict | None:
        """P-A2: the three non-tools surfaces reach the model too. Same rules,
        minus the capability axis. Returns the JSON-RPC error to substitute."""
        result = resp.get("result") if isinstance(resp, dict) else None
        scan = surface_scan(result, kind)
        self.surfaces[kind] = scan
        self.log_dir.mkdir(parents=True, exist_ok=True)
        (self.log_dir / "surface_manifest.json").write_text(
            json.dumps(self.surfaces, sort_keys=True, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        if scan["flagged"] and self.block_on_hit:
            return {"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32001,
                              "message": f"mcp-guard blocked {kind}: poisoned entry(ies) "
                                         + ", ".join(scan["flagged"])}}
        return None

    def handle_call(self, msg: dict) -> tuple[dict, dict | None]:
        """Gate a tools/call request. Returns (entry, error-or-None); the entry
        is also appended to self.calls (flushed)."""
        entry, reason = call_decision(self, msg.get("params", {}) or {})
        self.calls.append(entry)
        self._flush_calls()
        if reason:
            return entry, {"jsonrpc": "2.0", "id": msg.get("id"),
                           "error": {"code": -32002,
                                     "message": "mcp-guard blocked tools/call: " + reason}}
        return entry, None

    def handle_call_response(self, entry: dict | None, resp, msg_id) -> dict | None:
        """P-R1: scan an upstream tools/call RESULT. Writes the observation
        fields onto the call entry (observe-only default); with
        --block-response-hits a flagged result becomes a -32007 error to
        relay instead of the upstream response."""
        result = resp.get("result") if isinstance(resp, dict) else None
        scan = response_scan(result)
        if entry is not None:
            entry["response_texts_scanned"] = scan["texts_scanned"]
            entry["response_flagged"] = scan["flagged"]
            entry["response_rule_ids"] = scan["rule_ids"]
            self._flush_calls()
        if scan["flagged"] and self.block_response_hits:
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32007,
                              "message": "mcp-guard blocked tools/call result: response content "
                                         "matched rule(s) " + ", ".join(scan["rule_ids"])
                                         + " (result-content injection)"}}
        return None

    def _flush_calls(self) -> None:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        n_tools = len({c["tool"] for c in self.calls})
        doc = {"source": "proxy-http", "n_calls": len(self.calls),
               "n_tools_called": n_tools,
               "tools_called": sorted({c["tool"] for c in self.calls}),
               "args_policy": "raw" if self.store_raw_args else "digest-only",
               "calls": self.calls}
        (self.log_dir / "tool_calls.json").write_text(
            json.dumps(doc, sort_keys=True, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """An HTTP connection that dials an ALREADY-VALIDATED address.

    ``host`` is still used for the Host header so virtual hosting works; the
    socket goes to ``pinned_ip``. That separation is the whole point: the name is
    resolved once, by :func:`guard.netguard.resolve_pinned`, and never again.
    """

    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float = 60):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:  # noqa: D401 - http.client protocol
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS variant: same pinning, with certificate verification on by default."""

    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float = 60,
                 context=None):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _forward(upstream: str, body: bytes, headers: dict,
             resolver=None) -> tuple[int, str, bytes]:
    """Forward to the upstream, connecting to the address the guard validated.

    Resolving at connect time would reopen the DNS-rebinding window the startup
    check exists to close (see P-A3). A 30x is surfaced as an ordinary response:
    http.client never follows redirects, so no ``Location`` header can bounce an
    allowed upstream into the metadata endpoint.
    """
    scheme, host, port, pinned_ip = resolve_pinned(upstream, resolver=resolver)
    parts = urlsplit(upstream)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    cls = _PinnedHTTPSConnection if scheme == "https" else _PinnedHTTPConnection
    conn = cls(host, port, pinned_ip, timeout=60)
    try:
        conn.request("POST", path, body=body,
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        ctype = resp.getheader("Content-Type") or "application/json"
        return resp.status, ctype, resp.read()
    finally:
        conn.close()


def make_handler(upstream: str, state: GateState):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length)
            try:
                msg = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._json_response(400, {"jsonrpc": "2.0", "id": None,
                                          "error": {"code": -32700,
                                                    "message": "mcp-guard: request body is not valid JSON"}})
                return

            single = isinstance(msg, dict)
            messages = [msg] if single else msg
            replacements: dict[int, dict] = {}
            relays: dict[int, tuple[int, str, bytes]] = {}
            for idx, m in enumerate(messages):
                if not isinstance(m, dict):
                    continue
                method = m.get("method")
                if method == "tools/call":
                    entry, blocked = state.handle_call(m)
                    if blocked is not None:
                        replacements[idx] = blocked
                        continue
                    # 放行：转发，然后扫描响应（P-R1）
                    payload = body if single else json.dumps(m).encode()
                    status, ctype, up_body = _forward(upstream, payload, dict(self.headers))
                    try:
                        resp = json.loads(up_body)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        resp = None
                    err = state.handle_call_response(entry, resp, m.get("id"))
                    if err is not None:
                        replacements[idx] = err
                    else:
                        relays[idx] = (status, ctype, up_body)
                elif method in SURFACE_METHODS:
                    status, ctype, up_body = _forward(
                        upstream, body if single else json.dumps(m).encode(), dict(self.headers))
                    try:
                        resp = json.loads(up_body)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        resp = None
                    err = state.handle_surface_response(SURFACE_METHODS[method], resp)
                    if err is not None:
                        err["id"] = m.get("id")
                        replacements[idx] = err
                    else:
                        relays[idx] = (status, ctype, up_body)
                elif method == "tools/list":
                    status, ctype, up_body = _forward(upstream, body if single else json.dumps(m).encode(), dict(self.headers))
                    try:
                        resp = json.loads(up_body)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        replacements[idx] = {"jsonrpc": "2.0", "id": m.get("id"),
                                             "error": {"code": -32006,
                                                       "message": "mcp-guard: upstream tools/list response is not JSON"}}
                        continue
                    error = state.handle_tools_response(resp)
                    if error is not None:
                        replacements[idx] = error
                    else:
                        relays[idx] = (status, ctype, up_body)

            if replacements or relays:
                # 阻断：不中继上游响应（tools/list 已转发仅用于取证扫描），
                # 用 JSON-RPC error 原位替换；放行的带其上游响应中继。
                if single:
                    if 0 in replacements:
                        self._json_response(200, replacements[0])
                    else:
                        status, ctype, up_body = relays[0]
                        self._relay(status, ctype, up_body)
                else:
                    out = []
                    for idx, m in enumerate(messages):
                        if idx in replacements:
                            out.append(replacements[idx])
                        elif idx in relays:
                            _, _, up_body = relays[idx]
                            out.append(json.loads(up_body) if up_body else None)
                        else:
                            out.append(m)
                    self._json_response(200, out)
                return

            # 其余方法：原样转发（逐条或整批）
            if single:
                status, ctype, up_body = _forward(upstream, body, dict(self.headers))
                self._relay(status, ctype, up_body)
            else:
                out = []
                for m in messages:
                    payload = json.dumps(m).encode() if isinstance(m, dict) else json.dumps(None).encode()
                    _, _, up_body = _forward(upstream, payload, dict(self.headers))
                    out.append(json.loads(up_body) if up_body else None)
                self._json_response(200, out)

        def do_GET(self):  # noqa: N802
            self._json_response(405, {"jsonrpc": "2.0", "id": None,
                                      "error": {"code": -32005,
                                                "message": "mcp-guard: GET not supported (POST JSON-RPC only)"}})

        def _relay(self, status: int, ctype: str, up_body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(up_body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(up_body)

        def _json_response(self, status: int, doc) -> None:
            payload = json.dumps(doc, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):  # 静音
            pass

    return Handler


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mcp-guard-http-proxy",
                                 description=__doc__.split("\n\n")[0])
    ap.add_argument("--upstream", required=True,
                    help="upstream MCP HTTP endpoint URL (Streamable HTTP POST target)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0,
                    help="listen port (0 = ephemeral; chosen port printed to stderr)")
    ap.add_argument("--log-dir", required=True, type=Path,
                    help="where tool_manifest.json / capability_manifest.json / tool_calls.json are written")
    ap.add_argument("--policy", type=Path, default=None,
                    help="JSON policy: {deny_arg_regex: [...], allow_tools: [...], max_tier, block: {...}}")
    ap.add_argument("--deny-arg-regex", action="append", default=[])
    ap.add_argument("--allow-tools", nargs="*", default=None,
                    help="explicit tool allowlist (implies --block-unauthorized)")
    ap.add_argument("--block-on-hit", action="store_true")
    ap.add_argument("--block-unauthorized", action="store_true")
    ap.add_argument("--block-batch-destructive", action="store_true")
    ap.add_argument("--require-annotations", action="store_true")
    ap.add_argument("--block-tier-mismatch", action="store_true")
    ap.add_argument("--block-response-hits", action="store_true",
                    help="scan tools/call RESULT text content with the poison rules; a flagged result is replaced with a JSON-RPC error (-32007) instead of being relayed (default: observe-only, hits recorded in tool_calls.json)")
    ap.add_argument("--store-raw-args", action="store_true",
                    help="debug only: persist raw call arguments (default: digest-only)")
    ap.add_argument("--allow-link-local-upstream", action="store_true",
                    help="escape hatch for tests/labs: permit a link-local upstream "
                         "(cloud-metadata endpoints are refused regardless)")
    args = ap.parse_args(argv)

    # Refuse a metadata / link-local destination before anything else happens:
    # relaying to IMDS hands out credentials, so this is fail-closed at startup.
    try:
        check_upstream(args.upstream, allow_link_local=args.allow_link_local_upstream)
    except BlockedUpstream as exc:
        print(f"[mcp-guard-http-proxy] {exc}", file=sys.stderr, flush=True)
        return 2

    policy = Policy.load(args.policy, args.deny_arg_regex)
    if args.allow_tools is not None:
        policy.allow_tools = set(args.allow_tools)
    if policy.max_tier is not None and policy.max_tier_rank is None:
        ap.error(f"policy max_tier {policy.max_tier!r} is not a known capability tier "
                 f"(one of {sorted(TIER_RANK)})")
    declared = policy.block
    flags = {
        "block_on_hit": args.block_on_hit or declared.get("on_hit", False),
        "block_unauthorized": (args.block_unauthorized
                               or policy.allow_tools is not None
                               or declared.get("unauthorized", False)),
        "block_batch_destructive": (args.block_batch_destructive
                                    or declared.get("batch_destructive", False)),
        "require_annotations": args.require_annotations or declared.get("require_annotations", False),
        "block_tier_mismatch": args.block_tier_mismatch or declared.get("tier_mismatch", False),
        "block_response_hits": args.block_response_hits or declared.get("response_hits", False),
        "store_raw_args": args.store_raw_args,
    }
    state = GateState(args.log_dir, policy, flags)

    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(args.upstream, state))
    port = httpd.server_address[1]
    print(f"[mcp-guard-http-proxy] listening on {args.host}:{port} -> {args.upstream}",
          file=sys.stderr, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        state._flush_calls()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
