#!/usr/bin/env python3
"""静态分层 vs 运行时调用的一致性审计（P-A3）。

输入：mcp-guard-proxy 落盘的 capability_manifest.json + tool_calls.json。
回答一个问题：**静态评估说只读的工具，运行时在干什么？**

检查（每条调用独立判）：
1. called-tool-not-in-manifest          调用了 tools/list 之后才出现的工具
2. read-only-tier-with-dangerous-param  T0/T1 工具调用带危险参数名
3. unknown-tier-with-dangerous-param    unknown 工具带危险参数（不冒充只读）
4. read-only-tier-hides-destructive-batch  raw args 下 batch 载荷内层是 T3

退出码：0 = 全一致；1 = 有告警；2 = 输入缺失/损坏（NOT_ASSESSED，fail-closed）。

只看参数名与（可选的）raw args；digest-only 模式下参数值不可见，这一层
不可判读就不判——诚实边界，不猜值。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from guard.capability import (  # noqa: E402
    TIER_RANK,
    unwrap_payload,
)

# 与 guard/capability.py 的危险参数表同源（此处用参数名，值不可见也可判）
DANGEROUS_PARAM_NAMES = {
    "argv", "cmd", "command", "commands", "commands_json", "cwd", "env",
    "force", "hard", "no_confirm", "payload", "script", "shell",
    "skip_confirm", "steps", "assume_yes",
}
LOW_TIERS = {"T0_read", "T1_local"}


def _load(path: Path) -> dict | list:
    return json.loads(path.read_text(encoding="utf-8"))


def audit(log_dir: Path) -> dict:
    cap_path = log_dir / "capability_manifest.json"
    calls_path = log_dir / "tool_calls.json"
    if not cap_path.exists() or not calls_path.exists():
        return {"status": "NOT_ASSESSED",
                "note": f"missing input(s): {cap_path.name} / {calls_path.name}",
                "alarms": [], "checked": 0}
    try:
        cap_doc = _load(cap_path)
        calls_doc = _load(calls_path)
    except (json.JSONDecodeError, OSError) as exc:
        return {"status": "NOT_ASSESSED", "note": f"unreadable input: {exc}",
                "alarms": [], "checked": 0}

    tier_map: dict[str, dict] = {}
    for tool in cap_doc.get("tools", []):
        if isinstance(tool, dict) and tool.get("name"):
            tier_map[tool["name"]] = tool

    alarms: list[dict] = []
    checked = 0
    for call in calls_doc.get("calls", []):
        checked += 1
        name = call.get("tool", "?")
        arg_keys = call.get("arg_keys") or []
        dangerous = sorted(set(arg_keys) & DANGEROUS_PARAM_NAMES)
        meta = tier_map.get(name)
        if meta is None:
            alarms.append({"kind": "called-tool-not-in-manifest", "tool": name,
                           "detail": "called tool absent from capability_manifest "
                                     "(tool surface appeared after tools/list)"})
            continue
        tier = meta.get("tier", "unknown")
        unknown = bool(meta.get("unknown"))
        if dangerous and (tier in LOW_TIERS):
            alarms.append({"kind": "read-only-tier-with-dangerous-param",
                           "tool": name, "tier": tier, "params": dangerous,
                           "detail": "statically read-only tool received "
                                     "dangerous parameter name(s) at call time"})
        elif dangerous and unknown:
            alarms.append({"kind": "unknown-tier-with-dangerous-param",
                           "tool": name, "tier": tier, "params": dangerous,
                           "detail": "unknown-capability tool received dangerous "
                                     "parameter name(s); not assuming read-only"})

        # raw-args 才能看 batch 内层（digest-only 不可判读，不猜）。
        # 逐参数值解包：unwrap_payload 对非 batch 载荷无害返回 []。
        raw_args = call.get("args")
        if isinstance(raw_args, dict) and not call.get("args_redacted"):
            try:
                inner = [item
                         for value in raw_args.values()
                         for item in (unwrap_payload(value) or [])]
            except Exception:  # noqa: BLE001 — 载荷损坏只影响这一条调用
                inner = []
            for item in inner or []:
                inner_tier = item.get("tier") if isinstance(item, dict) else None
                inner_name = item.get("name") if isinstance(item, dict) else None
                if inner_tier and TIER_RANK.get(inner_tier, 0) >= TIER_RANK["T3_destructive_or_exec"]:
                    alarms.append({
                        "kind": "read-only-tier-hides-destructive-batch",
                        "tool": name, "tier": tier,
                        "inner_tool": inner_name, "inner_tier": inner_tier,
                        "detail": "batch payload carries a T3 inner tool call "
                                  "inside a statically low-tier tool",
                    })
                    break  # 每条调用报一次足够

    status = "ok" if not alarms else "alarms"
    return {"status": status, "n_calls": calls_doc.get("n_calls", checked),
            "checked": checked, "alarms": alarms,
            "args_policy": calls_doc.get("args_policy", "?")}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log-dir", required=True, type=Path,
                    help="proxy log dir with capability_manifest.json + tool_calls.json")
    ap.add_argument("--out", default=None, type=Path,
                    help="report path (default <log-dir>/consistency_report.json)")
    args = ap.parse_args(argv)

    report = audit(args.log_dir)
    out = args.out or (args.log_dir / "consistency_report.json")
    try:
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8")
    except OSError as exc:
        print(f"[capability-consistency] cannot write report: {exc}", file=sys.stderr)
        return 2

    if report["status"] == "NOT_ASSESSED":
        print(f"[capability-consistency] NOT_ASSESSED: {report['note']}",
              file=sys.stderr)
        return 2
    for a in report["alarms"]:
        print(f"[alarm] {a['kind']}: {a['tool']} :: {a['detail']}", file=sys.stderr)
    return 1 if report["alarms"] else 0


if __name__ == "__main__":
    sys.exit(main())
