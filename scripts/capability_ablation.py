#!/usr/bin/env python3
"""能力层消融报告（P-B2）。

对同一工具集，依次关闭能力轴的四块证据，数多少工具的分层因此改变：
  - no-name-tiers        名字后缀证据（NAME_TIERS）
  - no-dangerous-params  危险参数证据（DANGEROUS_PARAMS）
  - no-enum-awareness    closed-enum 值级证据（_enum_tier）
  - no-batch-unwrapping  schema 默认 batch 内层解包（BATCH_KEYS）

输出 JSON：基线分层分布 + 每轴 changed 计数与样例 + restore 后基线复检。
退出码：0 = 报告产出；2 = 输入缺失/损坏（NOT_ASSESSED，fail-closed）。

这是测量工具不是门禁：它不声明哪个轴"应该"贡献多少，只给实测数字。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import guard.capability as cap  # noqa: E402


def _load_tools(path: Path) -> list[dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, dict):
        doc = doc.get("tools") or doc.get("tiers") or []
    return [t for t in doc if isinstance(t, dict) and t.get("name")]


def _scan_all(tools: list[dict]) -> dict[str, str]:
    return {t["name"]: cap.scan_capability(t)["tier"] for t in tools}


# 每轴：(轴名, patch 函数)——patch 返回 restore 函数
def _axes() -> list[tuple[str, "callable", "callable"]]:
    axes: list[tuple[str, callable, callable]] = []

    def patch_name_tiers():
        old = cap.NAME_TIERS
        cap.NAME_TIERS = {}
        return lambda: setattr(cap, "NAME_TIERS", old)

    def patch_dangerous():
        old = cap.DANGEROUS_PARAMS
        cap.DANGEROUS_PARAMS = {}
        return lambda: setattr(cap, "DANGEROUS_PARAMS", old)

    def patch_enum():
        old = cap._enum_tier
        cap._enum_tier = lambda prop, depth: None
        return lambda: setattr(cap, "_enum_tier", old)

    def patch_batch():
        old = cap.BATCH_KEYS
        cap.BATCH_KEYS = ()
        return lambda: setattr(cap, "BATCH_KEYS", old)

    axes.append(("no-name-tiers", patch_name_tiers, None))
    axes.append(("no-dangerous-params", patch_dangerous, None))
    axes.append(("no-enum-awareness", patch_enum, None))
    axes.append(("no-batch-unwrapping", patch_batch, None))
    return axes


def build_report(tools: list[dict]) -> dict:
    baseline = _scan_all(tools)
    ablations: dict[str, dict] = {}
    for axis, patch, _ in _axes():
        restore = patch()
        try:
            ablated = _scan_all(tools)
        finally:
            restore()
        changed = [
            {"name": name, "baseline": baseline[name], "ablated": ablated[name]}
            for name in baseline
            if ablated.get(name) != baseline[name]
        ]
        ablations[axis] = {
            "changed": len(changed),
            "examples": changed[:8],
        }
    # restore 复检：所有轴跑完后基线必须还原
    restored_check = _scan_all(tools) == baseline
    return {
        "status": "ok",
        "n_tools": len(tools),
        "baseline": baseline,
        "baseline_distribution": _distribution(baseline),
        "ablations": ablations,
        "restored_check": restored_check,
    }


def _distribution(tiers: dict[str, str]) -> dict[str, int]:
    dist: dict[str, int] = {}
    for tier in tiers.values():
        dist[tier] = dist.get(tier, 0) + 1
    return dist


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tools", required=True, type=Path,
                    help="tools JSON (list or {tools: [...]})")
    ap.add_argument("--out", required=True, type=Path, help="report path")
    args = ap.parse_args(argv)

    try:
        tools = _load_tools(args.tools)
    except (json.JSONDecodeError, OSError) as exc:
        report = {"status": "NOT_ASSESSED", "note": f"unreadable input: {exc}"}
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
        print(f"[capability-ablation] NOT_ASSESSED: {exc}", file=sys.stderr)
        return 2
    if not tools:
        report = {"status": "NOT_ASSESSED", "note": "no named tools in input"}
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
        return 2

    report = build_report(tools)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
    for axis, data in report["ablations"].items():
        print(f"{axis}: {data['changed']} changed", file=sys.stderr)
    if not report["restored_check"]:
        print("[capability-ablation] baseline did not restore — report unsafe",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
