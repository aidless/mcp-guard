"""Scan-only CLI — 只做"扫描 + 钉选 + 漂移检测"。

为什么单独开一个入口（2026-10-28 修的语义落差）：
`pyproject.toml` 里原本只有 `mcp-guard = "run_eval:main"`，所以装完之后敲
`mcp-guard --offline` 跑的是**离线评测**，而不是扫描——名字与行为不符。
现在两个入口职责分开，扫描逻辑完全共用 `guard.scan`，输出逐行 JSON：

    mcp-guard-scan tools.json            # 扫描 + 哈希钉选（stdout 逐工具 JSON）
    mcp-guard-scan tools.json --pin snap.json   # 顺带把钉选快照写盘，下次可比漂移
    mcp-guard-scan tools.json --fail-on-hit     # 有命中时退出码 1（给 CI 门禁用）
    mcp-guard-scan tools.json --capability      # 额外输出能力分层（T0..T3）
    mcp-guard-scan tools.json --fail-on-capability  # 有 T3 破坏/执行工具即退出码 1
    mcp-guard-scan tools.json --require-annotations # 破坏/写入工具缺显式注解即退出码 1

`mcp-guard` 仍然是评测运行器（run_eval:main），保留以兼容既有文档与脚本。
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .scan import check_drift, digest_tool, scan_tool
from .capability import (
    annotation_violations,
    scan_capability,
    summarise,
    tier_mismatches,
)


def load_tools(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        tools = json.load(f)
    if isinstance(tools, dict):
        tools = tools.get("tools", [tools])
    return tools


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="mcp-guard-scan",
        description="扫描 MCP 工具定义，输出规则命中、哈希钉选与漂移检测",
    )
    ap.add_argument("tools", help="工具定义 JSON（数组，或 {tools: [...]}）")
    ap.add_argument("--pin", default=None,
                    help="钉选快照文件（不存在则新建，存在则用于漂移比对）")
    ap.add_argument("--fail-on-hit", action="store_true",
                    help="只要有工具被命中，退出码就是 1（CI 门禁用）")
    ap.add_argument("--capability", action="store_true",
                    help="对每个工具额外输出能力分层（投毒扫描不覆盖的破坏/执行面）")
    ap.add_argument("--fail-on-capability", action="store_true",
                    help="存在 T3 破坏或任意执行能力时退出码 1（隐含 --capability）")
    ap.add_argument("--require-annotations", action="store_true",
                    help="能写入/破坏的工具缺少显式 readOnlyHint/destructiveHint 时退出码 1（隐含 --capability）")
    ap.add_argument("--annotation-report", default=None, type=pathlib.Path, metavar="PATH",
                    help="把注解门结果（violations/warnings/tier_mismatches）写成 JSON 工件；只出报告不改变退出码")
    args = ap.parse_args(argv)

    tools = load_tools(args.tools)
    want_capability = (args.capability or args.fail_on_capability
                       or args.require_annotations or args.annotation_report)
    capability_results: list[dict] = []

    pinned: dict[str, str] = {}
    snapshots: dict[str, dict] = {}
    pin_path = pathlib.Path(args.pin) if args.pin else None
    if pin_path and pin_path.exists():
        data = json.loads(pin_path.read_text(encoding="utf-8"))
        pinned = data.get("digests", {})
        snapshots = data.get("tools", {})

    flagged = 0
    for t in tools:
        result = scan_tool(t)
        if result["flagged"]:
            flagged += 1
        print(json.dumps(result, ensure_ascii=False))
        if want_capability:
            capability = scan_capability(t)
            capability_results.append(capability)
            print(json.dumps({"capability": capability}, ensure_ascii=False))
        if pinned:
            print(json.dumps(check_drift(t, pinned, snapshots), ensure_ascii=False))
        name = t.get("name", "?")
        pinned[name] = digest_tool(t)
        snapshots[name] = t

    if pin_path:
        pin_path.write_text(
            json.dumps({"digests": pinned, "tools": snapshots}, ensure_ascii=False, indent=1),
            encoding="utf-8",
        )

    summary = {"scanned": len(tools), "flagged": flagged}
    violations: list[dict] = []
    warnings: list[dict] = []
    mismatches: list[dict] = []
    if want_capability:
        summary["capability"] = summarise(capability_results)
    if args.require_annotations or args.annotation_report:
        violations, warnings = annotation_violations(tools, capability_results)
        mismatches = tier_mismatches(tools, capability_results)
    if args.require_annotations:
        summary["annotation_violations"] = len(violations)
        summary["annotation_warnings"] = len(warnings)
        print(json.dumps({"annotations": {"violations": violations, "warnings": warnings}},
                         ensure_ascii=False))
    if args.annotation_report:
        try:
            args.annotation_report.write_text(
                json.dumps({"violations": violations, "warnings": warnings,
                            "tier_mismatches": mismatches},
                           ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8")
        except OSError as exc:
            print(json.dumps({"status": "NOT_ASSESSED",
                              "error": f"annotation-report unwritable: {exc}"}),
                  file=sys.stderr)
            return 2
    print(json.dumps(summary, ensure_ascii=False), file=sys.stderr)

    destructive = summary.get("capability", {}).get("destructive", [])
    fail = (
        (args.fail_on_hit and flagged)
        or (args.fail_on_capability and destructive)
        or (args.require_annotations and violations)
    )
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
