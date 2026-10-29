"""Scan-only CLI — 只做"扫描 + 钉选 + 漂移检测"。

为什么单独开一个入口（2026-10-28 修的语义落差）：
`pyproject.toml` 里原本只有 `mcp-guard = "run_eval:main"`，所以装完之后敲
`mcp-guard --offline` 跑的是**离线评测**，而不是扫描——名字与行为不符。
现在两个入口职责分开，扫描逻辑完全共用 `guard.scan`，输出逐行 JSON：

    mcp-guard-scan tools.json            # 扫描 + 哈希钉选（stdout 逐工具 JSON）
    mcp-guard-scan tools.json --pin snap.json   # 顺带把钉选快照写盘，下次可比漂移
    mcp-guard-scan tools.json --fail-on-hit     # 有命中时退出码 1（给 CI 门禁用）

`mcp-guard` 仍然是评测运行器（run_eval:main），保留以兼容既有文档与脚本。
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .scan import check_drift, digest_tool, scan_tool


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
    args = ap.parse_args(argv)

    tools = load_tools(args.tools)

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

    print(json.dumps({"scanned": len(tools), "flagged": flagged}, ensure_ascii=False),
          file=sys.stderr)
    return 1 if (args.fail_on_hit and flagged) else 0


if __name__ == "__main__":
    raise SystemExit(main())
