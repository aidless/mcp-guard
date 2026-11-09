"""Cross-check the heuristic capability rulepack against an explicit ledger.

The agent-desktop case reports an explicitly curated 21/12/29/5 split. This
script recomputes the split from `guard/capability.py` and fails on any tier
mismatch, so the heuristic cannot silently drift away from the case study.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from guard.capability import scan_capability, summarise  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tools", type=Path,
                        default=ROOT / "examples/agent_desktop_1_2_0_tools.json")
    parser.add_argument("--ledger", type=Path,
                        default=ROOT / "examples/agent_desktop_1_2_0_ledger.json")
    args = parser.parse_args(argv)

    if not args.tools.exists():
        print(json.dumps({"status": "tools_missing", "path": str(args.tools)},
                         ensure_ascii=False))
        return 1
    tools = json.loads(args.tools.read_text(encoding="utf-8"))["tools"]
    results = [scan_capability(tool) for tool in tools]
    summary = summarise(results)

    if not args.ledger.exists():
        print(json.dumps({"status": "ledger_missing", "summary": summary},
                         ensure_ascii=False))
        return 1

    ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
    expected = {row["name"]: row["tier"].split("_")[0] for row in ledger["tiers"]}
    by_name = {row["name"]: row["tier"].split("_")[0] for row in results}
    mismatches = [
        {"name": name, "ledger": expected[name], "rulepack": by_name.get(name, "absent")}
        for name in expected if expected[name] != by_name.get(name, "absent")
    ]
    print(json.dumps({
        "status": "ok" if not mismatches else "DRIFT",
        "tools_checked": len(expected),
        "summary": summary,
        "mismatches": mismatches,
    }, ensure_ascii=False, indent=1))
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
