#!/usr/bin/env python3
"""CLI wrapper for guard.cross_tool — see that module for the checks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from guard.cross_tool import analyze  # noqa: E402


def _load(path: Path) -> list[dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, list):
        return doc
    return doc.get("tools", [])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("tools", help="tools JSON (a list, or {tools: [...]})")
    ap.add_argument("--out", help="write the report here instead of stdout")
    ap.add_argument("--fail-on-high", action="store_true",
                    help="exit 1 when any high-severity finding is reported")
    args = ap.parse_args()

    path = Path(args.tools)
    if not path.exists():
        print(f"not found: {path}", file=sys.stderr)
        return 2
    rep = analyze(_load(path))
    text = json.dumps(rep, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"{rep['n_findings']} finding(s) across {rep['n_tools']} tools", file=sys.stderr)
    else:
        sys.stdout.write(text)
    if args.fail_on_high and any(f["severity"] == "high" for f in rep["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
