#!/usr/bin/env python3
"""Turn cached smithery server-detail JSON into benign tool-description corpus.

The registry's /servers/<qualifiedName> endpoint returns the real tool list a
server publishes (name + description + inputSchema). That is the same text a
client would see in tools/list, so it is the right substrate for a false-positive
baseline — server blurbs are not.

Raw detail JSON is fetched once into a cache directory and never re-fetched here;
this script only reshapes what is on disk, so the corpus stays recomputable.

    python scripts/benign_from_smithery.py --cache /tmp/sm_details --out corpus.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def build(cache: Path) -> list[dict]:
    entries: list[dict] = []
    for path in sorted(cache.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        server = doc.get("qualifiedName") or path.stem
        tools = doc.get("tools")
        if not isinstance(tools, list):
            continue
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            desc = tool.get("description")
            name = tool.get("name")
            if not isinstance(desc, str) or not desc.strip() or not isinstance(name, str):
                continue
            entries.append({"server": server, "name": name, "description": desc,
                            "source": "smithery:registry-detail"})
    return entries


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache", required=True, type=Path)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    entries = build(args.cache)
    servers = len({e["server"] for e in entries})
    rep = {"source": "smithery registry /servers/<qualifiedName> (tools[].description)",
           "fetched": "2026-11-14", "servers": servers, "tools": len(entries),
           "tools_detail": entries}
    text = json.dumps(rep, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(json.dumps({"servers": servers, "tools": len(entries), "out": str(args.out)}))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
