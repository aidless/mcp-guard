#!/usr/bin/env python3
"""scan_corpus.py -- scan an extracted MCP tool corpus and report hits.

Input is the JSON produced by `tasks/extract_thirdparty.py`
(`{server: [tool, ...]}`). Output is a JSON summary with per-hit detail, so a
real-corpus run is reproducible instead of an ad-hoc shell loop.

Usage:
    python tasks/extract_thirdparty.py <checkouts...> -o corpus.json
    python scripts/scan_corpus.py corpus.json [--out report.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from guard.scan import scan_tool  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("corpus", type=Path, help="extract_thirdparty.py output JSON")
    ap.add_argument("--out", type=Path, help="write the JSON summary here")
    args = ap.parse_args(argv)

    doc = json.loads(args.corpus.read_text(encoding="utf-8"))
    per_server = {}
    hits = []
    n_tools = n_empty = 0
    for server, tools in doc.items():
        per_server[server] = len(tools)
        for tool in tools:
            n_tools += 1
            if not tool.get("description", "").strip():
                n_empty += 1
            result = scan_tool(tool)
            if result["flagged"]:
                hits.append({"server": server, "name": tool.get("name", "?"),
                             "description": tool.get("description", ""),
                             "rules": [h["rule"] for h in result["hits"]],
                             "matches": [h["match"] for h in result["hits"]]})
    summary = {
        "corpus": str(args.corpus),
        "n_servers": len(doc),
        "n_tools": n_tools,
        "n_empty_description": n_empty,
        "n_flagged": len(hits),
        "tools_per_server": per_server,
        "hits": hits,
    }
    text = json.dumps(summary, sort_keys=True, ensure_ascii=False, indent=2)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in
                      ("n_servers", "n_tools", "n_empty_description", "n_flagged")},
                     ensure_ascii=False))
    if n_empty:
        print(f"[scan-corpus] note: {n_empty} tool(s) have empty descriptions and "
              "cannot contribute evidence either way", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
