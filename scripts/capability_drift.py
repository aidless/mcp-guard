#!/usr/bin/env python3
"""Cross-run drift for capability manifests.

Compares two capability_manifest.json files (as written by mcp-guard-proxy,
or any mapping with a "tools" list of {name, tier, hits} entries) and reports:

  * added   -- tools present now but not in the baseline
  * removed -- tools present in the baseline but gone now
  * changed -- tier climb/drop, or a different hit-rule set, or a different
               dangerous-param surface

Exit codes: 0 = no drift (or drift found but --fail-on-drift unset),
1 = drift with --fail-on-drift, 2 = input unreadable/malformed (fail-closed:
a missing baseline is NOT_ASSESSED, never a silent "no drift").
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load(path: Path) -> list[dict]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        _fail_closed(f"baseline/current unreadable: {path} ({exc})")
    except json.JSONDecodeError as exc:
        _fail_closed(f"malformed JSON: {path} ({exc})")
    tools = payload.get("tools") if isinstance(payload, dict) else None
    if not isinstance(tools, list):
        _fail_closed(f"no 'tools' list in manifest: {path}")
    return tools


def _fail_closed(message: str) -> None:
    print(json.dumps({"status": "NOT_ASSESSED", "error": message}, ensure_ascii=False))
    raise SystemExit(2)


def _rules(entry: dict) -> set[str]:
    hits = entry.get("hits") or []
    return {h.get("rule", "?") for h in hits if isinstance(h, dict)}


def _params(entry: dict) -> set[str]:
    hits = entry.get("hits") or []
    return {h.get("match", "?") for h in hits
            if isinstance(h, dict) and h.get("rule") == "dangerous-param"}


def compare(baseline_tools: list[dict], current_tools: list[dict]) -> dict:
    base = {t.get("name", "?"): t for t in baseline_tools if isinstance(t, dict)}
    cur = {t.get("name", "?"): t for t in current_tools if isinstance(t, dict)}
    added = sorted(set(cur) - set(base))
    removed = sorted(set(base) - set(cur))
    changed = []
    for name in sorted(set(base) & set(cur)):
        b, c = base[name], cur[name]
        bt, ct = b.get("tier"), c.get("tier")
        if bt != ct or _rules(b) != _rules(c) or _params(b) != _params(c):
            changed.append({
                "name": name,
                "baseline_tier": bt,
                "current_tier": ct,
                "baseline_rules": sorted(_rules(b)),
                "current_rules": sorted(_rules(c)),
                "baseline_params": sorted(_params(b)),
                "current_params": sorted(_params(c)),
            })
    return {
        "status": "drift" if (added or removed or changed) else "clean",
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": len(set(base) & set(cur)) - len(changed),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--baseline", required=True, type=Path)
    ap.add_argument("--current", required=True, type=Path)
    ap.add_argument("--fail-on-drift", action="store_true",
                    help="exit 1 when any capability drift is found")
    args = ap.parse_args(argv)

    report = compare(_load(args.baseline), _load(args.current))
    print(json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2))
    drift = report["status"] == "drift"
    if drift and args.fail_on_drift:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
