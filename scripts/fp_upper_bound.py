#!/usr/bin/env python3
"""Report the benign false-positive count with a 95% upper bound.

A bare "0/N" is not a measurement of reliability: with zero hits the interval is
one-sided and its upper end shrinks only as 1/N. This script prints that bound
(Wilson score interval, cross-checked with the rule of three) next to the count,
so the claim in the README carries the uncertainty it actually has.

Usage:
    python3 scripts/fp_upper_bound.py [--corpus PATH] [--out PATH] [--check]

``--check`` exits 1 when any benign description is flagged, so it can gate CI.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from guard.rules import scan_text  # noqa: E402

Z_95 = 1.959964


def wilson_upper(hits: int, n: int, z: float = Z_95) -> float:
    """Upper end of the Wilson score interval for a binomial proportion."""
    if n <= 0:
        return 0.0
    p = hits / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return min(1.0, centre + margin)


def rule_of_three(n: int) -> float:
    """Zero-hit shortcut: 3/n approximates the 95% upper bound."""
    return 3.0 / n if n > 0 else 0.0


def load_corpus(path: Path) -> list[dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, list):
        return doc
    # Corpora carry their entries under "tools" or "tools_detail"; the other key
    # may be a plain count, so pick the one that is actually a list.
    for key in ("tools", "tools_detail"):
        value = doc.get(key)
        if isinstance(value, list):
            return value
    return []


def _key(entry: dict) -> str:
    """Stable identity for a known false positive: server/tool/rule."""
    who = entry.get("server") or entry.get("source") or ""
    return f"{who}:{entry.get('name', '')}:{','.join(entry.get('rules', []))}"


def build_report(tools: list[dict], corpus: str = "examples/benign_corpus.json",
                 known: dict[str, str] | None = None) -> dict:
    descriptions = [(t.get("server") or t.get("source") or "", t.get("name", ""),
                     (t.get("description") or "").strip())
                    for t in tools if isinstance(t, dict)]
    descriptions = [d for d in descriptions if d[2]]

    false_positives = []
    for server, name, text in descriptions:
        hits = scan_text(text)
        if hits:
            false_positives.append({
                "server": server,
                "name": name,
                "rules": sorted({h["rule"] for h in hits}),
                "anchors": sorted({h["anchor"] for h in hits if h.get("anchor")}),
            })

    known = known or {}
    for fp in false_positives:
        fp["identity"] = _key(fp)
        fp["known_reason"] = known.get(fp["identity"])
    unexplained = [fp for fp in false_positives if fp.get("known_reason") is None]

    n = len(descriptions)
    flagged = len(false_positives)
    return {
        "corpus": corpus,
        "n_descriptions": n,
        "flagged": flagged,
        "known_false_positives": len(false_positives) - len(unexplained),
        "unexplained": len(unexplained),
        "false_positive_rate": (flagged / n) if n else 0.0,
        "wilson_upper_95": wilson_upper(flagged, n),
        "rule_of_three_95": rule_of_three(n),
        "note": (
            "With zero hits the point estimate is not the reliability of the rule "
            "pack; the upper bound is. Quote it with the count."
        ),
        "false_positives": false_positives,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", action="append", default=None,
                    help="benign corpus JSON (repeatable); defaults to "
                         "examples/benign_corpus.json")
    ap.add_argument("--known-fps", default=str(REPO / "examples" / "known_false_positives.json"),
                    help="JSON list of known, explained false positives")
    ap.add_argument("--out", help="write the report here instead of stdout")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 when a benign description is flagged and is not a "
                         "known, explained false positive")
    args = ap.parse_args()

    corpora = [Path(c) for c in (args.corpus or [REPO / "examples" / "benign_corpus.json"])]
    missing = [str(c) for c in corpora if not c.exists()]
    if missing:
        print(f"corpus not found: {', '.join(missing)}", file=sys.stderr)
        return 2

    tools: list[dict] = []
    for corpus in corpora:
        for t in load_corpus(corpus):
            if isinstance(t, dict):
                t.setdefault("source", corpus.name)
            tools.append(t)

    known: dict[str, str] = {}
    known_path = Path(args.known_fps)
    if known_path.exists() and known_path.stat().st_size > 0:
        for entry in json.loads(known_path.read_text(encoding="utf-8")):
            known[_key(entry)] = entry.get("reason", "(no reason given)")

    rep = build_report(tools, corpus=", ".join(str(c) for c in corpora), known=known)
    text = json.dumps(rep, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    print(
        f"benign: {rep['flagged']}/{rep['n_descriptions']} flagged "
        f"({rep['known_false_positives']} known, {rep['unexplained']} unexplained) | "
        f"95% upper bound {rep['wilson_upper_95'] * 100:.2f}% (Wilson) / "
        f"{rep['rule_of_three_95'] * 100:.2f}% (rule of three)",
        file=sys.stderr,
    )
    if args.check and rep["unexplained"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
