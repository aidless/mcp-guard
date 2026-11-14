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
    return doc.get("tools", [])


def build_report(tools: list[dict], corpus: str = "examples/benign_corpus.json") -> dict:
    descriptions = [(t.get("name", ""), (t.get("description") or "").strip())
                    for t in tools if isinstance(t, dict)]
    descriptions = [(name, text) for name, text in descriptions if text]

    false_positives = []
    for name, text in descriptions:
        hits = scan_text(text)
        if hits:
            false_positives.append({
                "name": name,
                "rules": sorted({h["rule"] for h in hits}),
                "anchors": sorted({h["anchor"] for h in hits if h.get("anchor")}),
            })

    n = len(descriptions)
    flagged = len(false_positives)
    return {
        "corpus": corpus,
        "n_descriptions": n,
        "flagged": flagged,
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
    ap.add_argument("--corpus", default=str(REPO / "examples" / "benign_corpus.json"))
    ap.add_argument("--out", help="write the report here instead of stdout")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if any benign description is flagged")
    args = ap.parse_args()

    corpus = Path(args.corpus)
    if not corpus.exists():
        print(f"corpus not found: {corpus}", file=sys.stderr)
        return 2

    rep = build_report(load_corpus(corpus), corpus=str(corpus))
    text = json.dumps(rep, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    print(
        f"benign: {rep['flagged']}/{rep['n_descriptions']} flagged | "
        f"95% upper bound {rep['wilson_upper_95'] * 100:.2f}% (Wilson) / "
        f"{rep['rule_of_three_95'] * 100:.2f}% (rule of three)",
        file=sys.stderr,
    )
    if args.check and rep["flagged"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
