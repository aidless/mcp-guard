"""Offline eval: recall on poison, false-positive rate on benign. No model calls."""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guard.scan import check_drift, digest_tool, scan_tool


def load_cases(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--cases", default="tasks/cases.jsonl")
    ap.add_argument("--scan-file", default=None)
    a = ap.parse_args()

    if a.scan_file:
        with open(a.scan_file, encoding="utf-8") as f:
            tools = json.load(f)
        if isinstance(tools, dict):
            tools = tools.get("tools", [tools])
        for t in tools:
            print(json.dumps(scan_tool(t), ensure_ascii=False))
        # Drift demo: pin the definitions as seen now, then re-check a version in
        # which one description was rewritten after approval. Field-level output,
        # not just "DRIFT".
        pinned = {t.get("name", "?"): digest_tool(t) for t in tools}
        snapshots = {t.get("name", "?"): t for t in tools}
        for t in tools:
            print(json.dumps(check_drift(t, pinned, snapshots), ensure_ascii=False))
        return 0

    cases = load_cases(a.cases)
    poison = [c for c in cases if c["label"] == "poison"]
    benign = [c for c in cases if c["label"] == "benign"]
    tp = sum(1 for c in poison if scan_tool(c)["flagged"])
    fp = sum(1 for c in benign if scan_tool(c)["flagged"])
    # rule-level recall: gold rule fires?
    rule_hits = 0
    rule_total = sum(len(c.get("gold_rules", [])) for c in poison)
    for c in poison:
        fired = {h["rule"] for h in scan_tool(c)["hits"]}
        rule_hits += len(set(c.get("gold_rules", [])) & fired)
    print(json.dumps({
        "encoder": "rules-v1", "n_poison": len(poison), "n_benign": len(benign),
        "recall_case": round(tp / max(1, len(poison)), 4),
        "fpr_benign": round(fp / max(1, len(benign)), 4),
        "recall_rule": round(rule_hits / max(1, rule_total), 4),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
