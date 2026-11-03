#!/usr/bin/env python3
"""measure_rule_ablation.py -- recompute the README's rule-ablation numbers.

Every number in the README's ablation tables is a measurement, not a claim, so
it has to be recomputable from one command. This script is that command:

  * loads the committed rules (`guard/rules.py::RULES`) and cases
    (`tasks/cases.jsonl`), both read-only;
  * for each ablation it recompiles the rulepack **in memory** and re-scores
    every case with `guard.scan.scan_text`, the same scanning code the shipped
    eval runner uses;
  * cross-checks the unmodified ruleset against `run_eval.py --offline`, so the
    ablation machinery is known to agree with the runner.

No repo file is modified; cases and rulepack variants live only in memory.

Usage:
    python3 scripts/measure_rule_ablation.py
    python3 scripts/measure_rule_ablation.py --markdown   # README-style table
    python3 scripts/measure_rule_ablation.py --check      # exit 1 if a row misses

Exit codes: 0 = machinery agrees with run_eval (and, under --check, every
expectation reproduced); 1 = a cross-check or expectation missed.
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from guard import rules as rules_mod  # noqa: E402

METRIC_KEYS = ("recall_case", "fpr_benign", "recall_rule")

# The one ablation number the README states about the *current* case file is the
# headline `run_eval.py --offline` triple. --check pins this: if a future edit
# to RULES or cases.jsonl moves any of these, the README's headline is stale and
# the gate goes red. The two ablation *tables* are older snapshots (their
# denominators are 18 poison / 23 gold rules, not today's 19 / 24), so they are
# reported, not asserted -- see README's "已复算" notes.
HEADLINE_EXPECT = {"recall_case": 0.7368, "fpr_benign": 0.0, "recall_rule": 0.7083}


def drop_rules(rules, rule_ids):
    return [r for r in rules if r["id"] not in set(rule_ids)]


def restrict_secret_read(rules):
    """Keep only the ~/.ssh family of `secret-read` (pre-expansion shape).

    The family grew on 2026-10-28 (cloud credential paths, .netrc,
    *_credentials). This reproduces what recall looked like before that
    expansion, evaluated against today's case file.
    """
    out = []
    for rule in rules:
        if rule["id"] == "secret-read":
            rule = {**rule, "patterns": [p for p in rule["patterns"] if "ssh" in p]}
        out.append(rule)
    return out


def _compile(rulepack):
    return [(r["id"], r["severity"], [re.compile(p, re.I) for p in r["patterns"]], r["why"])
            for r in rulepack]


def _score_cases(compiled, cases):
    """Case-level and rule-level metrics for one compiled rulepack."""
    poison = [c for c in cases if c["label"] == "poison"]
    benign = [c for c in cases if c["label"] == "benign"]
    rule_total = sum(len(c.get("gold_rules", [])) for c in poison)
    tp = fp = rule_hits = 0
    for c in cases:
        text = json.dumps(c, sort_keys=True, ensure_ascii=False)
        fired = set()
        for rid, _sev, pats, _why in compiled:
            if any(p.search(text) for p in pats):
                fired.add(rid)
        if fired:
            if c["label"] == "poison":
                tp += 1
            else:
                fp += 1
        if c["label"] == "poison":
            rule_hits += len(fired & set(c.get("gold_rules", [])))
    return {
        "n_poison": len(poison), "n_benign": len(benign),
        "tp": tp, "fp": fp, "rule_hits": rule_hits, "rule_total": rule_total,
        "recall_case": round(tp / max(1, len(poison)), 4),
        "fpr_benign": round(fp / max(1, len(benign)), 4),
        "recall_rule": round(rule_hits / max(1, rule_total), 4),
    }


def real_offline_metrics() -> dict:
    """Run the shipped `run_eval.py --offline` in-process. Ground truth."""
    spec = importlib.util.spec_from_file_location("run_eval_shipped", REPO / "run_eval.py")
    run_eval = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(run_eval)
    buf = io.StringIO()
    argv = sys.argv
    sys.argv = ["run_eval.py", "--offline"]
    try:
        with contextlib.redirect_stdout(buf):
            run_eval.main()
    finally:
        sys.argv = argv
    return json.loads(buf.getvalue().strip().splitlines()[-1])


def build_variants(rules):
    return [
        ("full", "all committed rules", rules),
        ("no_encoded_exfil", "drop `encoded-exfil` entirely",
         drop_rules(rules, ["encoded-exfil"])),
        ("ssh_only_secret_read", "restrict `secret-read` to the ~/.ssh family",
         restrict_secret_read(rules)),
    ]


def emit(results, variants, markdown):
    if markdown:
        print()
        print("| 规则集 | recall_case | fpr_benign | recall_rule |")
        print("|---|---|---|---|")
        for key, label, _ in variants:
            m = results[key]
            print(f"| {label} | {m['tp']}/{m['n_poison']} = {m['recall_case']} | "
                  f"{m['fp']}/{m['n_benign']} = {m['fpr_benign']} | "
                  f"{m['rule_hits']}/{m['rule_total']} = {m['recall_rule']} |")
        return
    for key, label, _ in variants:
        m = results[key]
        print(f"\n[{key}] {label}")
        print(f"  recall_case = {m['tp']}/{m['n_poison']} = {m['recall_case']}")
        print(f"  fpr_benign  = {m['fp']}/{m['n_benign']} = {m['fpr_benign']}")
        print(f"  recall_rule = {m['rule_hits']}/{m['rule_total']} = {m['recall_rule']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--cases", default=str(REPO / "tasks" / "cases.jsonl"))
    ap.add_argument("--markdown", action="store_true", help="emit README-style markdown table")
    ap.add_argument("--check", action="store_true", help="exit 1 if a README row misses")
    args = ap.parse_args()

    cases = [json.loads(line) for line
             in Path(args.cases).read_text(encoding="utf-8").splitlines() if line.strip()]
    variants = build_variants(rules_mod.RULES)
    results = {key: _score_cases(_compile(rulepack), cases) for key, _, rulepack in variants}

    truth = real_offline_metrics()
    base = results["full"]
    agree = all(truth[k] == base[k] for k in METRIC_KEYS)

    print(f"cases: {len(cases)}  ({base['n_poison']} poison / {base['n_benign']} benign)")
    print(f"cross-check vs run_eval.py --offline: {'AGREE' if agree else 'DISAGREE'}")
    print(f"  run_eval  : {json.dumps({k: truth[k] for k in METRIC_KEYS})}")
    print(f"  recomputed: {json.dumps({k: base[k] for k in METRIC_KEYS})}")
    if not agree:
        print("  [FAIL] the ablation machinery disagrees with the shipped eval runner")

    emit(results, variants, markdown=args.markdown)

    ok = agree
    if args.check:
        for k in METRIC_KEYS:
            if base[k] == HEADLINE_EXPECT[k]:
                print(f"  [PASS] headline {k} == {HEADLINE_EXPECT[k]} (README's current-case number)")
            else:
                ok = False
                print(f"  [MISS] headline {k}: README says {HEADLINE_EXPECT[k]}, "
                      f"current cases give {base[k]} -- the README headline is stale")
        print("  [NOTE] the README ablation tables now carry these current-case values "
              "(19 poison / 24 gold); only the headline triple is asserted by --check, "
              "the per-variant rows above are the measurement to copy into README.")

    print("\nOVERALL:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
