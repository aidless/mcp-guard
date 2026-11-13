"""scripts/measure_rule_ablation.py -- the ablation numbers must stay recomputable.

Locks two invariants:
  1. the ablation machinery agrees with the shipped `run_eval.py --offline` on
     the full ruleset (if they drift, one of the two is wrong);
  2. the headline triple the README states about the *current* case file is
     still true -- so editing RULES or cases.jsonl without updating the README
     turns this test red.

The historical ablation tables use older denominators (18 poison / 23 gold) and
are intentionally not asserted here; the script reports them as measurements.
"""
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _load(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


abl = _load(str(REPO / "scripts" / "measure_rule_ablation.py"), "measure_rule_ablation")


def _cases():
    import json
    lines = (REPO / "tasks" / "cases.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(l) for l in lines if l.strip()]


def test_machinery_agrees_with_run_eval():
    metrics = abl.real_offline_metrics()
    recomputed = abl._score_cases(abl._compile(abl.rules_mod.RULES), _cases())
    for key in abl.METRIC_KEYS:
        assert metrics[key] == recomputed[key], key


def test_headline_matches_readme():
    recomputed = abl._score_cases(abl._compile(abl.rules_mod.RULES), _cases())
    for key, value in abl.HEADLINE_EXPECT.items():
        assert recomputed[key] == value, (key, recomputed[key], value)


def test_dropping_encoded_exfil_lowers_recall():
    full = abl._compile(abl.rules_mod.RULES)
    ablated = abl._compile(abl.drop_rules(abl.rules_mod.RULES, ["encoded-exfil"]))
    cases = _cases()
    a = abl._score_cases(full, cases)
    b = abl._score_cases(ablated, cases)
    assert b["recall_case"] < a["recall_case"]
    assert b["rule_hits"] < a["rule_hits"]


def test_benign_fpr_stays_zero_across_variants():
    cases = _cases()
    for _key, _label, rulepack in abl.build_variants(abl.rules_mod.RULES):
        assert abl._score_cases(abl._compile(rulepack), cases)["fpr_benign"] == 0.0
