"""capability_manifest cross-run drift: the rug-pull axis applied to capability.

Between two runs of the same server, a tool whose tier silently climbs
(T2 -> T3) or whose hit set grows is the capability-layer twin of the
poisoning drift that guard/drift.py covers for rule hits.
"""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "capability_drift.py"


def _manifest(tiers: dict) -> dict:
    return {
        "source": "proxy",
        "summary": {"total": len(tiers)},
        "tools": [{"name": name, "tier": tier,
                   "hits": [{"rule": "destructive-verb", "tier": tier}] if tier != "unknown" else []}
                  for name, tier in tiers.items()],
    }


def _run(*argv):
    return subprocess.run([sys.executable, str(SCRIPT), *argv],
                          capture_output=True, text=True)


def test_tier_climb_is_reported(tmp_path):
    base = tmp_path / "base.json"; cur = tmp_path / "cur.json"
    base.write_text(json.dumps(_manifest({"wiper": "T2_mutate_state"})))
    cur.write_text(json.dumps(_manifest({"wiper": "T3_destructive_or_exec"})))
    proc = _run("--baseline", str(base), "--current", str(cur), "--fail-on-drift")
    assert proc.returncode == 1, proc.stdout
    report = json.loads(proc.stdout)
    assert report["changed"][0]["name"] == "wiper"
    assert report["changed"][0]["baseline_tier"] == "T2_mutate_state"
    assert report["changed"][0]["current_tier"] == "T3_destructive_or_exec"
    assert report["added"] == [] and report["removed"] == []


def test_added_and_removed_tools_are_reported(tmp_path):
    base = tmp_path / "base.json"; cur = tmp_path / "cur.json"
    base.write_text(json.dumps(_manifest({"a": "T0_read", "b": "T0_read"})))
    cur.write_text(json.dumps(_manifest({"a": "T0_read", "c": "T3_destructive_or_exec"})))
    proc = _run("--baseline", str(base), "--current", str(cur))
    report = json.loads(proc.stdout)
    assert report["removed"] == ["b"]
    assert report["added"] == ["c"]


def test_identical_manifests_exit_zero(tmp_path):
    base = tmp_path / "base.json"; cur = tmp_path / "cur.json"
    payload = json.dumps(_manifest({"a": "T0_read", "b": "unknown"}))
    base.write_text(payload); cur.write_text(payload)
    proc = _run("--baseline", str(base), "--current", str(cur))
    assert proc.returncode == 0, proc.stdout
    assert json.loads(proc.stdout)["changed"] == []


def test_missing_baseline_fails_closed(tmp_path):
    """A missing baseline is NOT_ASSESSED (exit 2), never a silent 'no drift'."""
    cur = tmp_path / "cur.json"
    cur.write_text(json.dumps(_manifest({"a": "T0_read"})))
    proc = _run("--baseline", str(tmp_path / "nope.json"), "--current", str(cur))
    assert proc.returncode == 2, proc.stdout
    assert "NOT_ASSESSED" in proc.stdout + proc.stderr


def test_malformed_baseline_fails_closed(tmp_path):
    base = tmp_path / "base.json"; cur = tmp_path / "cur.json"
    base.write_text("{not json")
    cur.write_text(json.dumps(_manifest({"a": "T0_read"})))
    proc = _run("--baseline", str(base), "--current", str(cur))
    assert proc.returncode == 2


def test_fail_on_drift_flag_gates_exit(tmp_path):
    base = tmp_path / "base.json"; cur = tmp_path / "cur.json"
    base.write_text(json.dumps(_manifest({"wiper": "T0_read"})))
    cur.write_text(json.dumps(_manifest({"wiper": "T3_destructive_or_exec"})))
    soft = _run("--baseline", str(base), "--current", str(cur))
    hard = _run("--baseline", str(base), "--current", str(cur), "--fail-on-drift")
    assert soft.returncode == 0
    assert hard.returncode == 1
