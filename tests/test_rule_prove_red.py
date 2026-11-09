"""Per-rule prove-red battery (P4.1): every rule in the pack must demonstrably
fire on at least one minimal fixture.

A rule that cannot fire is decorative: it adds regex surface without adding
detection. The battery enumerates the LIVE rulepack (guard.rules.RULES +
guard.capability.CAPABILITY_RULES) and asserts a covering fixture table --
a newly added rule without a fixture turns CI red, and a fixture that stops
firing (rule regex edited away) turns CI red too.
"""
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts.rule_prove_red import build_report  # noqa: E402
from guard.rules import RULES  # noqa: E402
from guard.capability import CAPABILITY_RULES  # noqa: E402


def test_every_live_rule_fires_on_its_fixture():
    report = build_report()
    assert report["exit_code"] == 0, report["summary"]
    poison_ids = {r["id"] for r in RULES}
    cap_ids = {r["id"] for r in CAPABILITY_RULES}
    assert poison_ids <= set(report["poison"]["fired"]), \
        f"unfired poison rules: {poison_ids - set(report['poison']['fired'])}"
    assert cap_ids <= set(report["capability"]["fired"]), \
        f"unfired capability rules: {cap_ids - set(report['capability']['fired'])}"


def test_new_rule_without_fixture_is_red():
    """A rule added to the pack with no fixture must fail the battery."""
    report = build_report(extra_poison_rules=[{"id": "phantom-rule",
                                               "patterns": ["nothing"]}])
    assert report["exit_code"] == 1
    assert "phantom-rule" in report["summary"]


def test_broken_rule_regex_is_red():
    """If a rule's regex is edited so it can no longer fire, CI must go red."""
    report = build_report(broken_rule_ids={"secret-read"})
    assert report["exit_code"] == 1
    assert "secret-read" in report["summary"]


def test_script_exit_zero_on_current_rulepack():
    proc = subprocess.run([sys.executable, "scripts/rule_prove_red.py"],
                          cwd=str(REPO), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
