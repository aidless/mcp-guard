"""Regression: the shipped rulepack agrees with the agent-desktop case ledger.

Two-directional mutation record for the cross-check itself:

Direction A (mechanism): remove the `NAME_TIERS` "clear" override; the ledger's
desktop_clear (T2) becomes unknown and the check must go RED.
Direction B (criterion): in scan_capability, make _tier_max always return
T0_READ; the five T3 tools drop and the check must go RED.
"""
import json
from pathlib import Path

from guard.capability import scan_capability

LEDGER = Path(__file__).resolve().parents[1] / "examples/agent_desktop_1_2_0_ledger.json"
FIXTURE = Path(__file__).with_name("agent_desktop_tools.json")


def test_fixture_is_a_subset_of_the_case_ledger():
    tools = json.loads(FIXTURE.read_text(encoding="utf-8"))["tools"]
    ledger = {row["name"]: row["tier"] for row in
              json.loads(LEDGER.read_text(encoding="utf-8"))["tiers"]}
    for tool in tools:
        name = tool["name"]
        assert name in ledger, f"fixture tool {name} missing from case ledger"
        assert scan_capability(tool)["tier"].split("_")[0] == ledger[name].split("_")[0]


def test_local_state_names_are_not_unknown():
    for name in ("desktop_session_start", "desktop_focus_window", "desktop_trace_export"):
        tool = next(t for t in json.loads(FIXTURE.read_text(encoding="utf-8"))["tools"]
                    if t["name"] == name)
        assert scan_capability(tool)["unknown"] is False
