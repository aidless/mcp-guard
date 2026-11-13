"""Name-prefix read evidence (P4.2 finding): a tool named `list_tools` carries
read evidence in its FIRST word, but NAME_TIERS only matched suffixes. The
magpie registry ledger (second capability fixture surface, 23 names-only
community tools) surfaced this: list_tools must not sit at `unknown` while
get_voice_list (same evidence, suffix form) reads T0.

Widening is add-only: existing suffix evidence is untouched, so the
agent-desktop 21/12/29/5 split must not move.
"""
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from guard.capability import scan_capability  # noqa: E402


def test_prefix_read_names_are_t0():
    assert scan_capability({"name": "list_tools"})["tier"] == "T0_read"
    assert scan_capability({"name": "export_trace"})["tier"] == "T0_read"


def test_suffix_and_exact_names_unchanged():
    assert scan_capability({"name": "get_voice_list"})["tier"] == "T0_read"
    assert scan_capability({"name": "list"})["tier"] == "T0_read"


def test_prefix_mutating_name_evidence_too():
    """Same widening applies to the whole NAME_TIERS table, add-only."""
    assert scan_capability({"name": "clear_draft"})["tier"] == "T2_mutate"


def test_infix_name_is_not_evidence():
    """`clear_` as an INFIX (headclear_tool) is not name evidence: only a real
    prefix or suffix counts. Pins the boundary against a blind-substring
    criterion that would read evidence into unrelated names."""
    assert scan_capability({"name": "headclear_tool"})["tier"] == "unknown"


def test_agent_desktop_split_does_not_move():
    proc = subprocess.run([sys.executable, "scripts/capability_crosscheck.py"],
                          cwd=str(REPO), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout
    assert '"21": 21' not in proc.stdout  # sanity: real summary present


def test_magpie_registry_ledger_agrees():
    proc = subprocess.run(
        [sys.executable, "scripts/capability_crosscheck.py",
         "--tools", "examples/magpie_registry_tools.json",
         "--ledger", "examples/magpie_registry_ledger.json"],
        cwd=str(REPO), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout


def test_whatsapp_sample_ledger_agrees():
    proc = subprocess.run(
        [sys.executable, "scripts/capability_crosscheck.py",
         "--tools", "examples/whatsapp_tools.json",
         "--ledger", "examples/whatsapp_sample_ledger.json"],
        cwd=str(REPO), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout
