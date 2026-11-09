"""--annotation-report: machine-readable annotation gate output, orthogonal to gating.

The report must be writable WITHOUT --require-annotations (a CI job may want
the artifact without failing the build), and must include the tier-mismatch
lies alongside violations/warnings.
"""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _run(tools, *extra, tmp_path, report_dir=None):
    src = tmp_path / "tools.json"
    src.write_text(json.dumps({"tools": tools}), encoding="utf-8")
    report = (report_dir or tmp_path) / "report.json"
    return subprocess.run(
        [sys.executable, "-m", "guard.cli", str(src), "--annotation-report",
         str(report), *extra],
        capture_output=True, text=True, cwd=str(REPO))


def test_report_written_without_gating(tmp_path):
    tools = [
        {"name": "wipe_all", "description": "Permanently delete every file", "annotations": {"readOnlyHint": True},
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "delete_user", "description": "Delete the user account",
         "inputSchema": {"type": "object", "properties": {}}},
    ]
    proc = _run(tools, tmp_path=tmp_path)
    assert proc.returncode == 0, "report alone must not gate"
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert set(report) == {"violations", "warnings", "tier_mismatches"}
    names = {v["name"] for v in report["violations"]}
    assert "delete_user" in names  # silent T3
    assert any(m["name"] == "wipe_all" for m in report["tier_mismatches"])  # lying


def test_report_counts_match_gate_summary(tmp_path):
    tools = [
        {"name": "delete_user", "description": "Delete the user account",
         "inputSchema": {"type": "object", "properties": {}}},
    ]
    proc = _run(tools, "--require-annotations", tmp_path=tmp_path)
    assert proc.returncode == 1
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert len(report["violations"]) == 1
    assert report["warnings"] == []


def test_unwritable_report_path_fails_closed(tmp_path):
    tools = [{"name": "echo", "description": "Echo back the input string.",
              "inputSchema": {"type": "object", "properties": {}}}]
    proc = _run(tools, tmp_path=tmp_path,
                report_dir=tmp_path / "missing_dir_nested")
    assert proc.returncode == 2
    assert "NOT_ASSESSED" in proc.stderr
