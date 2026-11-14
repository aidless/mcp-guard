"""Capability rules + annotation gate.

Two-directional mutation record (see guard-test-two-direction-mutation):

Direction A — mechanism (batch unwrapping):
  production edit: MAX_BATCH_DEPTH = 0 in guard/capability.py.
  test_batch_unwrapping_raises_tier and test_unwrap_payload_handles_live_arguments
  must go RED, because the inner commands are no longer inspected.

Direction B — production criterion (annotation gate):
  production edit: in annotation_violations, accept any non-empty annotations
  dict as compliant (drop the destructiveHint/readOnlyHint checks).
  test_destructive_needs_explicit_hint must go RED, because the fixture carries
  annotations but claims destructiveHint=false, which only the real rule rejects.
"""
from __future__ import annotations

import json

from guard import capability
from guard.capability import (
    T0_READ,
    T2_MUTATE,
    T3_DESTRUCTIVE,
    annotation_violations,
    scan_capability,
    summarise,
    unwrap_payload,
)


def tool(name, description="", properties=None, annotations=None):
    out = {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": properties or {}},
    }
    if annotations is not None:
        out["annotations"] = annotations
    return out


def test_destructive_verb_is_t3():
    result = scan_capability(tool("delete_repo", "Delete the repository"))
    assert result["tier"] == T3_DESTRUCTIVE
    assert any(h["rule"] == "destructive-verb" for h in result["hits"])


def test_close_app_with_force_is_t3():
    result = scan_capability(tool(
        "desktop_close_app",
        "Quit an application gracefully",
        {"app": {"type": "string"}, "force": {"type": "boolean"}},
    ))
    assert result["tier"] == T3_DESTRUCTIVE
    rules = {h["rule"] for h in result["hits"]}
    assert "close-or-shutdown" in rules
    assert "dangerous-param" in rules


def test_launch_is_exec():
    result = scan_capability(tool(
        "desktop_launch",
        "Launch application and return once its process is running",
        {"app": {"type": "string"}, "args": {"type": "array"}},
    ))
    assert result["tier"] == T3_DESTRUCTIVE
    assert any(h["rule"] == "exec-or-launch" for h in result["hits"])


def test_read_tool_is_t0():
    result = scan_capability(tool("desktop_snapshot", "Capture accessibility tree"))
    assert result["tier"] == T0_READ
    assert result["unknown"] is False


def test_unrecognised_tool_is_unknown_not_read_only():
    result = scan_capability(tool("frobnicate", "Do something to the frobnicator"))
    assert result["tier"] == "unknown"
    assert result["unknown"] is True


def test_mutation_without_destruction_is_t2():
    result = scan_capability(tool("desktop_set_value", "Set element value"))
    assert result["tier"] == T2_MUTATE


def test_batch_unwrapping_raises_tier():
    payload = json.dumps([{"command": "close_app", "args": {"app": "Notes", "force": True}}])
    result = scan_capability(tool(
        "orchestrate",
        "Apply a list of steps",
        {"steps": {"type": "string", "default": payload}},
    ))
    assert result["tier"] == T3_DESTRUCTIVE
    inner = result["batch"][0]["inner"]
    assert inner and inner[0]["tier"] == T3_DESTRUCTIVE


def test_batch_without_default_is_opaque_not_clean():
    result = scan_capability(tool(
        "desktop_batch",
        "Execute a bounded command batch",
        {"commands_json": {"type": "string"}},
    ))
    assert result["tier"] == T3_DESTRUCTIVE  # exec-or-launch on "Execute"
    assert result["batch"][0]["status"] == "opaque"


def test_unwrap_payload_handles_live_arguments():
    inner = unwrap_payload([
        {"command": "snapshot", "args": {"app": "Notes"}},
        {"command": "close_app", "args": {"app": "Notes"}},
    ])
    assert [item["tier"] for item in inner] == [T0_READ, T3_DESTRUCTIVE]


def test_unwrap_payload_depth_is_bounded():
    inner = capability._unwrap_value(
        [{"command": "close_app", "args": {"app": "Notes"}}],
        depth=capability.MAX_BATCH_DEPTH,
    )
    assert inner[0]["tier"] == "unknown"
    assert inner[0]["opaque"] is True


def test_summarise_counts():
    results = [
        scan_capability(tool("desktop_snapshot", "Capture accessibility tree")),
        scan_capability(tool("desktop_close_app", "Quit an application")),
        scan_capability(tool("mystery", "???")),
    ]
    summary = summarise(results)
    assert summary["total"] == 3
    assert summary["tiers"][T0_READ] == 1
    assert summary["tiers"][T3_DESTRUCTIVE] == 1
    assert summary["tiers"]["unknown"] == 1
    assert summary["destructive"] == ["desktop_close_app"]


def test_missing_annotations_is_violation_for_mutating():
    target = tool("desktop_close_app", "Quit an application")
    results = [scan_capability(target)]
    violations, warnings = annotation_violations([target], results)
    assert [v["reason"] for v in violations] == ["missing-annotations"]
    assert warnings == []


def test_read_only_missing_annotations_is_warning():
    target = tool("desktop_snapshot", "Capture accessibility tree")
    results = [scan_capability(target)]
    violations, warnings = annotation_violations([target], results)
    assert violations == []
    assert [w["reason"] for w in warnings] == ["missing-annotations"]


def test_destructive_needs_explicit_hint():
    # Direction B fixture: annotations exist, but destructiveHint is false.
    # A gate that only checks "annotations present" would wrongly pass this.
    target = tool(
        "desktop_close_app",
        "Quit an application",
        annotations={"readOnlyHint": False, "destructiveHint": False},
    )
    results = [scan_capability(target)]
    violations, _ = annotation_violations([target], results)
    assert "destructive-without-destructiveHint" in [v["reason"] for v in violations]


def test_correct_annotations_pass():
    target = tool(
        "desktop_close_app",
        "Quit an application",
        annotations={"readOnlyHint": False, "destructiveHint": True},
    )
    results = [scan_capability(target)]
    violations, warnings = annotation_violations([target], results)
    assert violations == [] and warnings == []


def test_cli_fail_on_capability(tmp_path):
    from guard.cli import main
    path = tmp_path / "tools.json"
    path.write_text(json.dumps({"tools": [tool("desktop_close_app", "Quit an application")]}),
                    encoding="utf-8")
    assert main([str(path), "--fail-on-capability"]) == 1
    assert main([str(path), "--capability"]) == 0


def test_cli_require_annotations(tmp_path):
    from guard.cli import main
    path = tmp_path / "tools.json"
    path.write_text(json.dumps({"tools": [tool("desktop_set_value", "Set element value")]}),
                    encoding="utf-8")
    assert main([str(path), "--require-annotations"]) == 1


def test_cli_clean_read_only_with_annotations(tmp_path):
    from guard.cli import main
    path = tmp_path / "tools.json"
    path.write_text(json.dumps({"tools": [tool(
        "desktop_snapshot", "Capture accessibility tree",
        annotations={"readOnlyHint": True},
    )]}), encoding="utf-8")
    assert main([str(path), "--require-annotations"]) == 0
