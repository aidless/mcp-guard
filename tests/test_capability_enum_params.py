"""Enum-aware dangerous-param tiering.

A param named `command` whose schema constrains it to a closed enum of
harmless verbs (e.g. ["snapshot", "status"]) is NOT an execution surface:
the caller cannot smuggle arbitrary commands past the schema. A free-form
string `command` still is. The tier must come from what the schema actually
permits, not from the parameter's name alone.

Direction A (mechanism): drop the enum check in _param_hits -> the
enum-constrained fixture must go back to T3, proving the check is load-bearing.
Direction B (criterion): treating "any enum" as safe (e.g. ignoring the values)
-> the hostile-enum fixture ["snapshot", "shell -c"] must go RED.
"""
from __future__ import annotations
from guard.capability import scan_capability, T2_MUTATE, T3_DESTRUCTIVE


def _tool(props):
    return {"name": "runner", "description": "Run a controlled operation",
            "inputSchema": {"type": "object", "properties": props}}


def test_enum_constrained_command_is_not_exec():
    """Closed enum of harmless verbs: the dangerous-param hit must not fire as T3."""
    result = scan_capability(_tool({
        "command": {"type": "string", "enum": ["snapshot", "status", "list-apps"]},
    }))
    assert result["tier"] != T3_DESTRUCTIVE, (
        "enum-constrained command must not be tiered as exec; got "
        f"{result['tier']} with hits {[h['rule'] for h in result['hits']]}"
    )


def test_free_form_command_still_exec():
    """Free-form string command remains an execution surface."""
    result = scan_capability(_tool({"command": {"type": "string"}}))
    assert result["tier"] == T2_MUTATE  # dangerous-param command -> T2


def test_hostile_enum_values_keep_tier():
    """An enum that itself contains a command-bearing value stays exec."""
    result = scan_capability(_tool({
        "command": {"type": "string", "enum": ["snapshot", "sh -c $_PAYLOAD"]},
    }))
    assert result["tier"] == T3_DESTRUCTIVE


def test_enum_tier_never_exceeds_enum_values():
    """Tier of an enum param = max tier of its values, nothing higher."""
    result = scan_capability(_tool({
        "command": {"type": "string", "enum": ["snapshot", "clear history"]},
    }))
    # "clear history" is bulk-clear T3 by the prose rules; so T3 is correct here.
    assert result["tier"] == T3_DESTRUCTIVE
