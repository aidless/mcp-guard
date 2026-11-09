"""RED test: mid-sentence read phrases must NOT suppress mutating verbs.

This captures the false-negative class discovered in the audit. The rulepack must not
silently promote to read-only when the description's *first* action verb is clearly
mutating and a later clause merely mentions an observation target ("and show a receipt",
"... the status of ...", "... and list recipients", "... version-controlled permissions").

Direction A: mechanism (leading-position guard) — mutating if first verb != read phrase.
Direction B: production criterion (strictness) — don't over-suppress.
"""
from __future__ import annotations
import pytest
from guard.capability import scan_capability, T2_MUTATE


def tool(name, description="", properties=None):
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": properties or {}},
    }


def test_mid_sentence_show_doesnt_suppress_mutate():
    """A tool that sends an email and shows a recipient list remains T2, not T0."""
    # Leading action "Send" + mid-sentence "show " → must be T2
    result = scan_capability(tool(
        "send_email_and_list",
        "Send an email and list recipients",
    ))
    assert result["tier"] == T2_MUTATE, \
        "Mid-sentence 'show ' must not suppress leading 'Send'"


def test_mid_sentence_status_doesnt_suppress_mutate():
    """An order update with 'status' mid-sentence stays T2."""
    result = scan_capability(tool(
        "update_order_status",
        "Update the status of an order",
    ))
    assert result["tier"] == T2_MUTATE, \
        "Mid-sentence 'status' must not suppress leading 'Update'"


def test_mid_sentence_list_doesnt_suppress_mutate():
    """Transfer funds with 'list a receipt' stays T2."""
    result = scan_capability(tool(
        "transfer_funds_with_receipt",
        "Move money to a payee and list a receipt",
    ))
    assert result["tier"] == T2_MUTATE, \
        "Mid-sentence 'list ' must not suppress leading 'Move'"


def test_version_controlled_permissions_is_t2():
    """Setting version-controlled permissions is T2, not T0."""
    result = scan_capability(tool(
        "set_versioned_perms",
        "Set version-controlled permissions",
    ))
    assert result["tier"] == T2_MUTATE, \
        "'version' as substring must not suppress leading 'Set'"
