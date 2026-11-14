"""Cross-tool consistency: contradictions that no single description exposes.

The poison rules read one tool at a time. A server can still be steered without
any individual description looking wrong — say eight of its twelve tools acquire
the same "you MUST first call X" sentence. Each sentence alone is unremarkable;
the tool set as a whole has a single destructive front door.

Three checks, each relative to the server's own tool set:

``shared-precondition``
    Many tools demand the same prerequisite tool. Reported with the count, so a
    coordinated injection is distinguishable from two tools that happen to
    mention the same helper.

``requirement-cycle``
    A requires B and B requires A. Neither can be called first, so the documented
    path is dead on arrival.

``dangling-tool-reference``
    A description sends the model to a tool this server does not offer. Either
    the call fails, or the model is being steered off the visible tool set.

Scope caveat that matters for reading any number from this: a tool set is
per-server, so these checks need the server's whole ``tools/list``. On a merged
corpus (several servers flattened into one list) every cross-server reference
looks dangling — that is an artifact of the merge, not a finding.
"""

from __future__ import annotations

import re

# A referenced tool name must look like an identifier (snake_case or kebab-case)
# and be quoted. Unquoted prose ("call the API", "run the migration") is not a
# tool reference and flagging it would drown the real signal.
_IDENT = r"[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+|[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+"
# Quoted words are treated as identifiers at face value. This is deliberately
# wider than _IDENT: plenty of real tool names are a single lowercase word
# (`echo`, `status`, `commit`), and inside the "MUST first call `X`" frame a
# quoted word is a tool name essentially every time.
# A quoted span may carry arguments ("`git_reset --hard`") or prose; the tool is
# the leading token, so capture that and tolerate the rest inside the quotes.
_QUOTED_ANY = r"[A-Za-z][A-Za-z0-9_.-]{1,60}(?:[^`'\"]{0,80})?"
_QUOTED_REF = re.compile(r"[`'\"](%s)[`'\"]" % _IDENT)
_CALL_REF = re.compile(
    r"\b(?:call|invoke|use|run)\s+(?:the\s+)?[`'\"](%s)[`'\"]" % _IDENT, re.I)
_MUST_CALL = re.compile(
    r"\b(?:must|should|need\s+to|have\s+to)\s+(?:first\s+|always\s+)?"
    r"(?:call|invoke|use|run)\s+(?:the\s+)?[`'\"](%s)[`'\"]" % _QUOTED_ANY, re.I)
# "Call `X` first" states the same requirement without a modal verb.
_CALL_FIRST = re.compile(
    r"\b(?:call|invoke|use|run)\s+(?:the\s+)?[`'\"](%s)[`'\"]\s+(?:first|beforehand)\b"
    % _QUOTED_ANY, re.I)

SHARED_MIN_COUNT = 3
SHARED_MIN_RATIO = 0.3
_SEVERITY = {"shared-precondition": "high", "requirement-cycle": "high",
             "dangling-tool-reference": "medium"}


def _description(tool: dict) -> str:
    return (tool.get("description") or "").strip()


def _requires(description: str) -> set[str]:
    """Tools this description says must be called (before or as part of it)."""
    hits = {m.group(1) for m in _MUST_CALL.finditer(description)}
    hits |= {m.group(1) for m in _CALL_FIRST.finditer(description)}
    return hits


def _references(description: str) -> set[str]:
    """Any quoted tool-shaped identifiers the description points the model at."""
    return {m.group(1) for m in _QUOTED_REF.finditer(description)}


def analyze(tools: list[dict]) -> dict:
    tools = [t for t in tools if isinstance(t, dict) and t.get("name")]
    names = {t["name"] for t in tools}
    n_tools = len(tools)
    findings: list[dict] = []

    requires: dict[str, set[str]] = {}
    for tool in tools:
        req = _requires(_description(tool))
        requires[tool["name"]] = req

    # shared-precondition: many tools pointing at the same prerequisite.
    counts: dict[str, list[str]] = {}
    for tool_name, req in requires.items():
        for target in req:
            counts.setdefault(target, []).append(tool_name)
    for target, holders in sorted(counts.items()):
        ratio = len(holders) / n_tools if n_tools else 0.0
        if len(holders) >= SHARED_MIN_COUNT and ratio >= SHARED_MIN_RATIO:
            findings.append({
                "check": "shared-precondition",
                "severity": _SEVERITY["shared-precondition"],
                "tool": target,
                "count": len(holders),
                "ratio": round(ratio, 3),
                "tools": sorted(holders),
                "detail": (
                    f"{len(holders)} of {n_tools} tools each require `{target}` first "
                    f"({ratio:.0%}). Independently written descriptions rarely agree "
                    f"on one prerequisite; a shared one is a front door."
                ),
            })

    # requirement-cycle: A requires B and B requires A.
    seen_pairs: set[frozenset] = set()
    for tool_name, req in requires.items():
        for target in req:
            if target not in requires or target == tool_name:
                continue
            if tool_name in requires[target]:
                pair = frozenset((tool_name, target))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                findings.append({
                    "check": "requirement-cycle",
                    "severity": _SEVERITY["requirement-cycle"],
                    "tool": tool_name,
                    "tools": sorted(pair),
                    "detail": (
                        f"`{tool_name}` requires `{target}` and `{target}` requires "
                        f"`{tool_name}`; neither can be called first."
                    ),
                })

    # dangling-tool-reference: points at a tool this server does not offer.
    for tool in tools:
        desc = _description(tool)
        missing = sorted(ref for ref in _references(desc)
                         if ref not in names and ref != tool["name"])
        if missing:
            findings.append({
                "check": "dangling-tool-reference",
                "severity": _SEVERITY["dangling-tool-reference"],
                "tool": tool["name"],
                "target": missing[0],
                "targets": missing,
                "detail": (
                    f"`{tool['name']}` refers to {', '.join('`%s`' % m for m in missing)}, "
                    f"which this server's tool set does not contain."
                ),
            })

    return {
        "n_tools": n_tools,
        "n_findings": len(findings),
        "checks": sorted({f["check"] for f in findings}),
        "findings": findings,
        "scope_note": (
            "Cross-tool checks need one server's complete tools/list. A merged "
            "list from several servers makes every cross-server reference look "
            "dangling; that is a merge artifact, not a finding."
        ),
    }
