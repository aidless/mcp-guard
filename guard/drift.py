"""Drift detection: compare a tool definition against a pinned snapshot.

A rug pull is not "the file changed" -- it is "the change the reviewer did not
see". So the diff answers two questions the raw sha256 cannot:

  1. WHICH part moved (name / description / schema), because a description edit
     is the known exfiltration vector (Microsoft 2026-06, MCPTox) while a
     schema-wide re-key is usually a client upgrade.
  2. Did the change ADD a rule hit? That is the alarm-worthy case, and it is
     reported separately so a clean-but-different tool is not lumped in with
     one that newly tells the agent to read ~/.ssh.
"""
from __future__ import annotations

import hashlib
import json

from .rules import scan_text

# Fields that carry instructions the model acts on, in decreasing risk order.
INSTRUCTION_FIELDS = ("description", "title", "annotations")


def canon(tool: dict) -> str:
    return json.dumps(tool, sort_keys=True, ensure_ascii=False)


def digest_tool(tool: dict) -> str:
    return hashlib.sha256(canon(tool).encode()).hexdigest()


def _field_text(tool: dict, field: str) -> str:
    value = tool.get(field)
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def changed_fields(old: dict, new: dict) -> list[str]:
    """Field names whose value differs, instruction fields first."""
    keys = set(old) | set(new)
    changed = [k for k in keys
               if canon(old.get(k, "<absent>")) != canon(new.get(k, "<absent>"))]
    return sorted(changed, key=lambda k: (k not in INSTRUCTION_FIELDS, k))


def diff_tool(old: dict, new: dict) -> dict:
    """Classify one tool's drift.

    Returns a dict with:
      status   : ok | changed | new
      fields   : which top-level fields moved
      new_hits : rule hits present in new but not old (the alarm)
      gone_hits: rule hits that disappeared (informational)
    """
    if not old:
        return {"status": "new", "fields": changed_fields({}, new),
                "new_hits": [], "gone_hits": []}
    fields = changed_fields(old, new)
    if not fields:
        return {"status": "ok", "fields": [], "new_hits": [], "gone_hits": []}
    before = {h["rule"] for h in scan_text(_tool_text(old))}
    after = {h["rule"] for h in scan_text(_tool_text(new))}
    return {
        "status": "changed",
        "fields": fields,
        "new_hits": sorted(after - before),
        "gone_hits": sorted(before - after),
    }


def _tool_text(tool: dict) -> str:
    parts = [tool.get("name", ""), tool.get("description", "")]
    schema = tool.get("inputSchema") or tool.get("parameters") or {}
    parts.append(json.dumps(schema, ensure_ascii=False))
    return "\n".join(parts)


def check_drift(tool: dict, pinned: dict[str, str],
                snapshots: dict[str, dict] | None = None) -> dict:
    """Drift check that reports WHERE it moved and whether new rules fired.

    `snapshots` holds the full previous tool objects (not just digests). Without
    it only the digest comparison is possible, which is what the first version
    did -- and it reports every byte-level rewrite as an undifferentiated
    "DRIFT".
    """
    name = tool.get("name", "?")
    now = digest_tool(tool)
    old_digest = pinned.get(name)
    if old_digest is None:
        return {"name": name, "status": "new", "digest": now[:12],
                "fields": [], "new_hits": []}
    if old_digest == now:
        return {"name": name, "status": "ok", "digest": now[:12], "new_hits": []}
    old = (snapshots or {}).get(name)
    if old is None:
        return {"name": name, "status": "DRIFT", "old": old_digest[:12],
                "new": now[:12], "fields": ["<unknown: no snapshot stored>"],
                "new_hits": []}
    detail = diff_tool(old, tool)
    out = {"name": name, "status": "DRIFT" if detail["fields"] else "changed",
           "old": old_digest[:12], "new": now[:12],
           "fields": detail["fields"],
           "new_hits": detail["new_hits"]}
    if detail["gone_hits"]:
        out["gone_hits"] = detail["gone_hits"]
    return out
