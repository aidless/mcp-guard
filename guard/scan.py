"""Scan a tool definition + pin its hash (rug-pull detection)."""
from __future__ import annotations

import hashlib
import json

from .rules import scan_text
from . import drift as _drift

# Field-level drift check lives in guard/drift.py; re-exported here so existing
# callers (run_eval.py, older pinned consumers) keep importing from one place.
check_drift = _drift.check_drift
diff_tool = _drift.diff_tool
changed_fields = _drift.changed_fields


def tool_text(tool: dict) -> str:
    parts = [tool.get("name", ""), tool.get("description", "")]
    schema = tool.get("inputSchema") or tool.get("parameters") or {}
    parts.append(json.dumps(schema, ensure_ascii=False))
    return "\n".join(parts)


def scan_tool(tool: dict) -> dict:
    hits = scan_text(tool_text(tool))
    return {"name": tool.get("name", "?"), "flagged": bool(hits), "hits": hits}


def digest_tool(tool: dict) -> str:
    canon = json.dumps(tool, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canon.encode()).hexdigest()
