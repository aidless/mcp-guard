"""Scan a tool definition + pin its hash (rug-pull detection)."""
from __future__ import annotations

import hashlib
import json

from .rules import scan_text


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


def check_drift(tool: dict, pinned: dict[str, str]) -> dict:
    name = tool.get("name", "?")
    now = digest_tool(tool)
    old = pinned.get(name)
    if old is None:
        return {"name": name, "status": "new", "digest": now}
    if old != now:
        return {"name": name, "status": "DRIFT", "old": old[:12], "new": now[:12]}
    return {"name": name, "status": "ok", "digest": now[:12]}
