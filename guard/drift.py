"""Drift detection: compare a tool definition against a pinned snapshot.

A rug pull is not "the file changed" -- it is "the change the reviewer did not
see". So the diff answers two questions the raw sha256 cannot:

  1. WHICH part moved (name / description / schema), because a description edit
     is the known exfiltration vector (Microsoft 2026-06, MCPTox) while a
     schema-wide re-key is usually a client upgrade.
  2. Did the change ADD a rule hit, or swap WHAT an existing rule hit? That is
     the alarm-worthy case, and it is reported separately so a clean-but-
     different tool is not lumped in with one that newly tells the agent to
     read ~/.ssh.

2026-10-28: hit identity is now (rule id, matched text), not just the rule id.
Comparing rule ids alone missed the payload swap -- a rug pull that changes
"read ~/.ssh/id_rsa" into "read ~/.aws/credentials" fires the same rule id
(secret-read) before and after, so the old set-difference reported nothing.
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


def _norm_match(text: str) -> str:
    """归一化命中文本：压空白 + 小写。只用于比较，不回显给用户。"""
    return " ".join((text or "").split()).lower()


def _hit_map(hits: list[dict]) -> dict[tuple[str, str], str]:
    """命中身份 = (规则 id, anchor) -> 原始命中文本。

    anchor 由 `scan_text` 给出：规则作者标出的"这次打的是什么"那个词
    （`~/.aws` → `aws`，`read … id_rsa` → `id_rsa`）。没标 anchor 的规则，
    anchor 是整段命中文本的摘要。

    只比规则 id 会漏掉"载荷被换掉"；只比整段命中文本又会对纯措辞改动误报
    （`read the id_rsa` → `read your id_rsa`）。比 anchor 是两者的中间点。
    """
    out: dict[tuple[str, str], str] = {}
    for h in hits:
        key = (h["rule"], h.get("anchor") or _norm_match(h.get("match", "")))
        out.setdefault(key, h.get("match", ""))
    return out


def _empty_drift(status: str, fields: list[str]) -> dict:
    return {
        "status": status,
        "fields": fields,
        "new_hits": [],
        "changed_hits": [],
        "gone_hits": [],
        "hit_delta": [],
        "alarm": False,
    }


def diff_tool(old: dict, new: dict) -> dict:
    """Classify one tool's drift.

    Returns a dict with:
      status      : ok | changed | new
      fields      : which top-level fields moved
      new_hits    : rule ids that did not fire at all before (back-compat)
      changed_hits: rule ids that fired before AND after, but on different
                    matched text -- the payload-swap case the old id-diff missed
      gone_hits   : rule ids that no longer fire anywhere (informational)
      hit_delta   : per-(rule, matched text) added/removed detail, original text
      alarm       : True when anything was added, i.e. new_hits or changed_hits
    """
    if not old:
        return _empty_drift("new", changed_fields({}, new))
    fields = changed_fields(old, new)
    if not fields:
        return _empty_drift("ok", [])

    before = _hit_map(scan_text(_tool_text(old)))
    after = _hit_map(scan_text(_tool_text(new)))
    added = set(after) - set(before)
    removed = set(before) - set(after)
    rules_before = {r for r, _ in before}
    rules_after = {r for r, _ in after}

    new_hits = sorted(rules_after - rules_before)
    changed_hits = sorted({r for r, _ in added} & rules_before)
    gone_hits = sorted(rules_before - rules_after)
    hit_delta = (
        [{"rule": r, "change": "added", "anchor": a, "match": after[(r, a)]}
         for (r, a) in sorted(added)]
        + [{"rule": r, "change": "removed", "anchor": a, "match": before[(r, a)]}
           for (r, a) in sorted(removed)]
    )
    return {
        "status": "changed",
        "fields": fields,
        "new_hits": new_hits,
        "changed_hits": changed_hits,
        "gone_hits": gone_hits,
        "hit_delta": hit_delta,
        "alarm": bool(new_hits or changed_hits),
    }


def _tool_text(tool: dict) -> str:
    parts = [tool.get("name", ""), tool.get("description", "")]
    schema = tool.get("inputSchema") or tool.get("parameters") or {}
    parts.append(json.dumps(schema, ensure_ascii=False))
    return "\n".join(parts)


def check_drift(tool: dict, pinned: dict[str, str],
                snapshots: dict[str, dict] | None = None) -> dict:
    """Drift check that reports WHERE it moved and whether the hits changed.

    `snapshots` holds the full previous tool objects (not just digests). Without
    it only the digest comparison is possible, which is what the first version
    did -- and it reports every byte-level rewrite as an undifferentiated
    "DRIFT".

    `alarm` is True when the change ADDED a hit or swapped what an existing hit
    matched. It is None when we cannot tell (digest changed but no snapshot was
    stored) -- unknown is not the same as clean.
    """
    name = tool.get("name", "?")
    now = digest_tool(tool)
    old_digest = pinned.get(name)
    if old_digest is None:
        out = _empty_drift("new", [])
        out.update({"name": name, "digest": now[:12]})
        return out
    if old_digest == now:
        out = _empty_drift("ok", [])
        out.update({"name": name, "digest": now[:12]})
        return out
    old = (snapshots or {}).get(name)
    if old is None:
        out = _empty_drift("DRIFT", ["<unknown: no snapshot stored>"])
        out.update({"name": name, "old": old_digest[:12], "new": now[:12],
                    "alarm": None})
        return out
    detail = diff_tool(old, tool)
    out = {
        "name": name,
        "status": "DRIFT" if detail["fields"] else "changed",
        "old": old_digest[:12],
        "new": now[:12],
        "fields": detail["fields"],
        "new_hits": detail["new_hits"],
        "changed_hits": detail["changed_hits"],
        "hit_delta": detail["hit_delta"],
        "alarm": detail["alarm"],
    }
    if detail["gone_hits"]:
        out["gone_hits"] = detail["gone_hits"]
    return out
