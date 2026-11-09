"""Capability rules: what a tool can DO, independent of whether it is poisoned.

The poison rulepack in `guard/rules.py` answers "does this description try to
manipulate the model". It says nothing about a perfectly honest tool that can
terminate processes, launch arbitrary programs, or run an opaque batch. This
module adds that second axis.

Design constraints, matching the rest of the repository:

* deterministic and offline: regex over name/description/schema, no model call;
* auditable: every tier comes from a named rule, and the rule is reported;
* honest about absence: a tool that matches no rule is `unknown`, never
  silently promoted to read-only;
* conservative: capability hits are not a verdict, only a review signal.

Tiers are ordered. The tier of a tool is the highest tier among its hits.
"""
from __future__ import annotations

import json
import re

T0_READ = "T0_read"
T1_LOCAL = "T1_local"
T2_MUTATE = "T2_mutate"
T3_DESTRUCTIVE = "T3_destructive_or_exec"
TIER_ORDER = (T0_READ, T1_LOCAL, T2_MUTATE, T3_DESTRUCTIVE)
TIER_RANK = {tier: index for index, tier in enumerate(TIER_ORDER)}

# A description that only *checks* state is read-only even though it contains
# words like "check" or "focused". Applied before the verb rules: a positive
# read phrase wins over a stray mutating-looking word in the same sentence.
READ_PHRASES = ("check element state", "check nested permission states",
                "list ", "get ", "print ", "show ", "capture ", "read plain-text",
                "query ", "inspect ", "describe ", "fetch ", "status",
                "permission", "version", "skills")

# Explicit command-name overrides. These are not "inferred" from prose: they
# are the documented effects of common CLI-shaped MCP tools. A reviewer can
# dispute one line without reading the regex engine.
NAME_TIERS = {
    "clear": T2_MUTATE,
    "expand": T2_MUTATE,
    "collapse": T2_MUTATE,
    "select": T2_MUTATE,
    "start": T1_LOCAL,
    "end": T1_LOCAL,
    "gc": T1_LOCAL,
    "list": T0_READ,
    "show": T0_READ,
    "export": T0_READ,
    "enable": T1_LOCAL,
    "disable": T1_LOCAL,
    "delete": T3_DESTRUCTIVE,
    "terminate": T3_DESTRUCTIVE,
    "kill": T3_DESTRUCTIVE,
    "wipe": T3_DESTRUCTIVE,
    "format": T3_DESTRUCTIVE,
    "drop": T3_DESTRUCTIVE,
}

# Documented CLI-shaped commands whose prose contains a generic mutating verb
# but whose effect is window/session state, not application content.
LOCAL_STATE_TOKENS = (
    "window", "session", "trace", "clipboard", "notification", "overlay", "directory",
    "surface", "cursor", "system surface", "shell surface",
)

# A read phrase suppresses the generic mutating rule, but only when the
# description does not also advertise a concrete state change.
LOCAL_STATE_VERBS = (
    "start", "end", "create", "delete", "remove", "gc", "enable", "disable",
    "focus", "move", "resize", "minimize", "maximize", "restore", "export",
    "save", "merge", "open", "raise", "bring",
)

# Strong, unambiguous signals that the tool only observes. These override a
# generic "create/export/merge" word that would otherwise promote it to T1.
STRONG_READ_TOKENS = (
    "list ", "get ", "read ", "print ", "show ", "status", "version",
    "skills path", "check element state", "check nested permission",
    "merge session trace", "export a self-contained",
)

# Parameter names that turn an ordinary tool into an execution or bypass
# surface. Kept explicit so a reviewer can argue about the list, not the code.
DANGEROUS_PARAMS = {
    "no_confirm": ("skips confirmation", T3_DESTRUCTIVE),
    "skip_confirm": ("skips confirmation", T3_DESTRUCTIVE),
    "assume_yes": ("answers confirmation prompts automatically", T3_DESTRUCTIVE),
    "argv": ("passes arguments to a launched process", T3_DESTRUCTIVE),
    "cmd": ("names a command to run", T3_DESTRUCTIVE),
    "shell": ("requests a shell", T3_DESTRUCTIVE),
    "script": ("supplies executable script text", T3_DESTRUCTIVE),
    "env": ("controls the launched process environment", T3_DESTRUCTIVE),
    "cwd": ("controls the launched process working directory", T3_DESTRUCTIVE),
    "args": ("passes arguments to a launched process", T2_MUTATE),
    "force": ("bypasses a refusal or confirmation", T2_MUTATE),
    "hard": ("bypasses a refusal or confirmation", T2_MUTATE),
    "command": ("names a command to run", T2_MUTATE),
    "commands_json": ("carries an opaque command list", T2_MUTATE),
    "commands": ("carries an opaque command list", T2_MUTATE),
    "steps": ("carries an opaque step list", T2_MUTATE),
    "payload": ("carries an opaque payload", T2_MUTATE),
}

CAPABILITY_RULES = [
    {
        "id": "destructive-verb",
        "tier": T3_DESTRUCTIVE,
        "severity": "high",
        "patterns": [
            r"\b(?P<anchor>delete|destroy|wipe|purge|erase|uninstall|kill|terminate|"
            r"factory[\s_-]?reset|format\s+(?:disk|drive)|drop\s+(?:table|database))\b",
        ],
        "why": "name/description advertises an irreversible destruction",
    },
    {
        "id": "close-or-shutdown",
        "tier": T3_DESTRUCTIVE,
        "severity": "high",
        "patterns": [
            r"\b(?P<anchor>close|quit|exit|shutdown|shut\s+down|reboot|log\s*out)\b"
            r".{0,40}\b(app|application|process|program|window|system|machine|session)\b",
            r"\b(?P<anchor>close_app|quit_app|kill_app|terminate_app)\b",
        ],
        "why": "can end a process or session; unsaved work may be lost",
    },
    {
        "id": "exec-or-launch",
        "tier": T3_DESTRUCTIVE,
        "severity": "high",
        "patterns": [
            r"\b(?P<anchor>launch|spawn|execute|exec)\b",
            r"\b(?:run|start)\s+(?:a\s+)?(?P<anchor>command|script|program|programme|"
            r"binary|executable|shell|process)\b",
            r"\b(?P<anchor>shell\s*=\s*true|os\.system|subprocess)\b",
            r"\b(?P<anchor>sh\s+-c|bash\s+-c|zsh\s+-c|cmd\s+/c|powershell\s+-c|"
            r"/bin/(?:ba|z)?sh)\b",
        ],
        "why": "can start arbitrary code, not just manipulate an existing UI",
    },
    {
        "id": "bulk-clear",
        "tier": T3_DESTRUCTIVE,
        "severity": "high",
        "patterns": [
            r"\b(?P<anchor>dismiss|clear|delete|remove|purge)\w*\s+all\b",
            r"\bclear\s+(?:the\s+)?(?P<anchor>clipboard|history|log|queue|cache|"
            r"buffer|workspace|session|data|state)\b",
        ],
        "why": "bulk removal is harder to undo than a single-item action",
    },
    {
        "id": "single-clear",
        "tier": T2_MUTATE,
        "severity": "medium",
        "patterns": [
            r"\b(?P<anchor>clear|dismiss)\b.{0,40}\b(element|value|field|notification|"
            r"clipboard|item|entry|dialog|alert|text)\b",
        ],
        "why": "clears one value or UI element; reversible in most apps",
    },
    {
        "id": "mutating-verb",
        "tier": T2_MUTATE,
        "severity": "medium",
        "patterns": [
            r"\b(?P<anchor>set|write|update|create|insert|add|post|send|upload|move|"
            r"copy|rename|edit|patch|apply|click|type|press|drag|scroll|toggle|"
            r"check|select|focus|paste|truncate|reset)\b",
            r"\b(?P<anchor>change|modify|alter|replace|submit|confirm|accept)\b",
        ],
        "why": "changes application or shared state",
    },
    {
        "id": "opaque-payload",
        "tier": T2_MUTATE,
        "severity": "medium",
        "patterns": [
            r"\b(?P<anchor>batch|pipeline|workflow|sequence\s+of\s+(?:commands|steps))\b",
        ],
        "why": "one call can execute many inner actions that this schema does not show",
    },
    {
        "id": "local-state",
        "tier": T1_LOCAL,
        "severity": "low",
        "patterns": [
            r"\b(?P<anchor>resize|minimize|maximize|restore|arrange|save)\b",
            r"\b(?:create|start|end|delete|gc)\s+(?:a\s+)?(?P<anchor>session)\b",
            r"\b(?P<anchor>session)\s+(?:list|manifest|trace|directory)\b",
            r"\b(?:open|raise)\s+(?:a\s+)?(?P<anchor>system\s+surface|shell\s+surface)\b",
            r"\b(?P<anchor>bring\s+a\s+window\s+to\s+front|bring\s+window\s+to\s+front)\b",
        ],
        "why": "writes local UI/session/artifact state but not application content",
    },
    {
        "id": "read-verb",
        "tier": T0_READ,
        "severity": "low",
        "patterns": [
            r"\b(?P<anchor>get|list|read|snapshot|find|search|query|status|inspect|"
            r"describe|show|fetch|screenshot|capture|wait|watch|version|permissions|"
            r"print|check|merge|export)\b",
        ],
        "why": "observes without an advertised mutation",
    },
]

_COMPILED = [
    (r["id"], r["tier"], r["severity"], [re.compile(p, re.I) for p in r["patterns"]], r["why"])
    for r in CAPABILITY_RULES
]

# Keys whose string value may contain a JSON list of inner commands. Batch
# unwrapping is recursive but bounded: a tool that nests deeper than this is
# reported as opaque instead of exhaustively parsed.
BATCH_KEYS = ("commands_json", "commands", "steps", "pipeline", "batch")
MAX_BATCH_DEPTH = 3
MAX_BATCH_ENTRIES = 64


def _text(tool: dict) -> str:
    # Verb rules read only name/description. Scanning the raw JSON schema would
    # match the ubiquitous "type" key on every tool and manufacture a mutation
    # hit. Parameter risk is handled separately by _param_hits.
    return "\n".join([
        str(tool.get("name", "")),
        str(tool.get("description", "")),
    ])


def _tier_max(tiers: list[str]) -> str:
    known = [tier for tier in tiers if tier in TIER_RANK]
    if not known:
        return "unknown"
    return max(known, key=lambda tier: TIER_RANK[tier])


def _earliest_read_position(description: str) -> int | None:
    """Index of the earliest READ_PHRASE in the description, if any."""
    positions = [
        description.find(phrase)
        for phrase in READ_PHRASES
        if phrase.rstrip() and description.find(phrase.rstrip()) >= 0
    ]
    return min(positions) if positions else None


def _earliest_mutating_position(description: str) -> int | None:
    """Index of the earliest mutating-verb match, if any.

    Positions, not matched text: the question is which intent comes first
    in the prose, not which words matched.
    """
    rule = next(r for r in CAPABILITY_RULES if r["id"] == "mutating-verb")
    positions = []
    for pattern in rule["patterns"]:
        for match in re.finditer(pattern, description, re.I):
            positions.append(match.start())
    return min(positions) if positions else None


def _hits(tool: dict) -> list[dict]:
    name = str(tool.get("name", "")).lower()
    description = str(tool.get("description", "")).lower()
    text = _text(tool)
    hits = []
    for rid, tier, severity, patterns, why in _COMPILED:
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                hits.append({
                    "rule": rid,
                    "tier": tier,
                    "severity": severity,
                    "match": match.group(0)[:80],
                    "why": why,
                })
                break
    # Strip false mutating-verb hits when the description is explicitly a read.
    if any(phrase in description for phrase in READ_PHRASES):
        # Explicit destructive/exec evidence still wins; only the generic
        # mutating-verb rule is suppressed by a read phrase. A read tool that
        # also says "create/export/merge" writes a local artifact instead,
        # unless its leading phrase is an unambiguous observation.
        if not any(h["tier"] == T3_DESTRUCTIVE for h in hits):
            strong_read = any(token in description for token in STRONG_READ_TOKENS)
            local_change = (
                any(verb in description for verb in LOCAL_STATE_VERBS)
                and any(token in description for token in LOCAL_STATE_TOKENS)
                and not strong_read
            )
            if local_change:
                hits = [
                    h for h in hits
                    if h["rule"] not in ("mutating-verb", "local-state")
                ]
                hits.append({
                    "rule": "local-state-phrase",
                    "tier": T1_LOCAL,
                    "severity": "low",
                    "match": description[:80],
                    "why": "writes a local window/session/artifact",
                })
            else:
                # Suppress to read-verb only when the read intent comes *first*.
                # The description's earliest action word is its primary effect;
                # a mid-sentence "show a receipt" / "the status of" /
                # "version-controlled permissions" must not mute a leading
                # "Send" / "Update" / "Move" / "Set". Ties go to the read phrase,
                # because UI verbs like "check" are themselves the read phrase
                # ("check element state") and describe the same action.
                mutating_at = _earliest_mutating_position(description)
                read_at = _earliest_read_position(description)
                if read_at is not None and (mutating_at is None or read_at <= mutating_at):
                    hits = [h for h in hits if h["rule"] == "read-verb"]

    # A concrete window operation is local state even when its verb is
    # "focus" or "move" and the generic verb rule called it a mutation.
    if any(token in description for token in ("window", "system surface", "shell surface")) \
            and any(verb in description for verb in ("focus", "move", "resize",
                                                    "minimize", "maximize", "restore",
                                                    "open", "raise", "bring")):
        if not any(h["tier"] == T3_DESTRUCTIVE for h in hits):
            hits = [h for h in hits if h["rule"] != "mutating-verb"]
            hits.append({
                "rule": "window-state-phrase",
                "tier": T1_LOCAL,
                "severity": "low",
                "match": description[:80],
                "why": "changes window/shell surface state, not application content",
            })

    # Session start creates a local manifest; the generic "create" verb would
    # otherwise call it an application mutation.
    if "session" in description and any(
            verb in description for verb in ("start", "create", "end", "gc")):
        if not any(h["tier"] == T3_DESTRUCTIVE for h in hits):
            hits = [h for h in hits if h["rule"] != "mutating-verb"]
            hits = [h for h in hits if h["rule"] != "name-override"]
            hits.append({
                "rule": "session-state",
                "tier": T1_LOCAL,
                "severity": "low",
                "match": description[:80],
                "why": "creates or ends a local session",
            })

    # A trace viewer is an observation artifact, not an application write.
    if "trace" in description and any(
            verb in description for verb in ("show", "export", "merge")):
        hits = [
            h for h in hits
            if h["rule"] not in ("mutating-verb", "local-state", "name-override")
        ]
        hits.append({
            "rule": "trace-artifact",
            "tier": T0_READ,
            "severity": "low",
            "match": description[:80],
            "why": "produces a read-only observation artifact",
        })
    for suffix, tier in NAME_TIERS.items():
        if (name == suffix or name.endswith("_" + suffix)
                or name.startswith(suffix + "_")):
            hits.append({
                "rule": "name-override",
                "tier": tier,
                "severity": "high" if tier == T3_DESTRUCTIVE else "medium",
                "match": name,
                "why": "documented effect of this command name",
            })
            break
    return hits


def _enum_tier(prop, depth: int):
    """Max capability tier over a closed enum's values.

    A string enum is the only place a schema can prove what values a param
    admits; scanning the values turns "command" from a name-level guess into
    a value-level fact. Returns None when the prop is not a clean non-empty
    all-string enum (caller falls back to the static tier)."""
    if not isinstance(prop, dict):
        return None
    values = prop.get("enum")
    if not isinstance(values, list) or not values:
        return None
    if not all(isinstance(v, str) for v in values):
        return None
    tiers = []
    for value in values:
        synthetic = {
            "name": value,
            "description": value,
            "inputSchema": {"type": "object", "properties": {}},
        }
        inner = scan_capability(synthetic, depth + 1)
        tiers.append(inner["tier"])
    known = [t for t in tiers if t in TIER_RANK]
    if not known:
        return "unknown"
    return max(known, key=lambda t: TIER_RANK[t])


def _param_hits(tool: dict, depth: int = 0) -> list[dict]:
    schema = tool.get("inputSchema") or tool.get("parameters") or {}
    props = schema.get("properties") or {}
    hits = []
    for name, (why, tier) in DANGEROUS_PARAMS.items():
        if name not in props:
            continue
        prop = props[name]
        enum_tier = _enum_tier(prop, depth)
        hit_tier = tier
        if enum_tier is not None and enum_tier != "unknown":
            if TIER_RANK[enum_tier] < TIER_RANK[tier]:
                hit_tier = enum_tier  # closed enum proves the param is tamer than its name
            else:
                hit_tier = max(tier, enum_tier, key=lambda t: TIER_RANK[t])
        hits.append({
            "rule": "dangerous-param",
            "tier": hit_tier,
            "severity": "high" if hit_tier == T3_DESTRUCTIVE else "medium",
            "match": name,
            "why": why,
            **({"enum_tier": enum_tier} if enum_tier is not None else {}),
        })
    return hits


def _inner_tool(name: str, args) -> dict:
    props = {}
    if isinstance(args, dict):
        props = {key: {"type": "string"} for key in args}
    return {
        "name": str(name),
        "description": "",
        "inputSchema": {"type": "object", "properties": props},
    }


def _unwrap_value(value, depth: int) -> list[dict]:
    """Return inner capability results for a decoded batch payload."""
    if depth >= MAX_BATCH_DEPTH:
        return [{
            "name": "<batch-depth-limit>",
            "tier": "unknown",
            "hits": [],
            "batch": [],
            "opaque": True,
        }]
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return []
    if isinstance(value, dict):
        value = value.get("commands") or value.get("steps") or [value]
    if not isinstance(value, list):
        return []
    results = []
    for entry in value[:MAX_BATCH_ENTRIES]:
        if not isinstance(entry, dict):
            continue
        name = entry.get("command") or entry.get("tool") or entry.get("name") or entry.get("action")
        if not name:
            continue
        args = entry.get("args") or entry.get("arguments") or entry.get("params") or entry.get("input")
        inner = scan_capability(_inner_tool(name, args), depth + 1)
        results.append(inner)
    return results


def batch_hits(tool: dict, depth: int = 0) -> list[dict]:
    schema = tool.get("inputSchema") or tool.get("parameters") or {}
    props = schema.get("properties") or {}
    reports = []
    for key in BATCH_KEYS:
        if key not in props:
            continue
        value = props[key]
        # The schema may describe a string payload; there is no runtime value
        # to parse at scan time, so any declared opaque payload is a review
        # signal by itself.
        default = value.get("default") if isinstance(value, dict) else None
        inner = _unwrap_value(default, depth) if default is not None else []
        reports.append({
            "param": key,
            "status": "unwrapped" if inner else "opaque",
            "inner": inner,
        })
    return reports


def unwrap_payload(value) -> list[dict]:
    """Classify a decoded batch payload (list of {command,args} entries).

    Exposed so a live proxy can reuse the same unwrapping on an actual
    tools/call argument, not only on a schema default.
    """
    return _unwrap_value(value, 0)


def scan_capability(tool: dict, depth: int = 0) -> dict:
    """Classify one tool. Never raises on a missing schema."""
    hits = _hits(tool) + _param_hits(tool, depth)
    batches = batch_hits(tool, depth)
    inner_tiers = [
        item["tier"]
        for report in batches
        for item in report["inner"]
    ]
    tiers = [hit["tier"] for hit in hits] + inner_tiers
    return {
        "name": tool.get("name", "?"),
        "tier": _tier_max(tiers),
        "hits": hits,
        "batch": batches,
        "unknown": not tiers,
    }


def summarise(results: list[dict]) -> dict:
    counts = {tier: 0 for tier in TIER_ORDER}
    counts["unknown"] = 0
    for result in results:
        counts[result["tier"]] = counts.get(result["tier"], 0) + 1
    return {
        "total": len(results),
        "tiers": counts,
        "destructive": [
            result["name"] for result in results if result["tier"] == T3_DESTRUCTIVE
        ],
    }


def tier_mismatches(tools: list[dict], results: list[dict]) -> list[dict]:
    """Tools whose annotations *explicitly contradict* the capability tier.

    A lie (readOnlyHint=true on a T2/T3 tool, destructiveHint=false on a T3
    tool) is different from silence (no annotations at all): silence is
    --require-annotations' business; lies are --block-tier-mismatch's.
    """
    by_name = {result["name"]: result for result in results}
    out = []
    for tool in tools:
        annotations = tool.get("annotations")
        if not isinstance(annotations, dict):
            continue  # silence, not a lie
        tier = by_name.get(tool.get("name", "?"), {}).get("tier", "unknown")
        reasons = []
        if annotations.get("readOnlyHint") is True and tier in (T2_MUTATE, T3_DESTRUCTIVE):
            reasons.append(f"readOnlyHint-true-but-{tier}")
        if annotations.get("destructiveHint") is False and tier == T3_DESTRUCTIVE:
            reasons.append("destructiveHint-false-but-destructive")
        if reasons:
            out.append({"name": tool.get("name", "?"), "tier": tier, "reasons": reasons})
    return out


def annotation_violations(tools: list[dict], results: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return (violations, warnings) for the strict annotation gate.

    Violations are tools that can mutate or destroy but do not *explicitly*
    declare it. Warnings are observable/local tools with no annotations; they
    do not fail the gate because the blast radius is smaller.
    """
    by_name = {result["name"]: result for result in results}
    violations = []
    warnings = []
    for tool in tools:
        name = tool.get("name", "?")
        tier = by_name.get(name, {}).get("tier", "unknown")
        annotations = tool.get("annotations")
        if not isinstance(annotations, dict) or not annotations:
            entry = {"name": name, "tier": tier, "reason": "missing-annotations"}
            if tier in (T2_MUTATE, T3_DESTRUCTIVE, "unknown"):
                violations.append(entry)
            else:
                warnings.append(entry)
            continue
        read_only = annotations.get("readOnlyHint")
        destructive = annotations.get("destructiveHint")
        if tier == T0_READ:
            if read_only is not True:
                violations.append({
                    "name": name, "tier": tier,
                    "reason": "read-only-without-readOnlyHint",
                })
        elif tier == T1_LOCAL:
            if read_only is not False:
                violations.append({
                    "name": name, "tier": tier,
                    "reason": "local-write-claims-read-only",
                })
        elif tier in (T2_MUTATE, T3_DESTRUCTIVE):
            if read_only is not False:
                violations.append({
                    "name": name, "tier": tier,
                    "reason": "mutating-claims-read-only",
                })
            if destructive is not True and tier == T3_DESTRUCTIVE:
                violations.append({
                    "name": name, "tier": tier,
                    "reason": "destructive-without-destructiveHint",
                })
    return violations, warnings
