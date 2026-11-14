"""SARIF 2.1.0 output for GitHub Code Scanning (P-SARIF).

Why this exists: our results were JSONL only, so the one consumer that actually
turns MCP findings into PR annotations — GitHub Code Scanning — could not read
them.  `mcpaudit` and `snyk-agent-scan` both emit SARIF; without it we can only
be run by hand, never in a CI gate that leaves a review comment.

Two things ride on the same file:

* **CWE mapping** — a security team cannot triage by our internal rule ids alone.
  Each rule carries `properties.tags` with the CWE id it corresponds to.
  Prompt-injection rules have **no standard CWE** (OWASP LLM01 is the closest
  thing and it is not a CWE); they say so explicitly rather than borrowing a
  number that would be wrong.
* **stable rule descriptors** — the `driver.rules` table lists every rule once,
  so GitHub can render a rule description instead of a bare id.

Severity mapping is deliberately blunt: `high` -> `error`, `medium` -> `warning`.
SARIF only has note/warning/error, and anything we flag is worth looking at.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from guard.rules import RULES  # noqa: E402

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

#: rule id -> CWE.  Verified against cwe.mitre.org/data/definitions/<n>.html on
#: 2026-11-14, titles quoted so a wrong number is visible on inspection:
#:   CWE-78  Improper Neutralization of Special Elements used in an OS Command
#:   CWE-88  Improper Neutralization of Argument Delimiters in a Command
#:   CWE-200 Exposure of Sensitive Information to an Unauthorized Actor
#:   CWE-201 Insertion of Sensitive Information Into Sent Data
CWE_MAP: dict[str, str] = {
    "auth-url-exec": "CWE-78",
    "param-pollution": "CWE-88",
    "secret-read": "CWE-200",
    "exfil-param": "CWE-201",
    "encoded-exfil": "CWE-201",
    "recipient-rewrite": "CWE-201",
}

#: Rules that describe prompt injection.  There is no CWE for it — OWASP LLM01 is
#: the industry reference point, and it is not a CWE entry.  Saying "no standard
#: CWE" is more useful than borrowing CWE-77 ("used in a Command"), which would be
#: a category error a reviewer would immediately distrust.
NO_CWE_NOTE = "prompt-injection class; no standard CWE (closest reference: OWASP LLM01)"

_SEVERITY_TO_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def cwe_for(rule_id: str) -> str | None:
    return CWE_MAP.get(rule_id)


def rule_descriptors(version: str) -> list[dict]:
    """One SARIF reportingDescriptor per rule, in pack order (stable output)."""
    out: list[dict] = []
    for rule in RULES:
        rid = rule["id"]
        cwe = cwe_for(rid)
        desc: dict = {
            "id": rid,
            "name": rid,
            "shortDescription": {"text": rule.get("why", rid)},
            "defaultConfiguration": {
                "level": _SEVERITY_TO_LEVEL.get(rule.get("severity", "medium"), "warning")
            },
            "properties": {"severity": rule.get("severity", "medium")},
        }
        if cwe:
            desc["properties"]["tags"] = [cwe, "security"]
            desc["properties"]["precision"] = "medium"
            desc["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"
        else:
            desc["properties"]["tags"] = ["security"]
            desc["properties"]["note"] = NO_CWE_NOTE
        out.append(desc)
    return out


def to_sarif(
    tool_results: list[dict],
    *,
    artifact_uri: str,
    version: str = "0.0.0",
) -> dict:
    """Build a SARIF log from `scan_tool`-shaped results.

    `tool_results` is the list the CLI already prints one-per-line: each entry has
    `name`, `flagged`, `hits`.  Every hit becomes one SARIF result, so a tool that
    trips three rules produces three results and GitHub shows three annotations.
    """
    results: list[dict] = []
    for tool in tool_results:
        name = tool.get("name", "?")
        for hit in tool.get("hits", []) or []:
            rid = hit.get("rule", "unknown")
            anchor = hit.get("anchor")
            level = _SEVERITY_TO_LEVEL.get(hit.get("severity", "high"), "warning")
            text = f"{name}: matched rule '{rid}'"
            if anchor:
                text += f" at anchor {anchor!r}"
            entry: dict = {
                "ruleId": rid,
                "level": level,
                "message": {"text": text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri},
                            # We scan a JSON document, not source lines, so there is
                            # no meaningful line to point at.  A region of line 1 is
                            # honest; inventing an offset would be worse.
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [{"name": name, "kind": "member"}],
                    }
                ],
                "properties": {"tool": name},
            }
            if hit.get("id") is not None:
                entry["partialFingerprints"] = {
                    "mcpGuardHit/v1": f"{name}:{rid}:{hit.get('id')}"
                }
            if anchor:
                entry["properties"]["anchor"] = anchor
            if hit.get("evidence"):
                entry["properties"]["evidence"] = hit["evidence"]
            results.append(entry)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-guard",
                        "informationUri": "https://github.com/aidless/mcp-guard",
                        "version": version,
                        "rules": rule_descriptors(version),
                    }
                },
                "results": results,
                "properties": {"artifact": artifact_uri},
            }
        ],
    }
