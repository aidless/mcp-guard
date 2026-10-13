"""Rulepack: families of poison patterns. Auditable, no ML."""
from __future__ import annotations

import re

RULES = [
    {
        "id": "imperative-tag",
        "severity": "high",
        "patterns": [r"<\s*(IMPORTANT|INSTRUCTION|SYSTEM|URGENT)[^>]*>"],
        "why": "伪装成系统指令的标签劫持（WhatsApp案原型）",
    },
    {
        "id": "secret-read",
        "severity": "high",
        "patterns": [
            r"~\s*/\s*\.ssh",
            r"read\s+.*(id_rsa|id_ed25519|\.pem)",
            r"(include|attach|send).{0,40}(chat\s*history|conversation\s*history)",
            r"mcp.*\.json",
        ],
        "why": "读取密钥/配置/聊天记录并外带",
    },
    {
        "id": "exfil-param",
        "severity": "medium",
        "patterns": [
            r"fill\s+\w*(context|session_id|metadata)\w*\s+with",
            r"use\s+(system\s*prompt|previous\s*tool\s*result|conversation).{0,30}param",
        ],
        "why": "诱导模型把敏感数据填进无害名参数",
    },
    {
        "id": "recipient-rewrite",
        "severity": "high",
        "patterns": [
            r"\bbcc\b",
            r"append\s+.{0,20}(recipient|address|copy)",
            r"redirect\s+.{0,20}(email|message)",
        ],
        "why": "改写收件人/静默抄送（postmark-mcp原型）",
    },
    {
        "id": "auth-url-exec",
        "severity": "high",
        "patterns": [
            r"shell\s*=\s*True",
            r"os\.system\s*\(",
            r"subprocess.*shell\s*=\s*True",
        ],
        "why": "工具参数直达shell（CVE-2025-6514模式）",
    },
]

_COMPILED = [(r["id"], r["severity"], [re.compile(p, re.I) for p in r["patterns"]], r["why"])
             for r in RULES]


def scan_text(text: str) -> list[dict]:
    hits = []
    for rid, sev, pats, why in _COMPILED:
        for p in pats:
            m = p.search(text or "")
            if m:
                hits.append({"rule": rid, "severity": sev,
                             "match": m.group(0)[:80], "why": why})
                break
    return hits
