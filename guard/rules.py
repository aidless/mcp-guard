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
            # 2026-10-28 新增：常见的云/容器凭据路径。原先只覆盖 ~/.ssh，
            # 于是"把攻击换成读 ~/.aws/credentials"的 rug pull 不会产生 new_hits。
            r"~\s*/\s*\.(aws|gnupg|kube|docker|azure)",
            r"~\s*/\s*\.config\s*/\s*gcloud",
            r"\.netrc\b",
            r"\b(aws|gcloud|azure|kube)[\s_-]?credentials\b",
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
    {
        "id": "encoded-exfil",
        "severity": "high",
        # 编码对抗改写：明文规则看不到"先编码再外带"。
        # 三段必须同现——敏感材料 → 编码动作 → 外带/落参动作；
        # 缺任何一段都不报，避免"生成 SSH 公钥并 base64 编码"这类正常工具被误伤。
        "patterns": [
            r"(ssh|\.ssh|id_rsa|id_ed25519|private[\s_-]*key|secret|token|password|credential)"
            r"[\s\S]{0,80}?(base64|b64|rot13|hex)[\s_-]?encod\w*"
            r"[\s\S]{0,160}?(include|attach|send|upload|post|place|put|exfiltrat|param)",
        ],
        "why": "敏感材料先编码再外带（编码对抗改写，明文规则看不见这一层）",
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
