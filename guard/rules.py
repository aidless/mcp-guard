"""Rulepack: families of poison patterns. Auditable, no ML.

每条 pattern 可以用 `(?P<anchor>...)` 标出"最能把这次命中和别次区分开"的那个词
（`~/.aws` 里的 `aws`、`read .* id_rsa` 里的 `id_rsa`）。漂移检测比的是 anchor，
不是整段命中文本——否则 `read the id_rsa` → `read your id_rsa` 这种纯措辞改动
会被误判成"载荷被换掉了"。
没标 anchor 的 pattern 回退成整段命中文本的 sha256 前 16 位，因此也不受
`match` 截断到 80 字符的影响。
"""
from __future__ import annotations

import hashlib
import re

# encoded-exfil 的三段片段：敏感材料 / 编码动作 / 外带动作。
# 单独成片段是为了同时覆盖两种真实语序（先提密再编码、先编码再提密）。
_SENS_FRAG = (r"(?P<anchor>ssh|\.ssh|id_rsa|id_ed25519|private[\s_-]*key"
              r"|\w*[\s_-]*(?:secret|token|password|credential)s?\b)")
_ENC_FRAG = (r"(?:base64|b64|rot13|hex)[\s_-]?encod\w*"
             r"|xor[\s_-]*(?:encrypt\w*|obfuscat\w*|mask\w*)"
             r"|caesar[\s_-]*(?:shift\w*|cipher)"
             r"|char(?:acter)?[\s_-]*code[\s_-]*offset"
             r"|offset[\s\S]{0,12}?of[\s\S]{0,8}?\d"
             r"|shift[\s_-]+(?:each|every)[\s\S]{0,24}?(?:char|byte)")
_EXFIL_FRAG = r"(include|attach|send|upload|post|place|put|exfiltrat|param)"

RULES = [
    {
        "id": "imperative-tag",
        "severity": "high",
        "patterns": [r"<\s*(?P<anchor>IMPORTANT|INSTRUCTION|SYSTEM|URGENT)[^>]*>"],
        "why": "伪装成系统指令的标签劫持（WhatsApp案原型）",
    },
    {
        "id": "secret-read",
        "severity": "high",
        "patterns": [
            r"~\s*/\s*\.(?P<anchor>ssh|aws|gnupg|kube|docker|azure)",
            r"read\s+.*(?P<anchor>id_rsa|id_ed25519|\.pem)",
            r"(?:include|attach|send).{0,40}(?P<anchor>chat\s*history|conversation\s*history)",
            r"(?P<anchor>mcp).*\.json",
            # 2026-10-28 新增：常见的云/容器凭据路径。原先只覆盖 ~/.ssh，
            # 于是"把攻击换成读 ~/.aws/credentials"的 rug pull 不会产生 new_hits。
            r"~\s*/\s*\.config\s*/\s*(?P<anchor>gcloud)",
            r"(?P<anchor>\.netrc)\b",
            r"\b(?P<anchor>aws|gcloud|azure|kube)[\s_-]?credentials\b",
        ],
        "why": "读取密钥/配置/聊天记录并外带",
    },
    {
        "id": "exfil-param",
        "severity": "medium",
        "patterns": [
            r"fill\s+\w*(?P<anchor>context|session_id|metadata)\w*\s+with",
            r"use\s+(?P<anchor>system\s*prompt|previous\s*tool\s*result|conversation)"
            r".{0,30}param",
            # 同义改写家族（自进化闭环抓出的 confirmed miss）：populate/fill/copy
            # 语义等价、词面不同。三条分别覆盖：
            #   - populate ... with（冠词可省，锚点=敏感参数名）
            #   - copy ... into <敏感参数>（收窄避免 "copy a file into a dir" 误伤）
            #   - fill/populate/copy ... <敏感参数> ... param(eter)（补 summarize
            #     的 "fill the session_id param"：原 use 规则要求 system prompt 与
            #     param 相邻 30 字符内，实际隔了 50 字符）
            r"populate\s+(the\s+)?\w*(?P<anchor>context|session_id|metadata)\w*\b.{0,40}?\s+with\b",
            r"copy\b.{0,80}?into\s+(the\s+)?(?P<anchor>context|session_id|metadata)\b",
            r"(?P<anchor>fill|populate|copy)\s+(the\s+)?\w*(context|session_id|metadata)\w*\b.{0,20}?\s+param",
        ],
        "why": "诱导模型把敏感数据填进无害名参数",
    },
    {
        "id": "recipient-rewrite",
        "severity": "high",
        "patterns": [
            r"\b(?P<anchor>bcc)\b",
            r"append\s+.{0,20}(?P<anchor>recipient|address|copy)",
            r"redirect\s+.{0,20}(?P<anchor>email|message)",
            # 间接抄送（自进化闭环抓出的 confirmed miss）：换掉 bcc/append/redirect 词面。
            r"hidden\s+(?P<anchor>copy|recipient|address|bcc)",
        ],
        "why": "改写收件人/静默抄送（postmark-mcp原型）",
    },
    {
        "id": "auth-url-exec",
        "severity": "high",
        "patterns": [
            r"(?P<anchor>shell\s*=\s*True)",
            r"(?P<anchor>os\.system)\s*\(",
            r"(?:subprocess).*(?P<anchor>shell\s*=\s*True)",
        ],
        "why": "工具参数直达shell（CVE-2025-6514模式）",
    },
    {
        "id": "encoded-exfil",
        "severity": "high",
        # 编码对抗改写：明文规则看不到"先编码再外带"。
        # 三段必须同现——敏感材料 / 编码动作 / 外带动作；
        # 缺任何一段都不报，避免"生成 SSH 公钥并 base64 编码"这类正常工具被误伤。
        # 两种真实语序都收：先提密再编码（sens→enc→exfil）与
        # 先编码再提密（enc→sens→exfil，如 "xor-encrypt the stored api_token and upload"）。
        # 编码动作覆盖 base64/hex/rot13 编码词与 XOR/Caesar/逐字节偏移改写。
        "patterns": [
            _SENS_FRAG
            + r"[\s\S]{0,80}?(" + _ENC_FRAG + r")"
            + r"[\s\S]{0,160}?" + _EXFIL_FRAG,
            "(" + _ENC_FRAG + r")"
            + r"[\s\S]{0,80}?" + _SENS_FRAG
            + r"[\s\S]{0,160}?" + _EXFIL_FRAG,
        ],
        "why": "敏感材料先编码再外带（编码对抗改写，明文规则看不见这一层）",
    },
]

_COMPILED = [(r["id"], r["severity"], [re.compile(p, re.I) for p in r["patterns"]], r["why"])
             for r in RULES]


def scan_text(text: str) -> list[dict]:
    """返回命中列表；每条带一个 `anchor`（可比、不受 80 字符截断影响）。"""
    hits = []
    for rid, sev, pats, why in _COMPILED:
        for p in pats:
            m = p.search(text or "")
            if m:
                anchor = m.groupdict().get("anchor")
                if anchor:
                    anchor = _norm(anchor)
                else:
                    digest = hashlib.sha256(
                        _norm(m.group(0)).encode()).hexdigest()[:16]
                    anchor = f"sha256:{digest}"
                hits.append({"rule": rid, "severity": sev,
                             "match": m.group(0)[:80], "anchor": anchor, "why": why})
                break
    return hits


def _norm(text: str) -> str:
    return " ".join((text or "").split()).lower()
