# mcp-guard：MCP 工具定义投毒的离线规则扫描与版本钉选

> 本文档是 mcp-guard 的**论文摘要草稿**，内容全部来自仓库真实实现与真实评测结果，
> 无虚构数字。用于说明该仓库的研究价值与定位。

## 摘要（Abstract）

MCP（Model Context Protocol）工具定义是自然语言，LLM 把它当指令执行，因此攻击载荷
位于**语义层**——传统依赖扫描（pip-audit、lockfile 校验）看不见。已有实证工作
（MCPTox，2025-08：45 个真实 MCP 服务 × 20 个模型，投毒成功率最高 72.8%；
postmark-mcp 1.0.16 静默 BCC；Microsoft 2026-06；OWASP Agentic Top 10，2025-12）
证明该攻击面真实存在，但**缺少一个离线、确定性、零模型调用的防御工具**。

本文提出 **mcp-guard**：一个在工具定义（name / description / parameter schema）层面
做投毒检测的扫描器，配 sha256 钉选与字段级漂移检测。它有三个设计要点：

1. **离线且零模型调用**：规则包、扫描、钉选、漂移检测全部只用标准库（
   `dependencies = []`），无任何 LLM 调用，因此可复算、可进 CI 门禁。
2. **命中身份 = 敏感锚点**：漂移检测比较的不是整段命中文本，而是规则用
   `(?P<anchor>...)` 标出的"这次打的是什么"那个词——实测证明这能把"纯措辞改动"
   （`read the id_rsa` → `read your id_rsa`，`alarm=False`）与"换载荷攻击"
   （`~/.ssh/id_rsa` → `~/.aws/credentials`，`alarm=True`）分开。
3. **覆盖边界可被精确说出**：新增对抗改写用例（同义/分词破短语/间接指令）让
   `recall_case` 从 0.8333 降至 0.7368——这是**真实方法边界**，不是退步；未覆盖的
   编码变体（base64/rot13/hex 之外的编码）与 4 条已知漏报都在文档中逐条记录。

**评测（可复算）**：30 案例 = 19 毒 + 11 良，`recall_case = 0.7368`、
`fpr_benign = 0.0`、`recall_rule = 0.7083`；23 条单元测试全绿。

**结论**：本仓证明"已知模式可被词法规则覆盖、且覆盖边界可被精确说出"，**不声明**
通用检出率。要用在生产，请把它当第一层过滤 + 人工复核，不是裁决器。

## 关键词

MCP 安全；提示注入；语义层投毒；供应链接攻击；离线扫描；fail-closed；
hash pinning；rug pull；LLM 工具安全

## 与真实代码的对应

| 摘要声明 | 对应真实实现 |
|---|---|
| 零模型调用、纯标准库 | `pyproject.toml` `dependencies = []` |
| 7 个规则家族 | `guard/rules.py`（公开可审） |
| 漂移检测字段级 diff | `guard/drift.py` |
| 命中身份 anchor | `guard/rules.py` 的 `(?P<anchor>...)` |
| 30 案例评测 | `tasks/cases.jsonl`（19 毒 + 11 良） |
| 三指标 | `run_eval.py --offline` 实测输出 |
| 23 条单测 | `pytest tests/ -q` 实测 23 passed |
