# mcp-guard —— MCP 毒工具扫描 + 版本钉选

企业痛点（2026 实证）：MCP 工具描述是自然语言，模型把它当指令执行。
MCPTox（2025-08）对 45 个真实 MCP 服务 × 20 个模型的投毒成功率最高
**72.8%**；postmark-mcp 真实投毒（1.0.16 静默 BCC）；Microsoft 2026-06
确认为通用外泄技术；OWASP Agentic Top 10（2025-12）收录。攻击载荷在
**语义层**，传统依赖扫描看不见。

本仓做两件事（离线、确定性、零模型调用）：

1. **scan**：对 MCP 工具定义（name/description/parameter schema）跑规则包，
   检出投毒模式（指令劫持标签、敏感文件读取、外泄参数、收件人改写等）。
2. **pin**：对工具定义做 sha256 钉选，服务端会话间改描述即告警
   （防 rug pull：先合法后投毒）。

## 诚实性约束

- 规则是**词法/语义启发式**，不是模型判断：对抗性改写可绕过，评测集
  只证明"已知模式覆盖率"，不声明"检出率"。未知模式记 `unknown`。
- `--fake` 回放只验证接线，不计入能力声明。
- 误报是有意的保守偏向：宁可 flag 再人工看，不静默放行——阈值由回归测试锁死。

## 快速开始

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest tests/ -q
.venv/bin/python run_eval.py --offline
.venv/bin/python run_eval.py --scan-file examples/whatsapp_tools.json
```

## 规则包（`guard/rules.py`，公开可审）

| 家族 | 检什么 | 真实原型 |
|---|---|---|
| `imperative-tag` | `<IMPORTANT>`/`<INSTRUCTION>`类劫持标签 | WhatsApp 4444 泄露案 |
| `secret-read` | 读 `~/.ssh`、MCP 配置、聊天记录并外带 | 密钥窃取演示 |
| `exfil-param` | 无害名参数（context/session_id）诱填敏感数据 | 参数外泄 |
| `recipient-rewrite` | 改写收件人/BCC/追加抄送 | postmark-mcp 1.0.16 |
| `auth-url-exec` | 工具参数直达shell（CVE-2025-6514模式） | mcp-remote 命令注入 |
| Rug-pull 经 pin 检出 | 描述哈希漂移 | 15 个干净版本后投毒 |

## 漂移检测（`guard/drift.py`）

rug pull 不是"文件变了"，而是"变了但审核者没看见"。所以比较两个版本时回答两个
sha256 答不了的问题：

1. **哪个字段动了**（name / description / schema）——description 改写是已证实的
   外泄通道（Microsoft 2026-06、MCPTox），而 schema 整体换键通常是客户端升级。
2. **是否新引入规则命中**——这才是告警级；无害改写与"现在开始让 agent 读
   `~/.ssh`"必须分开报。

`run_eval.py --scan-file` 演示输出：

```json
{"name": "send_message", "status": "DRIFT", "old": "d4a86de6d98e",
 "new": "c538212ab4d0", "fields": ["description"],
 "new_hits": ["imperative-tag", "secret-read"]}
```

没有历史快照时只报 digest 不一致，`fields` 标
`<unknown: no snapshot stored>`——不猜。

## 离线评测结果（`rules-v1`，27 案例：17 毒 + 10 良）

| 指标 | 值 | 读法 |
|---|---|---|
| `recall_case` | 12/17 = 0.7059 | 案例级检出 |
| `fpr_benign` | 0/10 = 0.0 | 良性误报 |
| `recall_rule` | 0.6818 | gold 规则命中率 |

数字比首个版本（20 案例时 0.8333）**下降了，且是应该的**：新增的 7 个案例是
对抗改写（同义 / 分词破短语 / 间接指令），本来就设计来打穿词法规则。降下来的
部分是真实边界，不是退步。

已知漏报（逐条记录，非掩盖）：
- `adv_paraphrase_populate` / `adv_paraphrase_copy`：`populate/with/copy/into`
  替换 `fill...with`，语义等价、词面不同 → 规则不触发。
- `adv_indirect_bcc`："add a hidden copy to X" 不含 `bcc/append/redirect`。
- `run_cmd`：纯描述"Run a shell command"无 shell 痕迹，属方法边界。
- `summarize`：旧版残留漏报（"fill the session_id param"缺 with 搭配）。
抓到的（值得记）：`adv_tag_split` 把 `<IM-POR-TANT>` 拆词逃过标签规则，
但 `~/.ssh/id_rsa` 仍被 `secret-read` 兜住——**多家族重叠是有意的兜底设计**。

> 结论：本仓证明"已知模式可被词法规则覆盖、且覆盖边界可被精确说出"，
> 不声明通用检出率。要用在生产，请把它当第一层过滤 + 人工复核，不是裁决器。

## 待办

- [x] rug-pull pin 机制（2026-10-14 落地，含字段级 diff）
- [ ] 评测集扩到 50+30，对抗改写（同义/分词/编码）专项
- [ ] 真实 MCP server.json 批量扫描报告
- [ ] 与 agent-redteam 剧本联动（93 测试复用）
