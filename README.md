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
| ` Rug-pull` 经 pin 检出 | 描述哈希漂移 | 15 个干净版本后投毒 |

## 离线评测结果（`rules-v1`，20 案例：12 毒 + 8 良）

| 指标 | 值 | 读法 |
|---|---|---|
| `recall_case` | 10/12 = 0.8333 | 案例级检出 |
| `fpr_benign` | 0/8 = 0.0 | 良性误报 |
| `recall_rule` | 0.75 | gold 规则命中率 |

已知漏报（诚实记录，非调参掩盖）：`run_cmd`（"Run a shell command" 无
shell=True 字样——纯描述无法判定，属方法边界）；`summarize`（"fill the
session_id param" 缺 `with` 搭配——改写一句即可绕过，见待办对抗专项）。

## 待办

- [ ] 评测集扩到 50+30，对抗改写（同义/分词/编码）专项
- [ ] 真实 MCP server.json 批量扫描报告
- [ ] 与 agent-redteam 剧本联动（93 测试复用）
