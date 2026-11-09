# Changelog

## 0.2.0 — 2026-11-09

### Added

- **能力分层（第二条正交轴）** `guard/capability.py`：T0_read / T1_local / T2_mutate /
  T3_destructive_or_exec / unknown 五档；危险参数表（`env`/`cwd`/`force`/`commands_json`
  等 17 项）；batch 载荷内层解包（深度上限 3、条数上限 64，超限标 `opaque`）；
  注解门（T3 必须显式 `destructiveHint: true`，写入工具必须 `readOnlyHint: false`）。
  `unknown` 表示不认识，绝不冒充只读。
- `mcp-guard-scan` 新旗标：`--capability`、`--fail-on-capability`（有 T3 即退出码 1）、
  `--require-annotations`（写入/破坏工具缺显式注解即退出码 1）。
- **stdio 实时代理** `mcp-guard-proxy`：`tools/list` 写 `tool_manifest.json` 与
  `capability_manifest.json`；`tools/call` 写脱敏 `tool_calls.json`（默认只存参数键名与
  digest）。阻断选项：`--block-on-hit`、`--block-unauthorized`、
  `--block-batch-destructive`（解包真实 `tools/call` 载荷并拒绝内层 T3）、
  `--require-annotations`、`--deny-arg-regex`。`--store-raw-args` 仅限本地调试。
- `scripts/capability_crosscheck.py` + CI 步骤：启发式分层与 agent-desktop@1.2.0 显式
  台账（67 工具，21/12/29/5）逐工具对表，漂移即红。
- 案例语料入库：`examples/agent_desktop_1_2_0_tools.json`（原始 tools/list）与
  `examples/agent_desktop_1_2_0_ledger.json`（显式分层台账）。
- **枚举感知危险参数**：全字符串枚举参数逐值分层取 max（枚举 `command` 只含
  `["status"]` 不再触发 exec 层）；shell 形值（`sh -c`/`cmd /c`/`powershell -c`）
  直接判 exec。
- **注解错配门** `tier_mismatches` + 代理 `--block-tier-mismatch`：`readOnlyHint: true`
  配 T2/T3 行为属"说谎"，与"沉默"分开记账，说谎即阻断。
- **能力清单漂移** `scripts/capability_drift.py`：对比两份 `capability_manifest.json`
  （tier 爬升 / 规则面增长 / 危险参数面变化），`--fail-on-drift` 进 CI；缺输入
  fail-closed（NOT_ASSESSED）。
- `mcp-guard-scan --annotation-report PATH`：注解审计只出报告不设门，与
  `--require-annotations` 正交。
- **声明式代理策略文件**：`--policy` 支持 `allow_tools` / `max_tier`（unknown
  fail-closed）/ `block.*` 六键（与 CLI 旗标 OR 合并）；`max_tier` 拼写错误启动即拒。
- **逐规则 prove-red 电池** `scripts/rule_prove_red.py`（进 CI）：6 投毒规则 + 9 能力
  规则每条配最小夹具，规则失明即红。
- **第二、三个能力台账**：`examples/whatsapp_sample_ledger.json`（手判先行）与
  `examples/magpie_registry_{tools,ledger}.json`（23 个无描述社区插件，钉死
  unknown 不冒充只读）；crosscheck 支持 `--tools/--ledger`。
- **MCPTox 外部语料首读**（`tasks/mcptox_probe.json`）：AAAI-26 基准公开可得；
  `pure_tool.json` 实为投毒定义语料（命名陷阱）；mcp-guard 词法规则接住
  24/485 ≈ 4.9%，主导缺口 = 条件调用序劫持模板族，已登记为后续项。
- **调用序劫持规则族** `call-order-hijack`（A1，FP 研究先行）：良性编排语料
  （官方 7 servers 67 工具 + firecrawl/arxiv 48 工具 = 115）里 call-order 句式
  **0 命中**后落地三锚（before…must…call / must first call / 强度词+带引号
  工具名跨句版）；MCPTox 覆盖 24→215/485（×9），良性 FP 0/115；语料 44 案例
  （25 毒/19 良）。
- **unicode/hex 转义解码**（B3）：`scan_text` 扫「原文+解码」两遍
  （`\uXXXX`/`\xXX`），ablation 机器共享同一解码（否则机器与 run_eval 口径
  漂移）；语料 47 案例，recall_case 0.963（26/27）、fpr 0.0（0/20）。
- **静态-运行时一致性审计** `scripts/capability_consistency.py`（A3）：对代理
  落盘产物判矛盾——清单外工具、只读层配危险参数、unknown 层配危险参数、
  只读层藏破坏性 batch 内层；digest-only 不猜值，缺输入 NOT_ASSESSED。
- **能力层消融** `scripts/capability_ablation.py`（B2）：四条证据轴
  （名称表/危险参数表/枚举感知/batch 解包）逐轴打补丁重扫，restore 后必须
  复现基线，否则 exit 2；三 fixture 实测：agent-desktop 仅名称轴影响 4 工具。
- **Streamable HTTP 传输代理** `guard/http_proxy.py`（D1）：MCP 2025-06-18
  推荐传输的请求侧门禁；`tools_scan`/`call_decision` 抽成模块级纯函数，stdio
  与 HTTP 两面共享同一门禁语义；阻断码与 stdio 一致（-32001/-32002/-32003/-32004）。
- **def_tool/.py 交叉验证**（A2）：MCPTox `def_tool/` 485 个 FastMCP 形态
  .py 经 AST 提取与 `pure_tool.json` 对表——438 全匹配、19 条同名不同毒文
  （上游两源不同步的实测证据）、2 条 name missing；.py smoke 扫描与 JSON
  语料完全一致（24/485）。
- **magpie 台账刷新**（D2）：live 注册表重读，23 工具名零漂移，三台账
  crosscheck 全绿。

### Fixed

- **能力层假阴性**：中置只读词（`Send ... show a receipt`、`Update ... status of`、
  `Set version-controlled permissions`）曾误触 READ_PHRASE 抑制，把真实 T2 写入工具
  静默降级成 T0。改为「最早动作词胜出」的位置规则（`_earliest_read_position` /
  `_earliest_mutating_position`），平局判给读词以保留句首只读句式
  （`agent-desktop is: Check element state`）。4 条 RED→GREEN 测试 + 双方向变异
  （拆机制 4 红、拆准则 1 红）。

### 已知边界（声明，不掩盖）

- 分层依据是工具名、描述与 schema，非运行时行为；不声明检出率。
- stdio 代理覆盖规范定义的 newline framing；HTTP 代理覆盖 Streamable HTTP 的
  请求侧（POST JSON-RPC），上游响应（含 SSE 流）原样中继不做响应侧重扫，
  无鉴权；自定义传输仍不覆盖。
- batch 解包只看 schema 默认值与真实调用载荷；无默认载荷标 `opaque`。
- 调用序劫持规则依赖强度词+引号工具名的形态学；跨句窗口 140 字符内的变体
  可覆盖，更远的或改写强度词的不保证。

## 0.1.0 — 2026-10-28

- 投毒规则包 6 族（imperative-tag / secret-read / exfil-param / recipient-rewrite /
  auth-url-exec / encoded-exfil），命中身份 = anchor。
- 哈希钉选 + 三层漂移检测（哈希+字段 diff / new_hits / changed_hits+hit_delta）。
- 离线评测 30 案例：recall_case 0.9474 / fpr_benign 0.0 / recall_rule 0.875（回归锁定）。
- 消融可复算（`scripts/measure_rule_ablation.py --check` 进 CI）、CI 门禁自证
  （`mutation-control.yml`）、真实语料扫描报告（64 工具 0 误报）。
