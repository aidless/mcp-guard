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
- **响应侧门禁**（R1）：tools/call 的 JSON-RPC result 响应过同一套投毒规则——
  `response_scan(result)` 模块级纯函数，stdio 与 HTTP 共享；默认只观测
  （`tool_calls` 记 `response_flagged`/`response_rule_ids`/`response_texts_scanned`），
  `--block-response-hits` 命中即以 -32007 替换响应不转发（policy 键
  `response_hits` 同样生效）；SSE 流式体仍原样中继（边界保留）。
- **behavior-override + param-pollution 规则族**（R2，MCPTox 残差 270 分型
  驱动）：行为越权四锚（priority/precedence、override…regardless of、
  must instead/rather、refined regardless-of-input）+ 参数污染两锚
  （强度词+动词+带引号目标值/参数词）；MCPTox 覆盖 215→347/485（71.6%），
  良性基座扩到 222（+ smithery 108 条实抓）仍 0 FP；语料 52 案例（32 毒/
  22 良），recall_case 0.9688、fpr 0.0、recall_rule 0.9268；裸 regardless
  边界由良性 `read_text_file`（"regardless of extension"）钉死。
- **全链路 e2e 演示** `demo.sh`（R3）：六腿全真实子进程（静态扫描/漂移钉选/
  stdio 观测/stdio 阻断/HTTP 门禁/一致性审计），腿级自证、失败退出非零，
  `tests/test_demo_e2e.py` 接进套件。
- **跨仓联动**：agent-redteam `defenses/mcp_guard_scanner.py`（R6，layer 6：
  投毒命中→BLOCK、注解说谎→FLAG、引擎缺失→FLAG 绝不静默放行，commit eecb08f）；
  auditable-llm-eval `eval/auto_tool_calls.py`（R7：OpenAI 兼容 function-calling
  推理路径自动采集 tool_calls.json，Magpie live smoke 通过，commit c9f7400；
  runner 接线因该文件另有未提交改动而显式挂起）。

### Fixed

- **能力层假阴性**：中置只读词（`Send ... show a receipt`、`Update ... status of`、
  `Set version-controlled permissions`）曾误触 READ_PHRASE 抑制，把真实 T2 写入工具
  静默降级成 T0。改为「最早动作词胜出」的位置规则（`_earliest_read_position` /
  `_earliest_mutating_position`），平局判给读词以保留句首只读句式
  （`agent-desktop is: Check element state`）。4 条 RED→GREEN 测试 + 双方向变异
  （拆机制 4 红、拆准则 1 红）。

### 已知边界（声明，不掩盖）

- **发行名（dist name）是 `mcp-guard-scan`，不是仓库名 `mcp-guard`**。PyPI 的
  `ultranormalize_name()` 把 `mcp-guard` 归一为 `mcpguard`，与 2026-02 起的既有包
  `mcpguard` 同形，命中名称相似性检查（400，无 owner 例外）；`mcp-audit` 同理被
  `mcpaudit` 挡住。console script 名不受影响（仍是 `mcp-guard` /
  `mcp-guard-scan` / `mcp-guard-proxy`），从仓库装与从 Release 工件装行为一致。
- PyPI 上传通道实测受账号级配额限制（`429 Too many new projects created`，
  `project.create.user` 桶 4/86400s 耗尽；换 IP 后 `project.create.ip` 有余额但
  user 桶仍为 0，即换 IP 无效）。仓库已备 OIDC 可信发布工作流绕开该配额。
- 分层依据是工具名、描述与 schema，非运行时行为；不声明检出率。
- stdio 代理覆盖规范定义的 newline framing；HTTP 代理覆盖 Streamable HTTP 的
  请求侧，tools/call 的 JSON-RPC result 响应已做响应侧投毒扫描（R1），
  **SSE 流式体仍原样中继不重扫**；无鉴权；自定义传输仍不覆盖。
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
