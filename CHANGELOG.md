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

### Fixed

- **能力层假阴性**：中置只读词（`Send ... show a receipt`、`Update ... status of`、
  `Set version-controlled permissions`）曾误触 READ_PHRASE 抑制，把真实 T2 写入工具
  静默降级成 T0。改为「最早动作词胜出」的位置规则（`_earliest_read_position` /
  `_earliest_mutating_position`），平局判给读词以保留句首只读句式
  （`agent-desktop is: Check element state`）。4 条 RED→GREEN 测试 + 双方向变异
  （拆机制 4 红、拆准则 1 红）。

### 已知边界（声明，不掩盖）

- 分层依据是工具名、描述与 schema，非运行时行为；不声明检出率。
- 代理只覆盖 stdio newline framing，不处理 `Content-Length`。
- batch 解包只看 schema 默认值与真实调用载荷；无默认载荷标 `opaque`。

## 0.1.0 — 2026-10-28

- 投毒规则包 6 族（imperative-tag / secret-read / exfil-param / recipient-rewrite /
  auth-url-exec / encoded-exfil），命中身份 = anchor。
- 哈希钉选 + 三层漂移检测（哈希+字段 diff / new_hits / changed_hits+hit_delta）。
- 离线评测 30 案例：recall_case 0.9474 / fpr_benign 0.0 / recall_rule 0.875（回归锁定）。
- 消融可复算（`scripts/measure_rule_ablation.py --check` 进 CI）、CI 门禁自证
  （`mutation-control.yml`）、真实语料扫描报告（64 工具 0 误报）。
