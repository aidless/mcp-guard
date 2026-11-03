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

## 安装

**PyPI 尚未发布**（截至 2026-10-28）。`pip install mcp-guard` 会失败，请从源码安装：

```bash
git clone https://github.com/aidless/mcp-guard && cd mcp-guard
pip install .
mcp-guard --offline
```

开发（可编辑 + 跑测试）：

```bash
python3 -m venv .venv && .venv/bin/pip install -e . && .venv/bin/pip install pytest
.venv/bin/python -m pytest tests/ -q
```

运行时依赖为空（`pyproject.toml` 的 `dependencies = []`）：规则包、扫描、钉选、
漂移检测全部只用标准库。`requirements.txt` 里的 `pytest` 只在开发/测试时需要。

## 快速开始

```bash
# 安装后——两个入口，职责不同
mcp-guard --offline                                      # 评测运行器：跑离线基准集
mcp-guard --scan-file examples/whatsapp_tools.json       # 评测运行器：也能扫文件
mcp-guard-scan examples/whatsapp_tools.json              # 扫描器：只扫 / 钉选 / 漂移

# 未安装时也可直接跑
python3 run_eval.py --offline
python3 run_eval.py --scan-file examples/whatsapp_tools.json
python3 -m guard.cli examples/whatsapp_tools.json
```

### 两个命令入口的分工（2026-10-28 修的语义落差）

| 命令 | 实际做什么 | 什么时候用 |
|---|---|---|
| `mcp-guard`（= `run_eval:main`） | 离线**评测**运行器：`--offline` 跑基准集算 recall/fpr，`--scan-file` 也能扫文件 | 复现指标、回归 |
| `mcp-guard-scan`（= `guard.cli:main`） | 只做**扫描 + 哈希钉选 + 漂移检测**，逐工具输出 JSON 行；`--fail-on-hit` 时有命中即退出码 1 | 接进 CI 门禁 / agent 启动前的工具体检 |

两者共用 `guard.scan` 的同一套扫描逻辑，扫描结果完全一致；名字曾经对不上
（`mcp-guard --offline` 跑的是评测而不是扫描），现在拆开了。

`--offline` 的实测输出（19 条 poison / 11 条 benign）：

```json
{"encoder": "rules-v1", "n_poison": 19, "n_benign": 11,
 "recall_case": 0.9474, "fpr_benign": 0.0, "recall_rule": 0.875}
```

> `recall_case` 是**这 19 条样本上的**用例覆盖率，不是总体检出率；
> `fpr_benign = 0.0` 是**这 11 条 benign 上**的零误报。样本量很小，
> 这两个数字只用于回归锁定，不作能力声明。

## 规则包（`guard/rules.py`，公开可审）

| 家族 | 检什么 | 真实原型 |
|---|---|---|
| `imperative-tag` | `<IMPORTANT>`/`<INSTRUCTION>`类劫持标签 | WhatsApp 4444 泄露案 |
| `secret-read` | 读 `~/.ssh`、`~/.aws/credentials`、`~/.netrc` 等凭据路径、MCP 配置、聊天记录并外带 | 密钥窃取演示 |
| `exfil-param` | 无害名参数（context/session_id）诱填敏感数据 | 参数外泄 |
| `recipient-rewrite` | 改写收件人/BCC/追加抄送 | postmark-mcp 1.0.16 |
| `auth-url-exec` | 工具参数直达shell（CVE-2025-6514模式） | mcp-remote 命令注入 |
| `encoded-exfil` | 敏感材料**先编码再外带**（明文规则看不见这一层） | base64 编码外带对抗改写 |
| Rug-pull 经 pin 检出 | 描述哈希漂移 | 15 个干净版本后投毒 |

## 漂移检测（`guard/drift.py`）

rug pull 不是"文件变了"，而是"变了但审核者没看见"。所以比较两个版本时回答两个
sha256 答不了的问题：

1. **哪个字段动了**（name / description / schema）——description 改写是已证实的
   外泄通道（Microsoft 2026-06、MCPTox），而 schema 整体换键通常是客户端升级。
2. **命中有没有变化**——这才是告警级；无害改写与"现在开始让 agent 读
   `~/.ssh`"必须分开报。2026-10-28 起这一层比的是**命中内容**（规则 id +
   实际命中的文本），不再只是规则 id：同一 family 里换载荷也算变化。

`run_eval.py --scan-file` 演示输出：

```json
{"name": "send_message", "status": "DRIFT", "old": "d4a86de6d98e",
 "new": "c538212ab4d0", "fields": ["description"],
 "new_hits": ["imperative-tag", "secret-read"],
 "changed_hits": [], "alarm": true}
```

没有历史快照时只报 digest 不一致，`fields` 标
`<unknown: no snapshot stored>`——不猜。

## 离线评测结果（`rules-v1`，30 案例：19 毒 + 11 良）

| 指标 | 值 | 读法 |
|---|---|---|
| `recall_case` | 18/19 = 0.9474 | 案例级检出 |
| `fpr_benign` | 0/11 = 0.0 | 良性误报 |
| `recall_rule` | 21/24 = 0.875 | gold 规则命中率 |

数字比首个版本（20 案例时 0.8333）**下降了，且是应该的**：新增的 7 个案例是
对抗改写（同义 / 分词破短语 / 间接指令），本来就设计来打穿词法规则。降下来的
部分是真实边界，不是退步。

> **2026-11-02 更新**：对抗改写里有 4 条此前被词法规则漏掉（见下文"已知漏报"）。
> 自进化闭环把它们识别为 confirmed miss 后，给 `exfil-param` 补了同义改写家族
> （含 `fill/populate/copy ... param`）、给 `recipient-rewrite` 补了间接抄送，
> `recall_case` 从 0.7368 → **0.9474**、`recall_rule` 从 0.7083 → **0.875**，
> `fpr_benign` 仍为 0.0（零误报没被换掉）。
> 这是把已知边界往回推了一格，不是调参刷分。

### 编码对抗改写（2026-10-28 新增，可复算）

新增 1 条毒用例 `export_profile`（把 SSH 私钥材料 base64 编码后塞进参数）和
1 条良性用例 `generate_ssh_keypair`（生成 SSH 公钥并 base64 返回）。加规则前，
`export_profile` **能被明文规则看到吗？看不到**——它绕开了 `secret-read`
（没写 `~/.ssh`）、`exfil-param`（没用 `fill ... with`）、`recipient-rewrite`。

消融测量（`scripts/measure_rule_ablation.py`，摘掉规则在内存里重算，一条命令可复算）。
下表是对**当前** `cases.jsonl`（30 案例：19 毒 / 11 良，24 条 gold 规则）的实测：

| | recall_case | fpr_benign | recall_rule |
|---|---|---|---|
| 全部规则（有 `encoded-exfil`） | 18/19 = 0.9474 | 0/11 = 0.0 | 21/24 = 0.875 |
| 去掉 `encoded-exfil` | 17/19 = 0.8947 | 0/11 = 0.0 | 20/24 = 0.8333 |

> 复算命令：`python3 scripts/measure_rule_ablation.py`（加 `--markdown` 出这张表，
> `--check` 把 headline 三元组接成 CI 门禁）。脚本自己会先和 `run_eval.py --offline`
> 对表，AGREE 才继续，避免"两把尺各算各的"。
>
> 历史快照（首次引入时 18 毒 / 23 gold 规则，13/18 = 0.7222）已被上表取代，
> 不再作为当前数字引用。

良性用例 `generate_ssh_keypair` 没被误伤——因为规则要求三段同现
（敏感材料 → 编码 → 外带/落参），"生成公钥并 base64 编码"没有外带动作。
少一段就不报，这是为压误报做的刻意取舍。

### 凭据路径扩展（2026-10-28 新增，由一次 rug-pull 演练逼出来的）

演练里把 `send_message` 的描述改成合法外观 + 偷读 `~/.aws/credentials`，
漂移检测报的是：

```json
{"name": "send_message", "status": "DRIFT", "fields": ["description"],
 "new_hits": [], "gone_hits": ["imperative-tag", "secret-read"]}
```

**`new_hits` 是空的。** 攻击换了一种（从 `~/.ssh` 换成 `~/.aws/credentials`），
规则包里没有对应模式，于是"新引入规则命中"这个告警维度**看不见它**——
只有哈希漂移 + 字段级 diff 抓住了它。

据此给 `secret-read` 家族补了常见凭据路径（`~/.aws`、`~/.gnupg`、`~/.kube`、
`~/.docker`、`~/.azure`、`~/.config/gcloud`、`.netrc`、`*_credentials`），
并新增毒用例 `read_credentials`。消融测量（对**当前** `cases.jsonl`）：

| | recall_case | fpr_benign | recall_rule |
|---|---|---|---|
| 有扩展后的 `secret-read` | 18/19 = 0.9474 | 0/11 = 0.0 | 21/24 = 0.875 |
| 只有 `~/.ssh` 族（收紧） | 16/19 = 0.8421 | 0/11 = 0.0 | 18/24 = 0.75 |

> 这两行和上表由同一条命令产出、互相一致；`fpr_benign` 在所有消融下都保持 0，
> 即"加规则扩覆盖没有引入良性误报"。早期快照的 10/19 / 11/24 来自更早、更小的一版
> 规则包与案例集，与当前实现不同口径，不作为当前数字引用。

> 教训：**"新引入规则命中"不是漂移检测的替代品**。它是更精确的告警维度，
> 但只在"新攻击落在已有规则覆盖内"时才有效。哈希漂移 + 字段 diff 才是兜底。

补完规则后，同一次演练**仍然是 `new_hits: []`**——但原因变了：`secret-read`
在新旧两版都命中，而 `new_hits` 算的是**规则 id 集合的差集**，不是"命中内容"
的差集。于是"载荷被整个换掉了"这件事，在这一层依然看不见。

> **2026-10-28 已修**：命中身份从"规则 id"改成"规则 id + 实际命中的文本"。
> 同一个 `secret-read` 在旧版命中 `~/.ssh`、在新版命中 `~/.aws`，现在会落进
> 新字段 `changed_hits`，并置 `alarm: true`。`new_hits` 的语义**保持不变**
> （只是"此前完全没触发的规则 id"），所以旧调用方不用改。
>
> ```json
> {"name": "send_message", "status": "DRIFT", "fields": ["description"],
>  "new_hits": [], "changed_hits": ["secret-read"],
>  "hit_delta": [
>    {"rule": "secret-read", "change": "added",   "match": "~/.aws"},
>    {"rule": "secret-read", "change": "removed", "match": "~/.ssh"},
>    {"rule": "imperative-tag", "change": "removed", "match": "<IMPORTANT>"}],
>  "gone_hits": ["imperative-tag"], "alarm": true}
> ```
>
> `alarm` 是 `None` 而不是 `false` 的情况：digest 变了但没有存快照——
> **不知道 ≠ 干净**，这时只能靠 `fields: ["<unknown: no snapshot stored>"]`
> 提示人工介入，不能当成"没发现新命中"。

### 命中身份 = 敏感锚点（2026-10-28 同日第二次修订）

第一版把命中身份定成"整段命中文本"后，立刻测出误报面：`secret-read` 的模式
`read\s+.*(id_rsa|…)` 会把中间所有词吃进 `match`，于是

```
旧: "read the id_rsa key"   → match "read the id_rsa"
新: "read your id_rsa key"  → match "read your id_rsa"   ← 只换了 the→your
```

`alarm` 翻成 `True`，平台侧 R1 就判 `BLOCK`。纯措辞改动触发 `BLOCK` 是不可用的。

所以命中身份再收一层：每条 pattern 用 `(?P<anchor>...)` 标出**"这次打的是什么"**
那个词，比的是它：

| 改动 | anchor | alarm |
|---|---|---|
| `read the …` → `read your …` | `id_rsa` → `id_rsa` | `False` ✅ |
| `read the id_rsa file and show its fingerprint` → `… its SHA256 fingerprint` | `id_rsa` → `id_rsa` | `False` ✅ |
| `read the id_rsa key` → `read the .pem key` | `id_rsa` → `.pem` | `True` ✅ |
| `~/.ssh/id_rsa` → `~/.aws/credentials` | `ssh` → `aws` | `True` ✅ |
| `BCC a copy` → `redirect the email` | `bcc` → `email` | `True` ✅ |

没标 `(?P<anchor>...)` 的规则回退成**整段命中文本的 sha256 前 16 位**，
所以 `match` 截断到 80 字符**不再影响漂移判断**——80 字符之后的差异照样能分辨
（`test_anchor_ignores_80_char_truncation` 守着这条不变量）。

新增测试 4 条：3 个无害改写必须 `alarm=False`、3 个真换载荷必须 `alarm=True`、
所有内建命中必须带 anchor、anchor 不受 80 字符截断影响。

三层合起来才完整（2026-10-28 后的实际形态）：

| 层 | 回答的问题 | 本次演练的表现 |
|---|---|---|
| 哈希 + 字段 diff | 哪个字段被动了 | `fields: ["description"]` ✓ 抓到 |
| `new_hits` | 有没有**全新规则**开始触发 | 空（规则族已被同一个 family 覆盖） |
| `changed_hits` | 同一规则**命中的东西**是否换了 | `["secret-read"]` ✓ 抓到（新增层） |
| 规则包覆盖度 | 新攻击是否落在**规则覆盖**内 | 补规则后覆盖（`~/.aws/credentials` 命中） |

已知漏报（逐条记录，非掩盖）——**2026-11-02 起，四条已由自进化闭环修掉**：
- [x] `summarize`：原 `use system prompt ... param` 规则要求两者相距 ≤30 字符，
  实际隔了 50 字符 → 一直未命中。已给 `exfil-param` 补
  `fill/populate/copy ... <敏感参数> ... param(eter)`，现命中。
- [x] `adv_paraphrase_populate` / `adv_paraphrase_copy`：`populate/with`、`copy/into`
  替换 `fill...with`，语义等价、词面不同 → 曾规则不触发。已给 `exfil-param` 补同义
  改写家族（锚点仍是敏感参数名，copy 要求 `into <敏感参数>` 以免误伤），现均命中。
- [x] `adv_indirect_bcc`："add a hidden copy to X" 不含 `bcc/append/redirect`。已给
  `recipient-rewrite` 补 `hidden copy`（锚点 `copy`），现命中。
- [ ] `run_cmd`：纯描述"Run a shell command"无 shell 痕迹，属方法边界（未修）。
  （这是目前唯一未修的词法边界：描述里没有任何 shell 痕迹可抓。）

> 机器可读的边界清单在 [`tasks/known_boundaries.json`](tasks/known_boundaries.json)。
> `agent-evolve --fail-on-proposal` 读它，把 `run_cmd` 归为 `known_boundary` 而非
> 新漏报；**不在清单里的** poison 一旦未被规则命中，门禁就变红。新增一块已接受的
> 边界必须同时写进这里，否则 CI 会一直红——这是刻意的：边界要被声明，不能被沉默。
抓到的（值得记）：`adv_tag_split` 把 `<IM-POR-TANT>` 拆词逃过标签规则，
但 `~/.ssh/id_rsa` 仍被 `secret-read` 兜住——**多家族重叠是有意的兜底设计**。
仍未覆盖的编码变体：base64/rot13/hex 之外的编码（偏移+异或、自定义表），
以及把编码串直接塞进参数名而不写 "include/send" 的写法，都不在 `encoded-exfil`
的三段判定内——已知边界，未修。

> 结论：本仓证明"已知模式可被词法规则覆盖、且覆盖边界可被精确说出"，
> 不声明通用检出率。要用在生产，请把它当第一层过滤 + 人工复核，不是裁决器。

## 待办

- [x] rug-pull pin 机制（2026-10-14 落地，含字段级 diff）
- [x] 编码对抗改写专项第一轮（2026-10-28：1 毒 + 1 良性用例 + `encoded-exfil` 规则 + 消融测量）
- [x] 凭据路径扩展（2026-10-28：rug-pull 演练逼出来的——`new_hits` 抓不到"换一种攻击"，
  故 `secret-read` 补 `~/.aws`/`~/.netrc`/`~/.kube` 等路径 + 新增 `read_credentials` 用例）
- [x] `new_hits` 改为命中内容级别（2026-10-28：新增 `changed_hits` / `hit_delta` / `alarm`；
  `new_hits` 语义保持不变以兼容旧调用方；`alarm: null` = 没快照、无法判断）
- [ ] 评测集扩到 50+30，对抗改写（同义/分词/编码）剩余变体
- [ ] 真实 MCP server.json 批量扫描报告
- [ ] 与 agent-redteam 剧本联动（93 测试复用）
- [x] CI 门禁自证（`scripts/mutation_control.py` + `mutation-control` workflow：
  证明 pytest 门禁在代码被改坏时**必须**变红，而不是把失败吞掉）
- [x] 消融数字可复算（2026-11-02：`scripts/measure_rule_ablation.py` 落盘，
  与 `run_eval.py --offline` 对表 AGREE；README 两组消融表换成当前可复算实测值）
- [x] **Agent Reliability Platform 胶水层**：与 `auditable-llm-eval` 组成三层
  （BEFORE 门禁 / AFTER 审计 / trace 胶水）。胶水层落盘在 `auditable-llm-eval` 仓
  `agent_platform/trace.py`（一条命令产出带 sha256 的 trace），工具绑定（allowlist）
  与实际调用（tool_calls）两层都已接进来。
- [ ] 让 runner 从推理路径**自动**采集 tool_calls（当前是喂入观测证据，
  因为本仓评测腿走 ollama `/api/generate` 纯文本补全、无原生 tool_calls 字段；
  自动采集需换 chat 接口 + function-calling 模型，属另一增量）。
