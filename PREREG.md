# PREREG — mcp-guard 预注册规格

> 本文件是 mcp-guard 的**预注册规格**（pre-registration spec）：把研究假设、评测方案、
> 成功标准与明确边界写在**分析之前**，防止事后按结果挑边界。
> 所有数字与判据都可从仓库内确定性代码复算（见「复算」节）。

## 1. 研究问题

MCP（Model Context Protocol）工具定义是自然语言，模型把它当指令执行。攻击载荷
位于**语义层**：MCPTox（2025-08）对 45 个真实 MCP 服务 × 20 个模型的投毒成功率最高
**72.8%**；postmark-mcp 1.0.16 真实投毒（静默 BCC）；Microsoft 2026-06 确认为通用外泄
技术；OWASP Agentic Top 10（2025-12）收录。传统依赖扫描（package-lock、pip-audit）
看不见这一层——因为它扫描的是**依赖**，不是**工具描述文本**。

**核心假设（H1）**：MCP 工具描述中的已知投毒模式，可被**离线、确定性、零模型调用**的
词法/语义规则包覆盖，且覆盖边界**可被精确说出**。

**辅助假设（H2，防 rug pull）**：对工具描述做 sha256 钉选 + 字段级 diff，可在服务端
会话间识别"描述被改写"这一真实外泄通道，且命中身份（anchor）比整段命中文本更能
区分"无害措辞改动"与"换载荷攻击"。

## 2. 评测方案（可复算）

### 2.1 评测集

- `tasks/cases.jsonl`：**30 案例 = 19 毒 + 11 良**（实测 `len([...])`）。
- 毒用例覆盖 7 个规则家族的真实原型（`imperative-tag`、`secret-read`、`exfil-param`、
  `recipient-rewrite`、`auth-url-exec`、`encoded-exfil`、rug-pull pin）。
- 良性用例用于测误报；其中含**对抗改写**（同义替换、分词破短语、间接指令），
  这些是**有意设计来打穿词法规则**的，不是要全部检出。

### 2.2 指标与成功标准

| 指标 | 定义 | 成功标准 |
|---|---|---|
| `recall_case` | 毒用例中被规则命中的比例 | 用于**回归锁定**，不作总体检出率声明 |
| `fpr_benign` | 良性用例中被误报的比例 | `= 0.0`（零误报为回归红线） |
| `recall_rule` | gold 规则命中数 / 规则总数 | 用于回归锁定 |

**注意**：成功标准是"指标可复算且边界可被精确说出"，**不是**"检出率越高越好"。
新增对抗改写案例会让 `recall_case` 下降——这是**真实边界**，不是退步。

### 2.3 复算命令

```bash
python3 run_eval.py --offline          # 三指标
python3 -m pytest tests/ -q            # 23 passed
python3 -c "import json; print(len([1 for l in open('tasks/cases.jsonl')]))"  # 30
```

## 3. 明确边界（不证明什么）

mcp-guard **不证明**以下内容——它们是真实方法边界，非隐藏缺陷：

1. **不声明通用检出率**：规则是词法/语义启发式，对抗性改写可绕过。评测集只证明
   "已知模式覆盖率"，`recall_case=0.7368` 只在这 19 条毒样本上成立。
2. **`--fake` 回放只验证接线，不计入能力声明**。
3. **未覆盖的编码变体**：base64/rot13/hex 之外的编码（偏移+异或、自定义表），
   以及把编码串直接塞进参数名而不写 "include/send" 的写法，都不在 `encoded-exfil`
   的三段判定内——已知边界，未修。
4. **已知漏报**（逐条记录，非掩盖）：`adv_paraphrase_populate`/`adv_paraphrase_copy`
   （语义等价、词面不同）、`adv_indirect_bcc`（"add a hidden copy to X"）、`run_cmd`
   （纯描述无 shell 痕迹）、`summarize`（旧版残留）。
5. **无历史快照时**漂移检测只报 digest 不一致，`fields` 标 `<unknown: no snapshot
   stored>`——不猜，不把"不知道"当"干净"。
6. **误报是刻意保守偏向**：宁可 flag 再人工看，不静默放行——阈值由回归测试锁死。
7. **PyPI 尚未发布**（截至 2026-10-28），`pip install mcp-guard` 会失败，需源码安装。

## 4. 成功标准（判据）

本预注册声明**成功**当且仅当：
1. 三个指标可由 `run_eval.py --offline` 复算（与 README 记录值一致）；
2. 回归测试 `pytest tests/ -q` 全绿（23 passed）；
3. 每一条已知漏报/未覆盖边界都能在仓库文档中找到**对应记录**（不静默）。
