# 首份市场扫描报告（2026-10-14，rules-v1）

## 样本

官方参考实现（modelcontextprotocol/servers，2026-10-14 shallow clone）：

| server | 工具数 | flagged |
|---|---|---|
| filesystem | 14 | 0 |
| git | 12 | 0 |
| memory | 9 | 0 |
| time | 2 | 0 |
| fetch | 1 | 0 |
| sequentialthinking | 1 | 0 |
| **合计** | **39** | **0** |

提取方式：`registerTool(name, {description})` / `Tool(name=, description=)` /
`list_tools()` 静态解析，不执行任何 server。描述原文未改动，见
`/tmp/opencode/mcp_market_tools.json`（分析机本地）。

## 对照组（毒工具重构，12 个）

按公开事件原型重构（WhatsApp 4444 案、postmark-mcp 1.0.16、MCPTox 模式）：

- flagged 10/12，recall 0.83，与 `run_eval.py --offline` 一致。
- 2 个漏报：`run_cmd`（纯描述无 shell 痕迹，方法边界）、`summarize`
 （fill 搭配改写，见 README 已知漏报表）。

## 结论（诚实版）

1. 官方参考实现 0 告警：在可信样本上 FPR=0，与评测集良性 8/8 一致。
2. 本扫描**不能**证明野外安全：只覆盖官方 6 个 server，且是静态描述层；
   真实风险在第三方市场（12,000+ server）与运行时 rug pull（描述漂移）。
3. 下一步：pin 机制对同一 server 做版本间漂移检测 + 第三方 server 批量扫描。

## 方法边界

- 零模型调用，纯规则；对抗改写可绕过（待办 50+30 对抗专项）。
- 证据：`guard/rules.py` 规则包 + `tasks/cases.jsonl` 20 案例，两者缺一不可。
