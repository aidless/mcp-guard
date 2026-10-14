# 第二批市场扫描：第三方 server（2026-10-14，rules-v1）

## 样本

选取 GitHub 高 star 且非 modelcontextprotocol 官方参考实现（`mcp-server` 关键字
按 star 排序前 15 里剔除 awesome 列表与 Go/TS SDK 后取 4 个浅克隆）：

| server | star | 工具数 | flagged |
|---|---|---|---|
| firecrawl-mcp-server | 7.6k | 30 | 0 |
| arxiv-mcp-server | 3.2k | 19 | 0 |
| **合计** | | **49** | **0** |

提取方式：Python 走 `types.Tool(name=, description=, inputSchema=)` AST；
TypeScript 走 `name: '...' ... description: \`/...'` 正则。49/49 有非空描述
（空描述会让 0 告警变得无意义，故显式校验）。与第一批（官方 6 server / 39 工具，
0 告警）合计 **88 工具、0 误报**。

## 对照组（毒工具重构，17 毒）

同一评测集下 `recall_case 0.7059 / fpr 0.0`（README 已记录对抗集使指标从
0.8333 诚实下降）。已知漏报为同义改写与间接指令（`populate/with`、
"add a hidden copy to"），均逐条列在 README。

## 结论（能说什么，不能说什么）

1. 可信样本上 FPR=0：官方 39 + 第三方 49，无一误报。
2. 仍**不能**推断野外安全：样本 2 个 server、且是静态描述层；真实风险在
   12,000+ 注册中心的第三方长尾与运行时 rug pull。
3.下一步不是扩大词法规则，而是把 `guard/drift.py` 接到版本对比流水线——
   第一批已证明"审核后改描述"是主要缺口，那是机制问题不是规则问题。

## 复现

```bash
git clone --depth 1 https://github.com/firecrawl/firecrawl-mcp-server
git clone --depth 1 https://github.com/blazickjp/arxiv-mcp-server
python3 tasks/extract_thirdparty.py firecrawl-mcp-server arxiv-mcp-server -o tools.json
# 然后对每个 tool 调 guard.scan.scan_tool
python3 -m pytest tests/ -q     # 9 green
```

提取结果：49 工具 / 49 非空描述 / 0 告警（上述命令的 stderr 会打印每个 server
的工具数与空描述数；0 告警若无此学校验则无意义）。

证据与分析机路径：`/tmp/opencode/third_tools.json`、`/tmp/opencode/third_scan.json`。
