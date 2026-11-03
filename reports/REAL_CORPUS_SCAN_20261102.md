# 真实 MCP 工具语料扫描（2026-11-02）

## 这是什么

此前所有指标都来自 `tasks/cases.jsonl` 的 30 条手写案例。本报告回答一个不同
的问题：**在真实 MCP server 的工具定义上，词法规则包会不会误报？**

## 语料

| 来源 | 版本 | server 数 | 工具数 |
|---|---|---|---|
| [`modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers) | `194cc86`（2026-10-28） | 7 | 62 |
| `aidless-portfolio-mcp`（本机） | 工作树 | 1 | 2 |
| **合计** | | **8** | **64** |

官方语料按 server 拆分：`everything` 23、`filesystem` 14、`git` 12、`memory` 9、
`time` 2、`fetch` 1、`sequentialthinking` 1。

## 方法

```bash
git clone --depth 1 https://github.com/modelcontextprotocol/servers.git /tmp/mcp-corpus-src
python tasks/extract_thirdparty.py /tmp/mcp-corpus-src/src -o /tmp/official.json
python tasks/extract_thirdparty.py /path/to/aidless-portfolio-mcp -o /tmp/local.json
python scripts/scan_corpus.py /tmp/merged.json --out /tmp/scan-report.json
```

`extract_thirdparty.py` 本次扩展了三种注册写法：Python `@server.tool(...)`、
TS `server.registerTool("name", { description })`、以及
`registerTool(name, config, ...)` + `const name = "..."` 的变量形式。

## 结果

```
{"n_servers": 2, "n_tools": 64, "n_empty_description": 1, "n_flagged": 0}
```

**64 个真实工具中 0 个被标记 → 在这批良性语料上未观察到误报。**

- `fetch` 的 1 个工具描述为空（抽取器未覆盖其注册形式），不构成任何方向的证据，
  已单独计入 `n_empty_description`。
- 其余 63 个工具的 description 均非空，抽样核对过 `read_text_file`、`status`、
  `create_entities`、`sequentialthinking`、`get_current_time`、`echo` 等，内容完整。

## 边界（必须一起读）

1. **这是误报测量，不是召回测量。** 官方 servers 是良性工具，本报告只能说
   "没把 64 个正常工具误判为毒"；它对"能不能检出真实攻击"零证据。
2. **静态抽取有覆盖上限。** 运行时注册（`@mcp.tool()` 装饰器之外的动态 name、
   zod 运行时拼出的 schema）抽不到；TS 工具的 `inputSchema` 统一留 `{}`，所以
   "只看参数名"的规则在这批语料上没有被完整触发。
3. **64 条不是随机样本。** 它偏向官方参考实现，不代表整个 MCP 生态。
4. **`fpr_benign = 0.0` 的含义仍然只在"这 64 条"上成立**，与 30 条基准的
   0/11 是两个独立口径，不能相加。

## 结论

词法规则包在 64 个真实良性 MCP 工具上未产生误报。这是"零误报"从 11 条手写
良性案例扩到 63 条真实工具的一步，但**不改变"不声明通用检出率"的立场**——
召回仍只在 19 条手写 poison 上可测（当前 18/19）。
