"""Extract MCP tool definitions from local checkouts offline.

Supported forms:
  Python  types.Tool(name=..., description=..., inputSchema={...})
          @mcp.tool decorated functions are NOT parsed (runtime registration)
  TS/JS    { name: 'x', description: `...` | '...' | "..." } object literals

Usage:
  python tasks/extract_thirdparty.py <checkout-dir> [<checkout-dir> ...] -o tools.json

The output is a JSON object {server_name: [tool, ...]} ready for guard.scan.
"""
from __future__ import annotations

import argparse
import ast
import json
import pathlib
import re
import sys

# tool-name looking identifiers: keeps the TS regex from matching state keys
NAME_RE = re.compile(
    r"name:\s*'(?P<name>[a-z][a-z0-9_.]{2,})'"
)
DESC_AFTER_NAME = re.compile(
    r"description:\s*(?P<q>`(?:[^`]*)`|'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")",
    re.S,
)


def _server_name(path: pathlib.Path) -> str:
    return path.name


def extract_python(text: str, out: list[dict]) -> None:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = getattr(node.func, "id", None) or getattr(node.func, "attr", None) or ""
        if fn not in ("Tool", "tool"):
            continue
        kw = {k.arg: k.value for k in node.keywords}
        if "name" not in kw:
            continue
        try:
            name = ast.literal_eval(kw["name"])
        except Exception:
            continue
        if not isinstance(name, str):
            continue
        desc, schema = "", {}
        for field, target in (("description", "desc"), ("inputSchema", "schema")):
            if field in kw:
                try:
                    value = ast.literal_eval(kw[field])
                except Exception:
                    value = ""
                if target == "desc" and isinstance(value, str):
                    desc = value
                elif target == "schema" and isinstance(value, dict):
                    schema = value
        out.append({"name": name, "description": " ".join(desc.split()), "inputSchema": schema})


def extract_ts(text: str, out: list[dict]) -> None:
    for m in NAME_RE.finditer(text):
        tail = text[m.end(): m.end() + 1200]
        d = DESC_AFTER_NAME.search(tail)
        if not d:
            continue
        desc = d.group("q")[1:-1]
        out.append({"name": m.group("name"),
                    "description": " ".join(desc.split()),
                    "inputSchema": {}})


def extract_checkout(root: pathlib.Path) -> list[dict]:
    seen: set[str] = set()
    tools: list[dict] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or "__pycache__" in p.parts or ".git" in p.parts:
            continue
        if "tests" in p.parts or "__tests__" in p.parts:
            continue
        if p.suffix == ".py":
            extract_python(p.read_text(encoding="utf-8", errors="replace"), tools)
        elif p.suffix in (".ts", ".mts", ".js", ".mjs"):
            if p.name.endswith(".d.ts"):
                continue
            extract_ts(p.read_text(encoding="utf-8", errors="replace"), tools)
    # a name can appear in several files; keep the first non-empty description
    deduped: list[dict] = []
    by_name: dict[str, dict] = {}
    for t in tools:
        cur = by_name.get(t["name"])
        if cur is None:
            by_name[t["name"]] = t
            deduped.append(t)
        elif not cur["description"] and t["description"]:
            cur["description"] = t["description"]
            cur["inputSchema"] = cur["inputSchema"] or t["inputSchema"]
    for t in deduped:
        if t["name"] not in seen:
            seen.add(t["name"])
    return deduped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("checkouts", nargs="+", type=pathlib.Path)
    ap.add_argument("-o", "--out", default="tools.json")
    a = ap.parse_args()
    result = {}
    for c in a.checkouts:
        tools = extract_checkout(c)
        result[_server_name(c)] = tools
        n_empty = sum(1 for t in tools if not t["description"].strip())
        print(f"{c.name}: {len(tools)} tools ({n_empty} with empty description)",
              file=sys.stderr)
        if n_empty:
            print("  NOTE: empty descriptions make 0 flags meaningless; "
                  "the extractor did not cover this server's registration form.",
                  file=sys.stderr)
    pathlib.Path(a.out).write_text(json.dumps(result, ensure_ascii=False, indent=1),
                                   encoding="utf-8")
    print(f"wrote {a.out}: {sum(len(v) for v in result.values())} tools "
          f"across {len(result)} servers", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
