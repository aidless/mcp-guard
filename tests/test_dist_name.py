"""发行名（dist name）锁定测试。

为什么需要这条：PyPI 的 `ultranormalize_name()` 把 `mcp-guard` 归一成 `mcpguard`，
与 2026-02 起就存在的既有包 `mcpguard` 完全同形，`check_project_name()` 会抛
`ProjectNameUnavailableSimilarError` → HTTP 400，且没有 owner 例外。所以发行名必须
是 `mcp-guard-scan`，而 console script 名保持不变（改名会破坏所有既有文档与 CI 脚本）。

这条测试锁两件事：
1. `pyproject.toml` 的 `[project] name` 是 `mcp-guard-scan`（且不是会撞名的 `mcp-guard`）；
2. 三个 console script 的入口点原样保留。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"

EXPECTED_DIST_NAME = "mcp-guard-scan"
EXPECTED_SCRIPTS = {
    "mcp-guard": "run_eval:main",
    "mcp-guard-scan": "guard.cli:main",
    "mcp-guard-proxy": "guard.proxy:main",
}


def _ultranormalize(name: str) -> str:
    """复刻 warehouse 的 ultranormalize_name()。

    源码见 warehouse/migrations/versions/d18d443f89f0_ultranormalize_name_function.py：
    lower → 去掉 `.`/`_`/`-` → `l/L/i/I`→`1` → `o/O`→`0`。
    """
    s = name.lower()
    s = re.sub(r"[._-]", "", s)
    s = re.sub(r"[li]", "1", s)
    s = re.sub(r"o", "0", s)
    return s


def _load_pyproject() -> dict:
    """读 pyproject.toml（优先 tomllib，Python 3.9/3.10 回退到简易解析）。"""
    text = PYPROJECT.read_text(encoding="utf-8")
    try:
        import tomllib  # Python 3.11+

        return tomllib.loads(text)
    except ModuleNotFoundError:  # pragma: no cover - 3.9/3.10 走这里
        pytest.importorskip("tomli")
        import tomli

        return tomli.loads(text)


def test_dist_name_is_mcp_guard_scan() -> None:
    """发行名必须是 mcp-guard-scan。"""
    doc = _load_pyproject()
    assert doc["project"]["name"] == EXPECTED_DIST_NAME


def test_dist_name_does_not_collide_with_mcpguard() -> None:
    """发行名的 ultranormalize 结果不能与既有 mcpguard / mcpaudit 同形。

    这是 PyPI 相似性检查的真实判据，不是形状比喻：ultra("mcp-guard") == "mcpguard"，
    与既有包完全相等 → 400。
    """
    doc = _load_pyproject()
    ultra = _ultranormalize(doc["project"]["name"])
    assert ultra == "mcpguardscan"
    # 反向断言：撞名的旧名字确实会撞，证明本测试的判据是有效判据而非装饰。
    assert _ultranormalize("mcp-guard") == "mcpguard"
    assert _ultranormalize("mcp-audit") == "mcpaud1t"
    assert ultra not in {"mcpguard", "mcpaud1t"}


def test_console_scripts_unchanged() -> None:
    """三个 console script 入口点保持不变（改发行名不该动脚本名）。"""
    doc = _load_pyproject()
    assert doc["project"]["scripts"] == EXPECTED_SCRIPTS


def test_version_matches_changelog_head() -> None:
    """pyproject 的 version 必须是 CHANGELOG 里最新一节。"""
    doc = _load_pyproject()
    version = doc["project"]["version"]
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r"^## (\d+\.\d+\.\d+) — ", changelog, flags=re.MULTILINE)
    assert headings, "CHANGELOG 里没找到 `## x.y.z — ` 形式的版本标题"
    assert version == headings[0]
