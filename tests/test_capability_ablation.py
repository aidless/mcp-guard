"""P-B2：能力层消融报告（scripts/capability_ablation.py）。

回答「能力轴的每一块证据各自贡献了多少」：对同一工具集，依次关闭
NAME_TIERS / DANGEROUS_PARAMS / 枚举感知 / batch 解包四块证据，数多少工具
的分层因此改变。类似投毒侧的 measure_rule_ablation，但对象是能力分层。

TDD：先写测试（脚本不存在 → RED）。变异方向：
  - 拆机制（跳过某一轴的 patch）→ 该轴 changed 恒 0 → RED；
  - 拆准则（restore 后不复检基线）→ restored_check 缺失 → RED。
"""
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "capability_ablation.py"

TOOLS = [
    # 名字证据 → T3
    {"name": "delete_files", "description": "Manage file cleanup tasks."},
    # 只读描述证据 → T0
    {"name": "fetch_page", "description": "Fetch the cached page snapshot."},
    # 危险参数证据（cmd）→ T3
    {"name": "deploy_agent", "description": "Deploy the configured build target.",
     "inputSchema": {"type": "object",
                     "properties": {"cmd": {"type": "string"}}}},
    # 枚举感知：command 静态 T2，closed enum 全温和值 → 软化为温和层
    {"name": "task_runner", "description": "Organize the saved task board.",
     "inputSchema": {"type": "object",
                     "properties": {"command": {"type": "string",
                                                "enum": ["list", "show"]}}}},
    # batch 解包：commands_json 默认值内层 delete_files → T3
    {"name": "bulk_run", "description": "Read the checklist settings.",
     "inputSchema": {"type": "object",
                     "properties": {"commands_json": {
                         "type": "string",
                         "default": json.dumps([
                             {"tool": "delete_files", "args": {}}])}}}},
]

EXPECTED_AXES = {"no-name-tiers", "no-dangerous-params",
                 "no-enum-awareness", "no-batch-unwrapping"}


def _make_tools(tmp_path: Path) -> Path:
    path = tmp_path / "tools.json"
    path.write_text(json.dumps(TOOLS, ensure_ascii=False), encoding="utf-8")
    return path


def _run(tools: Path, out: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), "--tools", str(tools),
                           "--out", str(out)],
                          capture_output=True, text=True)


def test_ablation_axes_change_expected_tools(tmp_path):
    """四轴全跑：每轴按预期改变对应工具的分层。"""
    tools = _make_tools(tmp_path)
    out = tmp_path / "ablation.json"
    r = _run(tools, out)
    assert r.returncode == 0, r.stderr
    report = json.loads(out.read_text(encoding="utf-8"))

    assert EXPECTED_AXES <= set(report["ablations"])
    ab = report["ablations"]
    # 名字证据关掉 → delete_files 不再由名字保 T3
    names = {e["name"] for e in ab["no-name-tiers"]["examples"]}
    assert "delete_files" in names
    assert ab["no-name-tiers"]["changed"] >= 1
    # 危险参数关掉 → deploy_agent 失去 cmd 证据
    names = {e["name"] for e in ab["no-dangerous-params"]["examples"]}
    assert "deploy_agent" in names
    # 枚举感知关掉 → task_runner 的 command 回到静态 T2（枚举软化消失）
    names = {e["name"] for e in ab["no-enum-awareness"]["examples"]}
    assert "task_runner" in names
    # batch 解包关掉 → bulk_run 的内层 T3 证据消失
    names = {e["name"] for e in ab["no-batch-unwrapping"]["examples"]}
    assert "bulk_run" in names

    # 基线分布与 restore 复检
    assert report["baseline"]["delete_files"] == "T3_destructive_or_exec"
    assert report["baseline"]["task_runner"] == "T0_read"
    assert report["restored_check"] is True


def test_missing_input_fail_closed(tmp_path):
    """输入缺失 → exit 2 NOT_ASSESSED，不静默绿。"""
    out = tmp_path / "ablation.json"
    r = subprocess.run([sys.executable, str(SCRIPT), "--tools",
                        str(tmp_path / "nope.json"), "--out", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 2
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["status"] == "NOT_ASSESSED"
