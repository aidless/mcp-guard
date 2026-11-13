"""P-A3：静态分层 vs 运行时调用的一致性审计（scripts/capability_consistency.py）。

审计的是代理落盘产物之间的矛盾：capability_manifest.json 说工具是 T0/T1 只读，
tool_calls.json 却显示调用带了危险参数名（cmd/force/env/...）——静态评估与
实际行为不一致，rug-pull / 注解说谎的运行时信号。

TDD：先写测试（脚本不存在 → RED），实现后 GREEN；双向变异：
  - 拆机制（删 T0/T1+危险参数检查）→ RED；
  - 拆准则（unknown 不再告警）→ RED。
缺输入 fail-closed：exit 2 / NOT_ASSESSED。
"""
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "capability_consistency.py"


def _make_log(tmp_path: Path, capabilities: list[dict], calls: list[dict],
              raw_args: bool = False) -> Path:
    log = tmp_path / "run"
    log.mkdir()
    (log / "capability_manifest.json").write_text(json.dumps({
        "source": "proxy",
        "summary": {},
        "tools": capabilities,
    }, ensure_ascii=False), encoding="utf-8")
    record = {"source": "proxy", "n_calls": len(calls),
              "args_policy": "raw" if raw_args else "digest-only",
              "calls": calls}
    (log / "tool_calls.json").write_text(json.dumps(record, ensure_ascii=False),
                                         encoding="utf-8")
    return log


def _run(log: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), "--log-dir", str(log)],
                          capture_output=True, text=True)


def _read_report(log: Path) -> dict:
    return json.loads((log / "consistency_report.json").read_text(encoding="utf-8"))


def test_read_only_tier_with_dangerous_param_alarms(tmp_path):
    """T0 只读工具 + 调用带 cmd 参数 → 告警（静态说只读，运行时在执行）。"""
    log = _make_log(
        tmp_path,
        capabilities=[{"name": "weather_lookup", "tier": "T0_read", "unknown": False,
                       "n_hits": 0, "rules": []}],
        calls=[{"seq": 0, "tool": "weather_lookup", "arg_keys": ["city", "cmd"],
                "call_digest": "x", "blocked": False}])
    r = _run(log)
    assert r.returncode == 1, r.stderr
    report = _read_report(log)
    kinds = [a["kind"] for a in report["alarms"]]
    assert "read-only-tier-with-dangerous-param" in kinds
    alarm = next(a for a in report["alarms"]
                 if a["kind"] == "read-only-tier-with-dangerous-param")
    assert alarm["tool"] == "weather_lookup"
    assert alarm["params"] == ["cmd"]


def test_tier_consistent_no_alarm(tmp_path):
    """T3 工具 + 危险参数 = 静动一致，不告警。"""
    log = _make_log(
        tmp_path,
        capabilities=[{"name": "shell_exec", "tier": "T3_destructive_or_exec",
                       "unknown": False, "n_hits": 2, "rules": []}],
        calls=[{"seq": 0, "tool": "shell_exec", "arg_keys": ["cmd"],
                "call_digest": "x", "blocked": False}])
    r = _run(log)
    assert r.returncode == 0, r.stderr
    assert _read_report(log)["alarms"] == []


def test_unknown_tier_with_dangerous_param_alarms(tmp_path):
    """unknown 不冒充只读：unknown + 危险参数也要告警（fail-closed）。"""
    log = _make_log(
        tmp_path,
        capabilities=[{"name": "mystery_tool", "tier": "unknown", "unknown": True,
                       "n_hits": 0, "rules": []}],
        calls=[{"seq": 0, "tool": "mystery_tool", "arg_keys": ["force"],
                "call_digest": "x", "blocked": False}])
    r = _run(log)
    assert r.returncode == 1
    kinds = [a["kind"] for a in _read_report(log)["alarms"]]
    assert "unknown-tier-with-dangerous-param" in kinds


def test_called_tool_missing_from_manifest_alarms(tmp_path):
    """调用了 manifest 里没有的工具（tools/list 之后才出现的面）→ 告警。"""
    log = _make_log(
        tmp_path,
        capabilities=[{"name": "known_tool", "tier": "T0_read", "unknown": False,
                       "n_hits": 0, "rules": []}],
        calls=[{"seq": 0, "tool": "ghost_tool", "arg_keys": [],
                "call_digest": "x", "blocked": False}])
    r = _run(log)
    assert r.returncode == 1
    kinds = [a["kind"] for a in _read_report(log)["alarms"]]
    assert "called-tool-not-in-manifest" in kinds


def test_raw_batch_hides_destructive_inner_tool(tmp_path):
    """raw args 模式下：T0 工具的 batch 载荷内层是 T3 → 告警并点名内层工具。"""
    log = _make_log(
        tmp_path,
        capabilities=[{"name": "bulk_run", "tier": "T0_read", "unknown": False,
                       "n_hits": 0, "rules": []}],
        calls=[{"seq": 0, "tool": "bulk_run",
                "arg_keys": ["commands_json"], "call_digest": "x", "blocked": False,
                "args": {"commands_json": json.dumps([
                    {"tool": "delete_files", "args": {"path": "/tmp/x"}}])}},
               ],
        raw_args=True)
    r = _run(log)
    assert r.returncode == 1
    kinds = [a["kind"] for a in _read_report(log)["alarms"]]
    assert "read-only-tier-hides-destructive-batch" in kinds
    alarm = next(a for a in _read_report(log)["alarms"]
                 if a["kind"] == "read-only-tier-hides-destructive-batch")
    assert alarm["inner_tool"] == "delete_files"


def test_missing_manifest_fail_closed(tmp_path):
    """capability_manifest 缺失 → exit 2 NOT_ASSESSED，不静默绿。"""
    log = tmp_path / "run2"
    log.mkdir()
    (log / "tool_calls.json").write_text(json.dumps(
        {"calls": []}, ensure_ascii=False), encoding="utf-8")
    r = _run(log)
    assert r.returncode == 2
    report = _read_report(log)
    assert report["status"] == "NOT_ASSESSED"


def test_clean_run_exit_zero(tmp_path):
    """全一致 → exit 0，report 带 checked 计数。"""
    log = _make_log(
        tmp_path,
        capabilities=[{"name": "get_weather", "tier": "T0_read", "unknown": False,
                       "n_hits": 0, "rules": []}],
        calls=[{"seq": 0, "tool": "get_weather", "arg_keys": ["city"],
                "call_digest": "x", "blocked": False}])
    r = _run(log)
    assert r.returncode == 0
    report = _read_report(log)
    assert report["status"] == "ok"
    assert report["checked"] == 1
