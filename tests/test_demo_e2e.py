"""R3: demo.sh 全链路 e2e —— 一条命令演示六条腿（静态扫描/漂移/stdio 观测/
stdio 阻断/HTTP 门禁/一致性审计），全部真实子进程，任何一腿失败 demo 必须退出非零。

RED 先行：demo.sh 不存在或任何腿断言失败 → 本测试红。
"""
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEMO = REPO / "demo.sh"

# 各腿必须出现在 demo 输出里的标记（腿级自证）
EXPECTED_MARKERS = [
    "[L1] static scan",
    "[L2] drift pin",
    "[L3] stdio observe",
    "[L4] stdio block",
    "[L5] http gate",
    "[L6] consistency audit",
    "ALL LEGS PASSED",
]


def test_demo_full_chain_green():
    assert DEMO.exists(), "demo.sh missing"
    out = subprocess.run(["bash", str(DEMO)], capture_output=True, text=True,
                         cwd=REPO, timeout=180)
    assert out.returncode == 0, (
        f"demo.sh failed (exit {out.returncode})\nstdout:\n{out.stdout[-3000:]}\n"
        f"stderr:\n{out.stderr[-2000:]}"
    )
    for marker in EXPECTED_MARKERS:
        assert marker in out.stdout, f"missing marker {marker!r}\n{out.stdout[-2000:]}"
