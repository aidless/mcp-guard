#!/usr/bin/env python3
"""mutation_control.py — 证明 CI 门禁真的有牙（而不是"失败被吞掉"）。

背景：一条绿色的 CI 运行无法区分"门禁通过"和"门禁把错误吞了"——两者退出码都是 0。
唯一能分开它们的方法，是故意把代码改坏，然后断言门禁**必须**变红。

这个脚本做三件事：
  1. 基线：干净树上 `pytest tests/ -q` 必须为 0（否则拒绝在一个已经红的门禁上做变异测试）。
  2. 变异：注入一个必然失败的测试文件，断言 pytest **必须**非零退出，且输出里点名了
     注入的用例名（否则它是因为别的原因失败，这次运行什么都没证明）。
  3. 负对照：模拟"吞错误"的门禁形态（`pytest ... || echo "skipping"`），断言它会返回 0，
     因此会被同一套判决规则判为"没有牙"。

全程只改本地工作树，且在 finally 里恢复；跑完必须回到干净状态。

用法：
    python3 scripts/mutation_control.py [--repo .] [--allow-dirty]

退出码：0 = 门禁有牙（全部断言通过）；1 = 断言失败。
"""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

PROBE_PATH = "tests/test_mutation_control_probe.py"
PROBE_TEST_NAME = "test_mutation_control_probe_must_fail"

PROBE_SOURCE = f'''"""Injected by scripts/mutation_control.py -- must fail on purpose."""


def {PROBE_TEST_NAME}():
    assert "mutation-control-introduced-failure" == "the-unmutated-value"
'''


def _run_pytest(repo: pathlib.Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _git_clean(repo: pathlib.Path) -> tuple[bool, str]:
    proc = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    return proc.stdout.strip() == "", proc.stdout.strip()


def _verdict(rc: int, output: str) -> tuple[bool, str]:
    """判决规则：非零退出 **且** 点名了注入的用例，才算"门禁因正确的理由变红"。"""
    if rc == 0:
        return False, "gate exited 0 with a failing test in tests/ -- the gate has no teeth"
    if PROBE_TEST_NAME not in output:
        return False, "gate exited non-zero but did not name the injected test -- wrong failure"
    return True, f"gate exited {rc} and named the injected test"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(pathlib.Path(__file__).resolve().parents[1]))
    ap.add_argument(
        "--allow-dirty",
        action="store_true",
        help="跳过『干净树』前置检查（本地迭代用；CI 必须用默认严格模式）",
    )
    args = ap.parse_args()
    repo = pathlib.Path(args.repo).resolve()

    ok = True

    print("[0] pristine tree check")
    clean, dirty = _git_clean(repo)
    initial_status = dirty
    if not clean:
        if args.allow_dirty:
            print(f"  [WARN] working tree is not clean (allowed by --allow-dirty):\n{dirty}")
        else:
            print(f"  [FAIL] working tree is not clean:\n{dirty}")
            return 1
    else:
        print("  [PASS] tree is pristine")

    print("\n[1] baseline (must pass, else stop)")
    rc, out = _run_pytest(repo)
    if rc != 0:
        print("  [FAIL] baseline is red -- refusing to mutation-test an already-failing gate")
        print(out[-800:])
        return 1
    print("  [PASS] baseline green")

    probe = repo / PROBE_PATH
    try:
        print("\n[2] inject failing test")
        probe.write_text(PROBE_SOURCE, encoding="utf-8")
        print(f"  injected {PROBE_PATH}")

        print("\n[3] mutated run (must be red)")
        rc_mut, out_mut = _run_pytest(repo)
        good, why = _verdict(rc_mut, out_mut)
        print(f"  [{'PASS' if good else 'FAIL'}] {why}")
        if not good:
            ok = False

        print("\n[4] negative control (swallowing gate must be rejected)")
        # `pytest ... || echo "skipping"` 的退出码恒为 0 —— 这里在 Python 里复刻该形态，
        # 不用 shell，避免把命令串接注入的风险带进来。
        swallow_rc = 0
        swallow_ok, _ = _verdict(swallow_rc, out_mut)
        if swallow_ok:
            print("  [FAIL] the swallowing gate was accepted -- the assertion is vacuous")
            ok = False
        else:
            print("  [PASS] swallowing gate (exit 0) correctly rejected as 'no teeth'")
    finally:
        print("\n[5] restore")
        if probe.exists():
            probe.unlink()
        for cache in repo.rglob("__pycache__"):
            if cache.is_dir():
                for f in cache.iterdir():
                    if f.name.endswith(".pyc"):
                        f.unlink()
        clean, dirty = _git_clean(repo)
        if dirty == initial_status:
            print("  [PASS] tree restored to its initial state")
        else:
            print(f"  [FAIL] tree differs from its initial state after restore:\n{dirty}")
            ok = False

    print("\n" + "=" * 60)
    print("OVERALL:", "PASS" if ok else "FAIL")
    print("=" * 60)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
