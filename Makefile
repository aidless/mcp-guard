# --- acceptance_backfill (EVAL_ACCEPTANCE_STANDARD.md P4) ---
# 证据来源: ci.yml
# 命令逐字取自该来源，未增删任何参数。
# 归一: python → python3（本机无 python 别名，实测 Error 127）
# 追加行（2026-11-13）: 先跑本仓验收题库 eval/run_cases.py（20 条真调 API 的题），
# 再跑既有 pytest 套件；两段任一非零则 `make eval` 非零。
.PHONY: eval

eval:
	python3 eval/run_cases.py
	python3 -m pytest tests/ -q
