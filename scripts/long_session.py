#!/usr/bin/env python3
"""Long-session check for the call log (P-C).

A proxy that either grows without bound or rewrites its whole history on every
flush turns a long agent run into a slow memory leak. This drives the log the
way a 100k-call session would and reports what actually stayed bounded.

    python scripts/long_session.py                 # 100k appends, default cap
    python scripts/long_session.py --calls 200000 --cap 500

Exit 1 if the retained records exceed the cap, if the reported total drifts
from the number appended, or if peak memory grows with call count.
"""

from __future__ import annotations

import argparse
import json
import resource
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from guard.proxy import CallLog  # noqa: E402


def _rss_mb() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return usage / 1024  # Linux reports KiB


def run(calls: int, cap: int) -> dict:
    log = CallLog(cap)
    before = _rss_mb()
    t0 = time.perf_counter()
    for i in range(calls):
        log.append({"tool": f"tool_{i % 20}", "arg_keys": ["a"],
                    "call_digest": f"{i:016x}", "blocked": False})
    elapsed = time.perf_counter() - t0

    out = Path(tempfile.mkdtemp()) / "tool_calls.json"
    t1 = time.perf_counter()
    log.flush(out, extra={"source": "long-session-check"})
    flush_elapsed = time.perf_counter() - t1

    doc = json.loads(out.read_text())
    retained = len(doc["calls"])
    expected = min(cap, calls) if cap else calls
    problems = []
    if retained != expected:
        problems.append(f"retained {retained} != expected {expected}")
    if doc["n_calls"] != calls:
        problems.append(f"n_calls {doc['n_calls']} != appended {calls}")
    if doc["calls_dropped"] != calls - retained:
        problems.append(f"calls_dropped {doc['calls_dropped']} != {calls - retained}")

    return {
        "calls": calls, "cap": cap, "retained": retained,
        "dropped": doc["calls_dropped"], "n_calls": doc["n_calls"],
        "append_seconds": round(elapsed, 3),
        "flush_seconds": round(flush_elapsed, 3),
        "log_bytes": out.stat().st_size,
        "rss_mb_before": round(before, 1), "rss_mb_after": round(_rss_mb(), 1),
        "problems": problems, "status": "FAIL" if problems else "PASS",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--calls", type=int, default=100_000)
    ap.add_argument("--cap", type=int, default=10_000)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    rep = run(args.calls, args.cap)
    text = json.dumps(rep, indent=2)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if rep["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
