"""Run every analytic rule query against a live Log Analytics workspace and
compare the hits with the ground truth, exactly like tests/test_kql_rules.py
does on Kustainer.

    az login
    python deploy/sentinel/verify_live.py <workspace-customer-id> [--timespan P2D]

Use after `ingest.py datasets/sample.jsonl --shift-to-now`. Session IDs survive
ingestion, so the labels in datasets/labels.json apply unchanged. Uses the az
CLI, so no extra Python packages are needed.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.groundtruth import RULE_IDS, describe, expectation  # noqa: E402
from tests.kusto import rule_query  # noqa: E402


def run(workspace: str, query: str, timespan: str) -> list[dict]:
    res = subprocess.run(["az", "monitor", "log-analytics", "query", "-w", workspace,
                          "--analytics-query", query, "--timespan", timespan, "-o", "json"],
                         capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip()[-800:])
    return json.loads(res.stdout)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("workspace", help="workspace customer ID (GUID)")
    p.add_argument("--timespan", default="P2D")
    args = p.parse_args()

    total = run(args.workspace, "LLMAppLogs_CL | count", args.timespan)
    print(f"LLMAppLogs_CL rows in window: {total[0]['Count']}")

    failures = 0
    for path in sorted((ROOT / "detections" / "sentinel").glob("LLMD-*.yaml")):
        rule_id = path.name[:8]
        rows = run(args.workspace, rule_query(path), args.timespan)
        exp = expectation(rule_id)
        if rows and "session_id" in rows[0]:
            hits, want = {r["session_id"] for r in rows}, set(exp.sessions)
            missed, extra = describe(want - hits), describe(hits - want)
        else:
            hits, want = {r["user_id"] for r in rows}, set(exp.users)
            missed, extra = sorted(want - hits), sorted(hits - want)
        ok = not missed and not extra
        failures += not ok
        print(f"{'OK  ' if ok else 'FAIL'} {rule_id}  rows={len(rows):3d}"
              + (f"  missed={missed}" if missed else "") + (f"  extra={extra}" if extra else ""))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
