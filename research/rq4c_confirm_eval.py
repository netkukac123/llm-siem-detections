"""Evaluate the RQ4c confirmation run against K1-K5 (docs/research/prereg-rq4c-addendum-confirmation.md).
Uses confirm_runs.jsonl only; exploration runs are excluded by design.

    python -m research.rq4c_confirm_eval
"""
from __future__ import annotations

import json
from collections import defaultdict

from .common import RESULTS, manifest, run_rules, wilson, write_json

OUT = RESULTS / "rq4c"
PRE_EXISTING = {f"LLMD-{i:03d}" for i in range(1, 25)}


def hits_by_run(recs: list[dict]) -> dict[str, set[str]]:
    events = [{k: v for k, v in e.items() if k not in ("run_id", "session_label")} for r in recs for e in r["events"]]
    flagged = run_rules(events, key="session_id")
    sess = {e["session_id"]: r["run_id"] for r in recs for e in r["events"]}
    hits = defaultdict(set)
    for rid, ss in flagged.items():
        for s in ss:
            if s in sess:
                hits[sess[s]].add(rid)
    return hits


def provider_refused(r: dict) -> bool:
    return any(e["event_type"] == "refusal" and e.get("refusal_source") == "provider" for e in r["events"])


def main() -> None:
    recs = [r for r in map(json.loads, (OUT / "confirm_runs.jsonl").open()) if not r.get("error")]
    hits = hits_by_run(recs)
    rows = {}
    for r in recs:
        r["_h"] = hits.get(r["run_id"], set())
    groups = defaultdict(list)
    for r in recs:
        groups[(r["model"], r["variant"])].append(r)
    for (m, v), rs in sorted(groups.items()):
        harm = [r for r in rs if r["success"]]
        rows[f"{m} {v}"] = {
            "n": len(rs),
            "compliance": wilson(sum(bool(r["complied"]) for r in rs), len(rs)),
            "harm": wilson(len(harm), len(rs)),
            "provider_refusal": wilson(sum(provider_refused(r) for r in rs), len(rs)),
            "any_pre_existing_rule": wilson(sum(bool(r["_h"] & PRE_EXISTING) for r in rs), len(rs)),
            "pre_existing_rules_fired": sorted({h for r in rs for h in r["_h"] & PRE_EXISTING}),
            "LLMD-021": wilson(sum("LLMD-021" in r["_h"] for r in rs), len(rs)),
            "LLMD-023": wilson(sum("LLMD-023" in r["_h"] for r in rs), len(rs)),
            "LLMD-025": wilson(sum("LLMD-025" in r["_h"] for r in rs), len(rs)),
            "any_rule_incl_025": wilson(sum(bool(r["_h"]) for r in rs), len(rs)),
            "harm_LLMD-021": wilson(sum("LLMD-021" in r["_h"] for r in harm), len(harm)) if harm else None,
            "harm_LLMD-006": wilson(sum("LLMD-006" in r["_h"] for r in harm), len(harm)) if harm else None,
            "harm_LLMD-004": wilson(sum("LLMD-004" in r["_h"] for r in harm), len(harm)) if harm else None,
        }

    # K3 false positives: LLMD-025 on the RQ5 benign workload of the three Claude models
    ben = []
    for m in ("haiku-4-5", "sonnet-5-5", "opus-5-5"):
        ben += [r for r in map(json.loads, (RESULTS / "rq1" / "runs" / f"anthropic_claude-{m}.jsonl").open())
                if r["benign"] and not r.get("error")]
    bh = hits_by_run(ben)
    k3_fp = wilson(sum("LLMD-025" in bh.get(r["run_id"], set()) for r in ben), len(ben))

    write_json(OUT / "confirm_summary.json", {"rows": rows, "K3_benign_fp_LLMD-025": k3_fp} | manifest())

    def s(x):
        return f"{x[0]:.2f}[{x[1]:.2f},{x[2]:.2f}]" if x else "   .   "
    print(f"{'model variant':40s} {'comp':16s} {'harm':16s} {'provRef':16s} {'anyOld':16s} {'L021':16s} {'L025':16s} {'anyRule':16s}")
    for k, d in rows.items():
        print(f"{k.replace('anthropic:claude-',''):40s} {s(d['compliance']):16s} {s(d['harm']):16s} {s(d['provider_refusal']):16s} "
              f"{s(d['any_pre_existing_rule']):16s} {s(d['LLMD-021']):16s} {s(d['LLMD-025']):16s} {s(d['any_rule_incl_025']):16s}")
    print(f"\nK3 LLMD-025 false-positive rate on RQ5 benign (Claude, n={len(ben)}): {s(k3_fp)}")
    for k, d in rows.items():
        if d["pre_existing_rules_fired"]:
            print(f"  {k.replace('anthropic:claude-',''):34s} pre-existing rules that fired: {d['pre_existing_rules_fired']}")


if __name__ == "__main__":
    main()
