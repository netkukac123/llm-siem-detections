"""Scenario-level view and scenario-clustered bootstrap for the main proportions (review response).

Runs of the same scenario share attack text, so they are not independent. This resamples scenarios
(with all their runs) instead of runs, and reports per-scenario counts, so that a reader can see how
many distinct attacks a number rests on.

    python -m research.cluster_stats   # -> research/results/cluster_stats.json
"""
from __future__ import annotations

import json
import random
from collections import defaultdict
from pathlib import Path

from .common import RESULTS, run_rules, wilson, write_json

OC = {"LLMD-003", "LLMD-004", "LLMD-005", "LLMD-018"}
BEH = {"LLMD-006", "LLMD-007", "LLMD-008", "LLMD-013", "LLMD-016", "LLMD-017", "LLMD-019", "LLMD-020"}
INPUT = {"LLMD-001", "LLMD-002", "LLMD-010", "LLMD-011", "LLMD-012", "LLMD-014", "LLMD-015", "LLMD-021"}
B = 10000


def cluster_ci(groups: dict[str, list[bool]], seed: int = 7) -> list[float]:
    keys = sorted(groups)
    rng = random.Random(seed)
    est = []
    for _ in range(B):
        pick = [rng.choice(keys) for _ in keys]
        num = sum(sum(groups[k]) for k in pick)
        den = sum(len(groups[k]) for k in pick)
        est.append(num / den if den else float("nan"))
    est.sort()
    tot = sum(sum(v) for v in groups.values()) / sum(len(v) for v in groups.values())
    return [tot, est[int(0.025 * B)], est[int(0.975 * B) - 1]]


def rq1() -> dict:
    s = json.loads((RESULTS / "rq1" / "per_run.json").read_text())
    att = [r for r in s if not r["benign"] and not r["error"] and not r["model"].startswith("anthropic:")]
    out = {}
    # three different detection questions, kept apart
    for name, sel, rules in (("attempt_seen_by_input_rules", att, INPUT),
                             ("compromise_seen_by_output_rules", [r for r in att if r["complied"]], OC | BEH),
                             ("harm_seen_by_output_rules", [r for r in att if r["success"]], OC | BEH)):
        g = defaultdict(list)
        for r in sel:
            g[r["scenario"][:3]].append(bool(set(r["rules_fired"]) & rules))
        out[name] = {"n_runs": len(sel), "n_scenarios": len(g),
                     "per_scenario": {k: [sum(v), len(v)] for k, v in sorted(g.items())},
                     "wilson_runs": wilson(sum(sum(v) for v in g.values()), len(sel)),
                     "cluster_bootstrap": cluster_ci(g)}
    return out


def rq5c() -> dict:
    recs = []
    for p in sorted((RESULTS / "rq5c").glob("runs_*.jsonl")):
        recs += [json.loads(line) for line in p.open()]
    recs = [r for r in recs if not r.get("error")]
    events = [{k: v for k, v in e.items() if k not in ("run_id", "session_label")} for r in recs for e in r["events"]]
    fl = run_rules(events, key="session_id")
    sess = {e["session_id"]: r["run_id"] for r in recs for e in r["events"]}
    hits = defaultdict(set)
    for rid, ss in fl.items():
        for x in ss:
            if x in sess:
                hits[sess[x]].add(rid)
    prov = lambda r: any(e["event_type"] == "refusal" and e.get("refusal_source") == "provider" for e in r["events"])
    out = {}
    att = [r for r in recs if not r["benign"]]
    for name, f in (("action_only", lambda r: bool(hits[r["run_id"]] & (OC | BEH))),
                    ("action_plus_refusal", lambda r: bool(hits[r["run_id"]] & (OC | BEH | {"LLMD-023"})) or prov(r))):
        g = defaultdict(list)
        for r in att:
            g[r["scenario"][:3]].append(f(r))
        out[name] = {"n_runs": len(att), "per_scenario": {k: [sum(v), len(v)] for k, v in sorted(g.items())},
                     "wilson_runs": wilson(sum(map(f, att)), len(att)), "cluster_bootstrap": cluster_ci(g)}
    ben = [r for r in recs if r["benign"]]
    sig = lambda r: bool(hits[r["run_id"]] & {"LLMD-023"}) or prov(r)
    out["benign_refusal_signal"] = {"n": len(ben), "k": sum(map(sig, ben)), "wilson": wilson(sum(map(sig, ben)), len(ben))}
    return out


def main() -> None:
    res = {"rq1_non_frontier": rq1(), "rq5c": rq5c()}
    write_json(RESULTS / "cluster_stats.json", res)
    f = lambda x: f"{x[0]:.2f} [{x[1]:.2f}, {x[2]:.2f}]"
    for k, d in res["rq1_non_frontier"].items():
        print("RQ1", k, d["n_runs"], "runs", d["n_scenarios"], "scen", "wilson", f(d["wilson_runs"]),
              "cluster", f(d["cluster_bootstrap"]), d["per_scenario"])
    for k, d in res["rq5c"].items():
        if "cluster_bootstrap" in d:
            print("RQ5C", k, "wilson", f(d["wilson_runs"]), "cluster", f(d["cluster_bootstrap"]), d["per_scenario"])
        else:
            print("RQ5C", k, d)


if __name__ == "__main__":
    main()
