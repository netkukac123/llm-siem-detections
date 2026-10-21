"""RQ5 coverage analysis over the live runs in research/results/rq1/runs/.

Three strands from the pre-registration:
  A  refusal telemetry: LLMD-023 makes refused (and therefore action-invisible) attacks visible and
     attributes them to the poisoned source. Reported as the coverage gain over action-only rules.
  B  capability-conditioned detectability: among runs where the attack completed, recall of the
     content-signature rule family vs the behavioural/provenance family, per capability tier.
  C  reasoning-trace rules: LLMD-024 recall among compliant runs, split by raw chain of thought and
     summary (only where a reasoning trace was logged).

    python -m research.rq5_coverage        # -> research/results/rq5/summary.json
"""
from __future__ import annotations

import json
from collections import defaultdict

from .common import RESULTS, manifest, run_rules, wilson, write_json
from .live_scenarios import live_scenarios

OUT = RESULTS / "rq5"
RUNS = RESULTS / "rq1" / "runs"

# Rule families. Content rules match on the text of an action, a document, or a tool result; they
# are the ones expected to decay as a model learns to paraphrase or re-encode. Behavioural rules
# match on the shape of what happened (external content then egress, private read then egress,
# destructive action without approval) regardless of wording.
CONTENT = {"LLMD-001", "LLMD-002", "LLMD-003", "LLMD-004", "LLMD-005", "LLMD-011", "LLMD-012",
           "LLMD-018", "LLMD-021"}
BEHAVIOURAL = {"LLMD-006", "LLMD-007", "LLMD-008", "LLMD-013", "LLMD-014", "LLMD-015", "LLMD-016",
               "LLMD-017", "LLMD-019", "LLMD-020"}
REFUSAL = {"LLMD-023"}
REASONING = {"LLMD-024"}
ACTION = CONTENT | BEHAVIOURAL  # everything a tool-call-only SIEM would have


def tier_of(model: str) -> str:
    if model.startswith("anthropic:"):
        return "frontier"
    if model.startswith("azure:"):
        return "mid"
    return "open-8b"


def load_runs() -> list[dict]:
    latest: dict[str, dict] = {}
    for p in sorted(RUNS.glob("*.jsonl")):
        for line in p.open():
            r = json.loads(line)
            latest[r["run_id"]] = r
    return list(latest.values())


def rule_hits_per_run(records: list[dict]) -> dict[str, set[str]]:
    events = [{k: v for k, v in e.items() if k not in ("run_id", "session_label")}
              for r in records for e in r["events"]]
    flagged = run_rules(events, key="session_id")
    session_run = {e["session_id"]: r["run_id"] for r in records for e in r["events"]}
    hits: dict[str, set[str]] = defaultdict(set)
    for rid, sessions in flagged.items():
        for s in sessions:
            if s in session_run:
                hits[session_run[s]].add(rid)
    return hits


def reasoning_kind_of(rec: dict) -> str | None:
    kinds = {e.get("reasoning_kind") for e in rec["events"] if e["event_type"] == "reasoning"}
    kinds.discard(None)
    kinds.discard("")
    if not kinds:
        return None
    return "summary" if "summary" in kinds else "raw"


def frac(hit: int, n: int) -> dict | None:
    return wilson(hit, n) if n else None


def main() -> None:
    records = load_runs()
    hits = rule_hits_per_run(records)
    for r in records:
        r["_hits"] = hits.get(r["run_id"], set())

    # Per-model, then aggregated per tier.
    by_model = {}
    models = sorted({r["model"] for r in records})
    for m in models + sorted({tier_of(r["model"]) for r in records}, key=lambda t: f"~{t}"):
        is_tier = m in ("open-8b", "mid", "frontier")
        rows = [r for r in records if (tier_of(r["model"]) == m if is_tier else r["model"] == m)
                and not r.get("error")]
        att = [r for r in rows if not r["benign"]]
        ben = [r for r in rows if r["benign"]]
        comp = [r for r in att if r["complied"]]
        succ = [r for r in att if r["success"]]
        resisted = [r for r in att if not r["complied"]]

        def fired(run, fam):
            return bool(run["_hits"] & fam)

        # held-out variant: drop Haiku rep-0, the pilot cell the detector patterns were tuned on
        ho = [r for r in att if not (r["model"] == "anthropic:claude-haiku-4-5" and r["rep"] == 0)]
        ho_res = [r for r in ho if not r["complied"]]

        by_model[m] = {
            "is_tier": is_tier, "n_attack": len(att), "n_benign": len(ben),
            "compliance": frac(len(comp), len(att)),
            "asr": frac(len(succ), len(att)),
            # B: detectability among completed attacks, by family
            "content_given_success": frac(sum(fired(r, CONTENT) for r in succ), len(succ)),
            "behavioural_given_success": frac(sum(fired(r, BEHAVIOURAL) for r in succ), len(succ)),
            "content_given_compliance": frac(sum(fired(r, CONTENT) for r in comp), len(comp)),
            "behavioural_given_compliance": frac(sum(fired(r, BEHAVIOURAL) for r in comp), len(comp)),
            # A: refusal coverage of the resisted attacks that action rules miss
            "resisted_n": len(resisted),
            "resisted_visible_action_only": frac(sum(fired(r, ACTION) for r in resisted), len(resisted)),
            "resisted_visible_with_refusal": frac(sum(fired(r, ACTION | REFUSAL) for r in resisted), len(resisted)),
            "refusal_recall_on_resisted": frac(sum(fired(r, REFUSAL) for r in resisted), len(resisted)),
            "refusal_recall_held_out": frac(sum(fired(r, REFUSAL) for r in ho_res), len(ho_res)),
            # whole-attack recall gain from adding the refusal rule
            "attack_recall_action_only": frac(sum(fired(r, ACTION) for r in att), len(att)),
            "attack_recall_with_refusal": frac(sum(fired(r, ACTION | REFUSAL) for r in att), len(att)),
            # A attribution: a refusal alert that names a source (the only external source in an
            # attack session is the poisoned one)
            "refusal_attributed": frac(sum(1 for r in resisted if fired(r, REFUSAL)),
                                       sum(fired(r, REFUSAL) for r in resisted)),
            # A false positives on benign
            "benign_refusal_fp": frac(sum(fired(r, REFUSAL) for r in ben), len(ben)),
            "benign_content_fp": frac(sum(fired(r, CONTENT) for r in ben), len(ben)),
            "benign_behavioural_fp": frac(sum(fired(r, BEHAVIOURAL) for r in ben), len(ben)),
            "benign_reasoning_fp": frac(sum(fired(r, REASONING) for r in ben), len(ben)),
        }

        # C: reasoning rule, only over runs that logged a reasoning trace
        comp_r = [r for r in comp if reasoning_kind_of(r)]
        for kind in ("raw", "summary"):
            sub = [r for r in comp if reasoning_kind_of(r) == kind]
            by_model[m][f"reasoning_recall_{kind}"] = frac(sum(fired(r, REASONING) for r in sub), len(sub))
        by_model[m]["reasoning_recall_any"] = frac(sum(fired(r, REASONING) for r in comp_r), len(comp_r))
        by_model[m]["reasoning_adds_over_behavioural"] = frac(
            sum(1 for r in comp_r if fired(r, REASONING) and not fired(r, BEHAVIOURAL)), len(comp_r))

    write_json(OUT / "summary.json", {"by_model": by_model} | manifest(
        families={"content": sorted(CONTENT), "behavioural": sorted(BEHAVIOURAL),
                  "refusal": sorted(REFUSAL), "reasoning": sorted(REASONING)}))
    # compact console view
    order = [m for m in models] + ["open-8b", "mid", "frontier"]
    for m in order:
        if m not in by_model:
            continue
        d = by_model[m]
        def s(x):
            return f"{x[0]:.2f}" if x else "  . "
        print(f"{m:34s} n={d['n_attack']:3d} comp={s(d['compliance'])} asr={s(d['asr'])} "
              f"content|succ={s(d['content_given_success'])} behav|succ={s(d['behavioural_given_success'])} "
              f"refusal|resisted={s(d['refusal_recall_on_resisted'])} benFP_ref={s(d['benign_refusal_fp'])}")


if __name__ == "__main__":
    main()
