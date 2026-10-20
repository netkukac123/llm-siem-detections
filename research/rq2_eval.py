"""RQ2: the text-based rules on public datasets, run unchanged on Kustainer.

    python -m research.rq2_eval

Surfaces: prompt items -> `prompt` events (LLMD-001/011/012), documents -> `retrieval`
events (LLMD-002) and tool results (LLMD-021), MCP tool descriptions -> `tool_registry`
events (LLMD-015). Writes per-item predictions (reused by RQ3) and a summary with
bootstrap intervals.
"""
from __future__ import annotations

import hashlib
import json
import random
from collections import defaultdict

from .common import RESULTS, ROOT, bootstrap_ci, confusion, manifest, run_rules, wilson, write_json

ITEMS = ROOT / "research" / "data" / "rq2_items.jsonl"
OUT = RESULTS / "rq2"
SURFACE_RULES = {"prompt": ["LLMD-001", "LLMD-011", "LLMD-012"], "document": ["LLMD-002", "LLMD-021"],
                 "tool_description": ["LLMD-015"]}
TS = "2026-10-20T00:00:00.000Z"


def _base(item_id: str, event_type: str) -> dict:
    return {"TimeGenerated": TS, "app_name": "rq2", "event_type": event_type, "request_id": item_id,
            "session_id": item_id, "user_id": "rq2", "src_ip": "10.0.0.1", "model": "n/a"}


def events_for(item: dict) -> list[dict]:
    iid, text = item["item_id"], item["text"]
    if item["kind"] == "prompt":
        return [_base(iid, "prompt") | {"prompt": text, "prompt_chars": len(text)}]
    if item["kind"] == "document":
        return [_base(iid, "retrieval") | {"doc_id": iid, "doc_source": "external-upload", "chunk_text": text},
                _base(f"{iid}|tool", "tool_call") | {"tool_name": "read_file", "tool_target": "doc.txt",
                                                      "tool_status": "ok", "tool_risk": "read",
                                                      "tool_args": "{}", "tool_result": text}]
    return [_base(iid, "tool_registry") | {"mcp_server": "rq2", "tool_name": "t", "tool_key": iid,
                                           "tool_desc_sha256": hashlib.sha256(text.encode()).hexdigest(),
                                           "tool_description": text}]


def main() -> None:
    items = [json.loads(l) for l in ITEMS.open(encoding="utf-8")]
    rules = sorted({r for rs in SURFACE_RULES.values() for r in rs})
    flagged = run_rules((e for it in items for e in events_for(it)), rules=rules, key="request_id")

    preds = []
    for it in items:
        p = {}
        for rid in SURFACE_RULES[it["kind"]]:
            key = f"{it['item_id']}|tool" if rid == "LLMD-021" else it["item_id"]
            p[rid] = key in flagged.get(rid, set())
        p["any"] = any(p.values())
        preds.append({"item_id": it["item_id"], "dataset": it["dataset"], "kind": it["kind"],
                      "label": it["label"], "preds": p})
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "preds.jsonl").open("w", encoding="utf-8") as f:
        for p in preds:
            f.write(json.dumps(p) + "\n")

    summary = {"labelled": [], "unlabelled": [], "pooled": []}
    by_ds = defaultdict(list)
    for p in preds:
        by_ds[(p["dataset"], p["kind"])].append(p)
    for (ds, kind), ps in sorted(by_ds.items()):
        for rid in SURFACE_RULES[kind] + ["any"]:
            if ps[0]["label"] is None:
                hits = sum(x["preds"][rid] for x in ps)
                summary["unlabelled"].append({"dataset": ds, "kind": kind, "rule": rid, "n": len(ps),
                                              "alert_rate": wilson(hits, len(ps))})
                continue
            y = [bool(x["label"]) for x in ps]
            yh = [x["preds"][rid] for x in ps]
            c = confusion(y, yh)
            row = {"dataset": ds, "kind": kind, "rule": rid, "n": len(ps), "positives": sum(y),
                   "tp": c.tp, "fp": c.fp, "tn": c.tn, "fn": c.fn}
            if sum(y):
                row["recall"] = (c.recall, *bootstrap_ci(y, yh, "recall"))
            if c.tp + c.fp:
                row["precision"] = (c.precision, *bootstrap_ci(y, yh, "precision"))
            if len(y) - sum(y):
                row["fpr"] = (c.fpr, *bootstrap_ci(y, yh, "fpr"))
            summary["labelled"].append(row)

    # Pooled benign false-positive rate per surface (all label-0 items) and pooled recall.
    for kind, rids in SURFACE_RULES.items():
        ks = [p for p in preds if p["kind"] == kind and p["label"] is not None]
        for rid in rids + ["any"]:
            neg = [p["preds"][rid] for p in ks if p["label"] == 0]
            pos = [p["preds"][rid] for p in ks if p["label"] == 1]
            summary["pooled"].append({"kind": kind, "rule": rid,
                                      "benign_n": len(neg), "fpr": wilson(sum(neg), len(neg)),
                                      "attack_n": len(pos), "recall": wilson(sum(pos), len(pos))})

    # Sample alerts on unlabelled real traffic for manual review.
    rng = random.Random(7)
    unl = {p["item_id"] for p in preds if p["label"] is None and p["preds"]["any"]}
    text = {it["item_id"]: it["text"] for it in items if it["item_id"] in unl}
    sample = rng.sample(sorted(unl), min(60, len(unl)))
    write_json(OUT / "unlabelled_alert_sample.json",
               [{"item_id": i, "text": text[i][:600], "verdict": None} for i in sample])
    write_json(OUT / "summary.json", summary)
    write_json(OUT / "manifest.json", manifest(items=len(items)))
    for row in summary["pooled"]:
        print(json.dumps(row))


if __name__ == "__main__":
    main()
