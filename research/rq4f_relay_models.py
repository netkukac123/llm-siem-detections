"""RQ4f: is relaying a failed injection to the user a general behaviour across model families?
Pre-registered in docs/research/prereg-rq4f-relay-across-models.md.

    python -m research.rq4f_relay_models run
    python -m research.rq4f_relay_models export     # blinded, shuffled answers for the raters

Same three framings, address, tool channel and oracles as RQ4d (`research/rq4d_relay.py`), on the
eight non-Claude models of RQ1. The Claude rows come from RQ4d.
"""
from __future__ import annotations

import argparse
import json
import random

from .common import RESULTS
from .rq4d_relay import TEXTS, answer, label, scenario

OUT = RESULTS / "rq4f"
MODELS = ["gemma4:e4b", "granite4:tiny-h", "llama3.1:8b", "ministral-3:8b", "qwen3:8b",
          "azure:gpt-4.1-mini", "azure:gpt-5-mini", "azure:gpt-oss-120b"]
REPS = 10
OLLAMA = "http://127.0.0.1:11434/v1"


def run() -> None:
    from .rq1_live import run_once
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "runs.jsonl"
    done = {r["run_id"] for r in map(json.loads, path.open()) if not r.get("error")} if path.exists() else set()
    with path.open("a", encoding="utf-8") as f:
        for tag in MODELS:
            for v, text in TEXTS.items():
                env = (("CARGOLINK_PAD", "0"), ("CARGOLINK_PLACEMENT", "end"), ("CARGOLINK_INSTRUCTION", text))
                for rep in range(REPS):
                    rid = f"rq4f~RQ4d-{v}-{tag.replace(':', '_')}-r{rep}"
                    if rid in done:
                        continue
                    rec = run_once(scenario(v), tag, OLLAMA, rep, 0.7, run_prefix="rq4f~", mcp_env=env)
                    rec["variant"] = v
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    f.flush()
                    print(f"{tag:22s} {v} r{rep} label={label(rec)} complied={rec['complied']} harm={rec['success']}"
                          + (f" ERROR {rec['error']}" if rec["error"] else ""), flush=True)


def export() -> None:
    """Blinded rater input: Claude answers from RQ4d plus these, shuffled, model identity removed."""
    recs = [json.loads(line) for line in (RESULTS / "rq4d" / "runs.jsonl").open()]
    recs += [r for r in map(json.loads, (OUT / "runs.jsonl").open()) if not r.get("error")]
    items = []
    for i, r in enumerate(recs):
        sent = any(e["event_type"] == "tool_call" and e.get("tool_name") == "send_email" for e in r["events"])
        items.append({"item": i, "run_id": r["run_id"], "sent_email": sent, "answer": answer(r)})
    key = [{"item": x["item"], "run_id": x["run_id"]} for x in items]
    blind = [{"item": x["item"], "agent_sent_an_email": x["sent_email"], "answer": x["answer"]} for x in items]
    random.Random(4242).shuffle(blind)
    (OUT / "blind_key.json").write_text(json.dumps(key, indent=1))
    (OUT / "blind_items.json").write_text(json.dumps(blind, indent=1, ensure_ascii=False))
    print(len(blind), "items")


def main() -> None:
    p = argparse.ArgumentParser(prog="research.rq4f_relay_models")
    p.add_argument("part", choices=["run", "export"])
    a = p.parse_args()
    run() if a.part == "run" else export()


if __name__ == "__main__":
    main()
