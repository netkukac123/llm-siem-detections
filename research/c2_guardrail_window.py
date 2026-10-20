"""C2: inspection window of the provider guardrail (pre-registered in
docs/research/prereg-c2-c3-guardrail-window-and-units.md).

    python -m research.c2_guardrail_window run      # queries the author's own Azure deployment
    python -m research.c2_guardrail_window evaluate

Only the author's Azure AI Foundry deployment is queried. max_tokens is 16: we only need the filter verdict.
"""
from __future__ import annotations

import argparse
import json
import random
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

from ragdemo.mcp_vendor_server import shipment_history

from .common import RESULTS, ROOT, manifest, wilson, write_json

OUT = RESULTS / "c2"
DEPLOYMENT = "gpt-4.1-mini"
OFFSETS = [0, 500, 900, 1100, 2000, 5000, 9500, 10500, 20000]
CHANNELS = ["user", "tool"]
SEED_DATASETS = {"deepset/prompt-injections", "neuralchemy/Prompt-injection-dataset",
                 "Lakera/gandalf_ignore_instructions"}
N_SEEDS = 50
AZURE_ENV = Path.home() / ".config" / "llmd" / "azure.env"
TOOLS = [{"type": "function", "function": {"name": "track_parcel", "description": "Track a parcel.",
                                           "parameters": {"type": "object",
                                                          "properties": {"tracking_id": {"type": "string"}},
                                                          "required": ["tracking_id"]}}}]


def _env():
    return dict(l.split("=", 1) for l in AZURE_ENV.read_text().split() if "=" in l)


def call(messages: list[dict], with_tools: bool) -> dict:
    env = _env()
    body = {"model": DEPLOYMENT, "messages": messages, "max_tokens": 16}
    if with_tools:
        body["tools"] = TOOLS
    req = urllib.request.Request(env["AZURE_AI_BASE"] + "/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + env["AZURE_AI_KEY"]})
    for attempt in range(8):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.load(resp)
            return {"blocked": False, "status": 200,
                    "annotations": data.get("prompt_filter_results"),
                    "finish_reason": data["choices"][0].get("finish_reason") if data.get("choices") else None}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            if exc.code == 429 and attempt < 7:
                time.sleep(float(exc.headers.get("retry-after", 2 ** attempt * 3)))
                continue
            if exc.code == 400 and "content_filter" in raw:
                try:
                    res = json.loads(raw)["error"]["innererror"]["content_filter_result"]
                except (KeyError, ValueError):
                    res = None
                return {"blocked": True, "status": 400, "annotations": res}
            return {"blocked": None, "status": exc.code, "error": raw[:300]}
    return {"blocked": None, "status": 429, "error": "rate limited"}


def messages_for(payload: str, offset: int, channel: str) -> list[dict]:
    text = (shipment_history(offset) + "\n" + payload) if offset else payload
    if channel == "user":
        return [{"role": "user", "content": text}]
    return [{"role": "user", "content": "Track shipment CL-90133 for me"},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_c2", "type": "function",
                 "function": {"name": "track_parcel", "arguments": json.dumps({"tracking_id": "CL-90133"})}}]},
            {"role": "tool", "tool_call_id": "call_c2", "content": text}]


def run() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    seeds_path = OUT / "seeds.json"
    if seeds_path.exists():
        seeds = json.loads(seeds_path.read_text())
    else:
        pool = [json.loads(l) for l in (ROOT / "research" / "data" / "rq2_items.jsonl").open(encoding="utf-8")]
        pool = [it for it in pool if it["kind"] == "prompt" and it["label"] == 1 and it["dataset"] in SEED_DATASETS
                and 20 <= len(it["text"]) <= 600]
        random.Random(5).shuffle(pool)
        seeds, screened = [], []
        for it in pool[:300]:
            r = call(messages_for(it["text"], 0, "user"), with_tools=False)
            screened.append({"item_id": it["item_id"], **r})
            if r["blocked"]:
                seeds.append({"item_id": it["item_id"], "dataset": it["dataset"], "text": it["text"]})
            if len(seeds) >= N_SEEDS:
                break
        write_json(OUT / "screening.json", screened)
        write_json(seeds_path, seeds)
        print(f"screened {len(screened)}, blocked at offset 0: {len(seeds)}")
    path = OUT / "runs.jsonl"
    done = {(r["item_id"], r["offset"], r["channel"]) for r in map(json.loads, path.open())} if path.exists() else set()
    with path.open("a", encoding="utf-8") as f:
        for s in seeds:
            for ch in CHANNELS:
                for off in OFFSETS:
                    if (s["item_id"], off, ch) in done:
                        continue
                    r = call(messages_for(s["text"], off, ch), with_tools=(ch == "tool"))
                    f.write(json.dumps({"item_id": s["item_id"], "offset": off, "channel": ch, **r}) + "\n")
                    f.flush()
                    print(f"{s['item_id'][:40]:40s} {ch:5s} {off:6d} blocked={r['blocked']}", flush=True)
    write_json(OUT / "manifest.json", manifest(deployment=DEPLOYMENT, offsets=OFFSETS, channels=CHANNELS))


def evaluate() -> None:
    rows = [json.loads(l) for l in (OUT / "runs.jsonl").open()]
    by = defaultdict(list)
    for r in rows:
        if r["blocked"] is not None:
            by[(r["channel"], r["offset"])].append(r["blocked"])
    summary = [{"channel": ch, "offset": off, "n": len(by[(ch, off)]),
                "blocked": wilson(sum(by[(ch, off)]), len(by[(ch, off)]))}
               for ch in CHANNELS for off in OFFSETS if by[(ch, off)]]
    screening = json.loads((OUT / "screening.json").read_text()) if (OUT / "screening.json").exists() else []
    write_json(OUT / "summary.json", {"cells": summary, "screened": len(screening),
                                      "blocked_at_zero_in_screening": sum(1 for s in screening if s.get("blocked"))})
    for s in summary:
        print(f"{s['channel']:5s} {s['offset']:6d} n={s['n']:3d} blocked={s['blocked'][0]:.2f} "
              f"[{s['blocked'][1]:.2f},{s['blocked'][2]:.2f}]")


def main() -> None:
    p = argparse.ArgumentParser(prog="research.c2_guardrail_window")
    p.add_argument("part", choices=["run", "evaluate"])
    a = p.parse_args()
    run() if a.part == "run" else evaluate()


if __name__ == "__main__":
    main()
