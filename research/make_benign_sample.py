"""Draw the real benign prompts used as live benign traffic in RQ1.

    python -m research.make_benign_sample   # -> research/results/rq2/benign_sample.json
"""
from __future__ import annotations

import json
import random

from .common import RESULTS, ROOT, write_json

ITEMS = ROOT / "research" / "data" / "rq2_items.jsonl"
SOURCES = {"OpenAssistant/oasst2", "databricks/databricks-dolly-15k"}


def main(n: int = 50, seed: int = 11) -> None:
    pool = []
    for line in ITEMS.open(encoding="utf-8"):
        it = json.loads(line)
        if it["kind"] == "prompt" and it["label"] == 0 and it["dataset"] in SOURCES and 15 <= len(it["text"]) <= 400:
            if it["dataset"] != "OpenAssistant/oasst2" or it["meta"].get("lang") == "en":
                pool.append(it["text"])
    random.Random(seed).shuffle(pool)
    write_json(RESULTS / "rq2" / "benign_sample.json", pool[:n])
    print(f"{min(n, len(pool))} benign prompts sampled from {len(pool)}")


if __name__ == "__main__":
    main()
