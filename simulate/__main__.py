"""Generate the reference dataset: datasets/sample.jsonl + datasets/labels.json.

    python -m simulate [--out datasets]

Output is deterministic (fixed clock, fixed seed, scripted model), so the
detection tests can assert exact hits.
"""
from __future__ import annotations

import argparse
import io
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ragdemo.app import RagApp
from ragdemo.llm import ScriptedModel
from ragdemo.logsink import EventLog, SimClock

from .scenarios import all_scenarios

DAY_START = datetime(2026, 10, 19, 7, 0, tzinfo=timezone.utc)


def main() -> None:
    p = argparse.ArgumentParser(prog="simulate")
    p.add_argument("--out", default="datasets")
    args = p.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    rng = random.Random(1337)
    uuid_rng = random.Random(42)
    uuid.uuid4 = lambda: uuid.UUID(int=uuid_rng.getrandbits(128), version=4)  # reproducible ids

    buf = io.StringIO()
    clock = SimClock(DAY_START)
    model = ScriptedModel()
    app = RagApp(EventLog(buf, clock=clock), model)

    labels = []
    for sc in all_scenarios():
        clock.current = DAY_START + timedelta(minutes=rng.randint(0, 9 * 60))
        session_id = f"s-{uuid.uuid4().hex[:12]}"
        for turn in sc.turns:
            model.script(*turn.model)
            app.handle(turn.message, session_id=session_id, user_id=sc.user_id, src_ip=sc.src_ip)
            clock.advance(turn.gap)
        labels.append({"scenario": sc.id, "kind": sc.kind, "session_id": session_id, "user_id": sc.user_id,
                       "expect": sc.expect, "known_miss": sc.known_miss, "description": sc.description})

    events = [json.loads(line) for line in buf.getvalue().splitlines()]
    events.sort(key=lambda e: e["TimeGenerated"])
    with open(out / "sample.jsonl", "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    (out / "labels.json").write_text(json.dumps(labels, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{len(events)} events, {len(labels)} scenarios -> {out}/")


if __name__ == "__main__":
    main()
