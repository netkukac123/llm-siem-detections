"""Shared helpers for the empirical study: statistics, rule evaluation on Kustainer,
and run manifests. Every experiment in research/ goes through these so the numbers
in the paper are computed one way only.
"""
from __future__ import annotations

import json
import math
import platform
import random
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "detections" / "sentinel"
RESULTS = ROOT / "research" / "results"


# ---------------------------------------------------------------- statistics

def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    """Point estimate and Wilson score interval for a binomial proportion."""
    if n == 0:
        return float("nan"), float("nan"), float("nan")
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return p, max(0.0, centre - half), min(1.0, centre + half)


@dataclass(frozen=True)
class Confusion:
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else float("nan")

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else float("nan")

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else float("nan")

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else float("nan")


def confusion(labels: Sequence[bool], preds: Sequence[bool]) -> Confusion:
    tp = sum(1 for y, p in zip(labels, preds) if y and p)
    fp = sum(1 for y, p in zip(labels, preds) if not y and p)
    tn = sum(1 for y, p in zip(labels, preds) if not y and not p)
    fn = sum(1 for y, p in zip(labels, preds) if y and not p)
    return Confusion(tp, fp, tn, fn)


def bootstrap_ci(labels: Sequence[bool], preds: Sequence[bool], metric: str,
                 iters: int = 1000, seed: int = 7) -> tuple[float, float]:
    """Percentile bootstrap 95% interval for precision/recall/fpr/f1."""
    rng = random.Random(seed)
    n = len(labels)
    vals = []
    for _ in range(iters):
        idx = [rng.randrange(n) for _ in range(n)]
        v = getattr(confusion([labels[i] for i in idx], [preds[i] for i in idx]), metric)
        if not math.isnan(v):
            vals.append(v)
    if not vals:
        return float("nan"), float("nan")
    vals.sort()
    return vals[int(0.025 * len(vals))], vals[int(0.975 * len(vals)) - 1]


# ---------------------------------------------------------------- rules on Kustainer

def rule_files() -> dict[str, Path]:
    return {p.name[:8]: p for p in sorted(RULES_DIR.glob("LLMD-*.yaml"))}


def rule_query(path: Path) -> str:
    q = yaml.safe_load(path.read_text(encoding="utf-8"))["query"]
    return re.sub(r"let trigger_window = \w+;", "let trigger_window = 3650d;", q)


def run_rules(events: Iterable[dict], rules: Sequence[str] | None = None,
              key: str = "request_id") -> dict[str, set[str]]:
    """Load events into Kustainer's LLMAppLogs_CL and return, per rule, the set of `key`
    values (request_id by default) that the rule flagged. Rules whose output lacks the key
    fall back to session_id, then user_id."""
    from tests import kusto  # local import: only experiments that need Kusto pay for it

    events = list(events)
    path = RESULTS / "_kusto_load.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events), encoding="utf-8")
    kusto.load_table(path, chunk=400)
    out: dict[str, set[str]] = {}
    for rid, p in rule_files().items():
        if rules and rid not in rules:
            continue
        cols, rows = kusto.query(rule_query(p))
        col = next((c for c in (key, "session_id", "user_id") if c in cols), None)
        out[rid] = {str(r[col]) for r in rows} if col else set()
    return out


# ---------------------------------------------------------------- manifests

def git_commit() -> str:
    res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    return res.stdout.strip()


def manifest(**extra) -> dict:
    return {"created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "commit": git_commit(), "python": platform.python_version(),
            "platform": platform.platform(), **extra}


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
