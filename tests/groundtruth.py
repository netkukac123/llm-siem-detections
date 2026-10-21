"""Ground truth helpers shared by the KQL and Wazuh test suites."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "datasets" / "sample.jsonl"
LABELS = ROOT / "datasets" / "labels.json"
RULE_IDS = [f"LLMD-{i:03d}" for i in range(1, 22)]
# Rules added by the empirical study; evaluated on live runs in research/, not on the reference dataset.
RESEARCH_RULE_IDS = ["LLMD-023", "LLMD-024", "LLMD-025", "LLMD-026"]


@dataclass(frozen=True)
class Expectation:
    sessions: frozenset[str]
    users: frozenset[str]
    known_miss_sessions: frozenset[str]


def labels() -> list[dict]:
    return json.loads(LABELS.read_text(encoding="utf-8"))


def expectation(rule_id: str) -> Expectation:
    lab = labels()
    hit = [l for l in lab if rule_id in l["expect"]]
    return Expectation(
        sessions=frozenset(s for l in hit for s in l["session_ids"]),
        users=frozenset(l["user_id"] for l in hit),
        known_miss_sessions=frozenset(s for l in lab if rule_id in l["known_miss"] for s in l["session_ids"]),
    )


def scenario_by_session() -> dict[str, str]:
    return {s: l["scenario"] for l in labels() for s in l["session_ids"]}


def describe(sessions: set[str] | frozenset[str]) -> list[str]:
    names = scenario_by_session()
    return sorted(names.get(s, s) for s in sessions)
