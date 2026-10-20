"""Run every Sentinel analytic rule against the reference dataset in Kustainer.

Each rule must flag exactly the sessions (or users, for per-identity rules)
whose scenario lists it in `expect`: no misses, no false positives, and the
documented `known_miss` gaps must stay silent.
"""
from __future__ import annotations

import os

import pytest

from . import kusto
from .groundtruth import DATASET, ROOT, RULE_IDS, describe, expectation

RULE_FILES = {p.name[:8]: p for p in (ROOT / "detections" / "sentinel").glob("LLMD-*.yaml")}

pytestmark = pytest.mark.skipif(not (os.environ.get("REQUIRE_ENGINES") or kusto.available()),
                                reason=f"Kustainer not reachable at {kusto.KUSTO_URL}")


@pytest.fixture(scope="module", autouse=True)
def loaded_table():
    kusto.load_table(DATASET)


def test_every_rule_has_a_sentinel_file():
    assert sorted(RULE_FILES) == RULE_IDS


def _hits(rule_id: str) -> tuple[str, set[str]]:
    columns, rows = kusto.query(kusto.rule_query(RULE_FILES[rule_id]))
    if "session_id" in columns:
        return "session", {r["session_id"] for r in rows}
    return "user", {r["user_id"] for r in rows}


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_matches_ground_truth(rule_id: str):
    exp = expectation(rule_id)
    level, hits = _hits(rule_id)
    if level == "session":
        missed, false_pos = exp.sessions - hits, hits - exp.sessions
        assert not missed, f"{rule_id} missed: {describe(missed)}"
        assert not false_pos, f"{rule_id} false positives: {describe(false_pos)}"
        assert not (hits & exp.known_miss_sessions), "a documented gap now fires; update coverage docs"
    else:
        assert hits == set(exp.users), f"{rule_id} flagged users {sorted(hits)}, expected {sorted(exp.users)}"
