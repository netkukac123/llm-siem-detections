"""Replay the reference dataset through a real wazuh-manager with wazuh-logtest.

Needs a running wazuh-manager container (default name: wazuh-llmd, override
with WAZUH_CONTAINER). The rules file, the dataset and the logtest client are
copied in on every run, so edits are picked up without a restart.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections import defaultdict

import pytest

from .groundtruth import DATASET, ROOT, RULE_IDS, describe, expectation

CONTAINER = os.environ.get("WAZUH_CONTAINER", "wazuh-llmd")
RULES = ROOT / "detections" / "wazuh" / "llm_rules.xml"
CLIENT = ROOT / "tests" / "wazuh_logtest_client.py"
PY = "/var/ossec/framework/python/bin/python3"
USER_LEVEL = {"LLMD-009", "LLMD-010"}


def _container_running() -> bool:
    if not shutil.which("docker"):
        return False
    res = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER], capture_output=True, text=True)
    return res.stdout.strip() == "true"


pytestmark = pytest.mark.skipif(not (os.environ.get("REQUIRE_ENGINES") or _container_running()),
                                reason=f"container {CONTAINER} not running")


def _docker(*args: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True, **kw)


@pytest.fixture(scope="module")
def results() -> list[dict]:
    _docker("cp", str(RULES), f"{CONTAINER}:/var/ossec/etc/rules/llm_rules.xml")
    _docker("cp", str(CLIENT), f"{CONTAINER}:/tmp/wazuh_logtest_client.py")
    _docker("cp", str(DATASET), f"{CONTAINER}:/tmp/sample.jsonl")
    out = _docker("exec", CONTAINER, PY, "/tmp/wazuh_logtest_client.py", "/tmp/sample.jsonl").stdout
    rows = [json.loads(line) for line in out.splitlines()]
    errors = [r for r in rows if "error" in r]
    assert not errors, f"logtest errors: {errors[:3]}"
    return rows


def test_every_event_was_decoded(results):
    undecoded = [r for r in results if not r["rule_id"]]
    assert not undecoded, f"{len(undecoded)} events matched no rule, first: {undecoded[0]}"


def test_every_rule_is_implemented(results):
    groups = (ROOT / "detections" / "wazuh" / "llm_rules.xml").read_text()
    missing = [r for r in RULE_IDS if f"llmd_{r[-3:]}," not in groups]
    assert not missing


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_matches_ground_truth(results, rule_id: str):
    group = f"llmd_{rule_id[-3:]}"
    hits_by_level: dict[str, set[str]] = defaultdict(set)
    for r in results:
        if group in r["groups"]:
            hits_by_level["session"].add(r["session_id"])
            hits_by_level["user"].add(r["user_id"])
    exp = expectation(rule_id)
    if rule_id in USER_LEVEL:
        assert hits_by_level["user"] == set(exp.users)
        return
    hits = hits_by_level["session"]
    missed, false_pos = exp.sessions - hits, hits - exp.sessions
    assert not missed, f"{rule_id} missed: {describe(missed)}"
    assert not false_pos, f"{rule_id} false positives: {describe(false_pos)}"
    assert not (hits & exp.known_miss_sessions), "a documented gap now fires; update coverage docs"
