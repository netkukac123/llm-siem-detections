"""Controlled measurement of the Wazuh logcollector path (file -> logcollector -> analysisd -> alerts).

For each probe we append three lines: a small marker that must alert, the probe line, and a second
small marker. That separates "the probe was too large" from "the pipeline lost other events too".

    python -m research.wazuh_agent_bisect
"""
from __future__ import annotations

import json
import subprocess
import time
import uuid

from ragdemo.mcp_vendor_server import RUNTIME_INSTRUCTION

from .c3_units import filler
from .common import RESULTS, manifest, write_json

C = "wazuh-llmd"
LOG = "/var/log/llmapp.jsonl"


def ev(sid: str, text: str) -> str:
    return json.dumps({"TimeGenerated": "2026-10-20T00:00:00Z", "app_name": "bisect", "event_type": "tool_call",
                       "request_id": sid.replace("-", ""), "session_id": sid, "user_id": "b", "src_ip": "10.0.0.1",
                       "model": "n/a", "tool_name": "track_parcel", "tool_risk": "external", "tool_status": "ok",
                       "mcp_server": "cargolink-tools", "tool_args": "{}", "tool_result": text},
                      ensure_ascii=False)


def alerted(sids: list[str]) -> dict[str, bool]:
    out = subprocess.run(["docker", "exec", C, "sh", "-c",
                          "grep -o '\"session_id\":\"[^\"]*\"' /var/ossec/logs/alerts/alerts.json || true"],
                         capture_output=True, text=True).stdout
    seen = {line.split(":", 1)[1].strip('"') for line in out.splitlines()}
    return {s: s in seen for s in sids}


def probe(script: str, chars: int) -> dict:
    tag = uuid.uuid4().hex[:6]
    before, target, after = f"mk-{tag}-a", f"pr-{tag}", f"mk-{tag}-b"
    lines = [ev(before, "x\n" + RUNTIME_INSTRUCTION),
             ev(target, filler(script, chars) + "\n" + RUNTIME_INSTRUCTION),
             ev(after, "y\n" + RUNTIME_INSTRUCTION)]
    open("/tmp/bisect.jsonl", "w").write("\n".join(lines) + "\n")
    subprocess.run(["docker", "cp", "/tmp/bisect.jsonl", f"{C}:/tmp/bisect.jsonl"], check=True)
    subprocess.run(["docker", "exec", C, "sh", "-c", f"cat /tmp/bisect.jsonl >> {LOG}"], check=True)
    time.sleep(12)
    a = alerted([before, target, after])
    return {"script": script, "chars": chars, "line_bytes": len(lines[1].encode()),
            "marker_before": a[before], "probe": a[target], "marker_after": a[after]}


def bisect(script: str, lo: int, hi: int, log: list) -> tuple[int, int]:
    while hi - lo > max(50, lo // 200):
        mid = (lo + hi) // 2
        r = probe(script, mid)
        log.append(r)
        print(r, flush=True)
        if r["probe"]:
            lo = mid
        else:
            hi = mid
    return lo, hi


def main() -> None:
    log: list = []
    sanity = probe("ascii", 1000)
    log.append(sanity)
    print("sanity", sanity, flush=True)
    bounds = {}
    for script, lo, hi in (("ascii", 1000, 80000), ("cjk", 300, 40000), ("emoji", 500, 80000)):
        lo_c, hi_c = bisect(script, lo, hi, log)
        bounds[script] = {"largest_alerting_chars": lo_c, "smallest_silent_chars": hi_c}
    write_json(RESULTS / "c3" / "wazuh_agent_bisect.json", {"bounds": bounds, "probes": log} | manifest())
    print(json.dumps(bounds, indent=1))


if __name__ == "__main__":
    main()
