"""N1/V3b: the real Wazuh ingestion path (logcollector reading a JSON log file -> analysisd -> alerts.json),
not just wazuh-logtest. Writes events with the injection at the end of tool results of increasing size and
checks which ones produce an LLMD-021 alert.

    python -m research.n1_wazuh_agent_path      # needs the wazuh-llmd container
"""
from __future__ import annotations

import json
import subprocess
import time

from .common import RESULTS, manifest, write_json
from .n1_view_divergence import shipment_history_payload

C = "wazuh-llmd"
LOG = "/var/log/llmapp.jsonl"
SIZES = [20000, 60000, 64000, 65000, 66000, 70000, 120000]
LOCALFILE = f"""
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>{LOG}</location>
  </localfile>
</ossec_config>
"""


def sh(*args, check=True):
    return subprocess.run(["docker", "exec", C, *args], capture_output=True, text=True, check=check).stdout


def main() -> None:
    subprocess.run(["docker", "cp", "detections/wazuh/llm_rules.xml", f"{C}:/var/ossec/etc/rules/llm_rules.xml"], check=True)
    conf = sh("cat", "/var/ossec/etc/ossec.conf")
    if LOG not in conf:
        open("/tmp/n1_localfile.xml", "w").write(LOCALFILE)
        subprocess.run(["docker", "cp", "/tmp/n1_localfile.xml", f"{C}:/tmp/n1_localfile.xml"], check=True)
        sh("sh", "-c", "cat /tmp/n1_localfile.xml >> /var/ossec/etc/ossec.conf")
    sh("sh", "-c", f"touch {LOG} && chmod 644 {LOG}")
    sh("/var/ossec/bin/wazuh-control", "restart")
    time.sleep(25)
    lines = []
    for n in SIZES:
        text = shipment_history_payload(n)
        ev = {"TimeGenerated": "2026-10-20T00:00:00Z", "app_name": "n1-agent", "event_type": "tool_call",
              "request_id": f"size{n}", "session_id": f"size{n}", "user_id": "n1", "src_ip": "10.0.0.1",
              "model": "n/a", "tool_name": "track_parcel", "tool_risk": "external", "tool_status": "ok",
              "mcp_server": "cargolink-tools", "tool_args": "{}", "tool_result": text}
        lines.append(json.dumps(ev))
    open("/tmp/n1_events.jsonl", "w").write("\n".join(lines) + "\n")
    subprocess.run(["docker", "cp", "/tmp/n1_events.jsonl", f"{C}:/tmp/n1_events.jsonl"], check=True)
    sh("sh", "-c", f"cat /tmp/n1_events.jsonl >> {LOG}")
    time.sleep(20)
    alerts = sh("sh", "-c", "grep -h '\"n1-agent\"' /var/ossec/logs/alerts/alerts.json || true")
    hits = {}
    for line in alerts.splitlines():
        try:
            a = json.loads(line)
        except json.JSONDecodeError:
            continue
        sid = a.get("data", {}).get("session_id")
        if sid:
            hits[sid] = {"rule": a["rule"]["id"], "groups": a["rule"]["groups"],
                         "logged_result_chars": len(a.get("data", {}).get("tool_result", ""))}
    ossec_log = sh("sh", "-c", "grep -iE 'too large|truncat|max.*size|65' /var/ossec/logs/ossec.log | tail -5 || true")
    result = {"sizes": {f"size{n}": {"event_bytes": len(l.encode()), "alert": hits.get(f"size{n}")}
                        for n, l in zip(SIZES, lines)},
              "ossec_log_tail": ossec_log.splitlines()}
    write_json(RESULTS / "n1" / "wazuh_agent_path.json", result | manifest())
    print(json.dumps(result, indent=1)[:2500])


if __name__ == "__main__":
    main()
