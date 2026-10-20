"""Find the largest JSON event (bytes) that wazuh-logtest accepts, by bisection."""
import json, subprocess
ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]


def accepted(n_bytes: int) -> bool:
    base = {"TimeGenerated": "2026-10-20T00:00:00Z", "app_name": "probe", "event_type": "tool_call",
            "request_id": "probe1", "session_id": "probe", "user_id": "u", "src_ip": "10.0.0.1", "model": "m",
            "tool_name": "track_parcel", "tool_risk": "external", "tool_status": "ok", "tool_result": ""}
    overhead = len(json.dumps(base).encode())
    base["tool_result"] = "x" * max(0, n_bytes - overhead)
    line = json.dumps(base)
    assert len(line.encode()) == n_bytes or n_bytes < overhead
    open("/tmp/probe.jsonl", "w").write(line + "\n")
    subprocess.run(["docker", "cp", "/tmp/probe.jsonl", "wazuh-llmd:/tmp/probe.jsonl"], check=True)
    out = subprocess.run(["docker", "exec", "wazuh-llmd", "/var/ossec/framework/python/bin/python3", "/tmp/c.py",
                          "/tmp/probe.jsonl"], capture_output=True, text=True).stdout
    lines = out.splitlines()
    if not lines:  # client got no answer at all: the socket refused the message
        return False
    return "error" not in json.loads(lines[0])


subprocess.run(["docker", "cp", f"{ROOT}/tests/wazuh_logtest_client.py", "wazuh-llmd:/tmp/c.py"], check=True)
lo, hi = 1000, 200000
assert accepted(lo) and not accepted(hi)
while hi - lo > 1:
    mid = (lo + hi) // 2
    if accepted(mid):
        lo = mid
    else:
        hi = mid
print(f"largest accepted event: {lo} bytes; smallest rejected: {hi} bytes")
