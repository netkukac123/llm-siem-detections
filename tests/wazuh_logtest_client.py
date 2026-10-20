"""Replay a JSONL file through wazuh-logtest and print one JSON result per event.

Runs *inside* the wazuh-manager container (stdlib only, so the bundled
framework Python works):

    /var/ossec/framework/python/bin/python3 wazuh_logtest_client.py /data/sample.jsonl

All events share one logtest session token, so frequency and correlation
rules keep state across events exactly as analysisd would.
"""
import json
import socket
import struct
import sys

SOCKET = "/var/ossec/queue/sockets/logtest"


def call(payload):
    data = json.dumps(payload).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCKET)
        s.sendall(struct.pack("<I", len(data)) + data)
        size = struct.unpack("<I", s.recv(4))[0]
        buf = b""
        while len(buf) < size:
            buf += s.recv(size - len(buf))
    return json.loads(buf)


def main(path):
    token = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            event = json.loads(line)
            params = {"event": line.rstrip("\n"), "log_format": "json", "location": "llm-app"}
            if token:
                params["token"] = token
            resp = call({"version": 1, "origin": {"name": "llmd-tests", "module": "api"},
                         "command": "log_processing", "parameters": params})
            if resp.get("error"):
                print(json.dumps({"error": resp}), flush=True)
                continue
            data = resp["data"]
            if "output" not in data:  # ruleset failed to load, or the event was rejected (e.g. too large)
                print(json.dumps({"error": data.get("messages"), "session_id": event.get("session_id"),
                                  "event_bytes": len(line.encode())}), flush=True)
                if any("Session initialized" in m or "rule" in m.lower() for m in data.get("messages", [])):
                    return
                continue
            token = data.get("token", token)
            rule = data["output"].get("rule", {})
            print(json.dumps({"request_id": event.get("request_id"), "session_id": event.get("session_id"),
                              "user_id": event.get("user_id"), "event_type": event.get("event_type"),
                              "rule_id": rule.get("id"), "level": rule.get("level"),
                              "groups": rule.get("groups", []),
                              "messages": [m for m in data.get("messages", []) if "ERROR" in m or "WARNING" in m]},
                             ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main(sys.argv[1])
