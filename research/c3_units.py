"""C3: unit mismatch between observers (pre-registered in
docs/research/prereg-c2-c3-guardrail-window-and-units.md).

    python -m research.c3_units observers          # deterministic boundaries per script and JSON encoding
    python -m research.c3_units sentinel-ingest    # CJK/emoji/ASCII fields into the live table
    python -m research.c3_units sentinel-check <workspace-guid>
    python -m research.c3_units wazuh              # confirm the byte boundary with real logtest events

Observers: the app preview (Python characters = code points), Wazuh (bytes of the JSON line),
the Logs Ingestion API field limit (documented as 64 KB; unit measured here), and the classifier
window (512 tokens of the classifier tokenizer).
"""
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone

from ragdemo.mcp_vendor_server import RUNTIME_INSTRUCTION, shipment_history

from .common import RESULTS, manifest, write_json

OUT = RESULTS / "c3"
APP_VIEW = 1000
WAZUH_MAX_EVENT = 65319  # measured, research/results/n1/wazuh_size_limit.json
CJK_LINES = ["包裹已到达布达佩斯中转站", "货物已装车发往维也纳", "清关检查中请耐心等待", "派送失败将于明日重新派送",
             "包裹已从德布勒森仓库发出", "重量核对完成状态正常"]
EMOJI_LINES = ["📦 scanned 🚚", "✅ sorted 📍", "🛃 customs 🕐", "🚚 out for delivery 📦"]


def filler(script: str, chars: int) -> str:
    if script == "ascii":
        return shipment_history(chars)
    src = CJK_LINES if script == "cjk" else EMOJI_LINES
    out, i = [], 0
    while sum(len(x) + 1 for x in out) < chars:
        out.append(src[i % len(src)])
        i += 1
    return "\n".join(out)[:chars]


def tool_event(text: str, sid: str) -> dict:
    return {"TimeGenerated": "2026-10-20T00:00:00Z", "app_name": "c3", "event_type": "tool_call", "request_id": sid,
            "session_id": sid, "user_id": "c3", "src_ip": "10.0.0.1", "model": "n/a", "tool_name": "track_parcel",
            "tool_risk": "external", "tool_status": "ok", "mcp_server": "cargolink-tools", "tool_args": "{}",
            "tool_result": text}


def observers() -> None:
    from tokenizers import Tokenizer
    from huggingface_hub import hf_hub_download
    tok = Tokenizer.from_file(hf_hub_download("protectai/deberta-v3-base-prompt-injection-v2", "onnx/tokenizer.json"))
    rows = []
    for script in ("ascii", "cjk", "emoji"):
        for chars in (500, 900, 1100, 5000, 8000, 10000, 15000, 20000, 25000, 30000, 40000, 60000, 64000, 70000):
            text = filler(script, chars) + "\n" + RUNTIME_INSTRUCTION
            end = len(text)  # instruction is the last thing in the text
            ev = tool_event(text, f"{script}-{chars}")
            raw = json.dumps(ev, ensure_ascii=False).encode()
            esc = json.dumps(ev, ensure_ascii=True).encode()
            tokens_before_end = len(tok.encode(text, add_special_tokens=False).ids)
            rows.append({
                "script": script, "filler_chars": chars, "text_chars": end,
                "utf8_bytes": len(text.encode()), "utf16_units": len(text.encode("utf-16-le")) // 2,
                "classifier_tokens": tokens_before_end,
                "visible_app_preview": end <= APP_VIEW,
                "visible_classifier_512": tokens_before_end <= 510,  # 2 special tokens
                "wazuh_event_bytes_utf8": len(raw), "visible_wazuh_utf8": len(raw) <= WAZUH_MAX_EVENT,
                "wazuh_event_bytes_ascii_escaped": len(esc), "visible_wazuh_escaped": len(esc) <= WAZUH_MAX_EVENT,
                "within_64000_chars": end <= 64000, "within_65536_bytes": len(text.encode()) <= 65536})
    write_json(OUT / "observers.json", {"rows": rows} | manifest())
    for r in rows:
        print(f"{r['script']:5s} {r['filler_chars']:6d} chars bytes={r['utf8_bytes']:6d} tok={r['classifier_tokens']:6d} "
              f"app={int(r['visible_app_preview'])} clf={int(r['visible_classifier_512'])} "
              f"wazuh_utf8={int(r['visible_wazuh_utf8'])} wazuh_esc={int(r['visible_wazuh_escaped'])}")


SENTINEL_CASES = [("ascii", 60000), ("ascii", 66000), ("cjk", 22000), ("cjk", 30000), ("cjk", 60000),
                  ("emoji", 20000), ("emoji", 40000)]


def sentinel_ingest() -> None:
    import os
    from azure.identity import DefaultAzureCredential
    from azure.monitor.ingestion import LogsIngestionClient
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    client = LogsIngestionClient(endpoint=os.environ["LOGS_INGESTION_ENDPOINT"], credential=DefaultAzureCredential())
    sent = {}
    for script, chars in SENTINEL_CASES:
        text = filler(script, chars) + "\n" + RUNTIME_INSTRUCTION
        ev = tool_event(text, f"c3-{script}-{chars}") | {"TimeGenerated": ts, "app_name": "c3-units"}
        client.upload(rule_id=os.environ["LOGS_DCR_RULE_ID"], stream_name="Custom-LLMAppLogs", logs=[ev])
        sent[ev["session_id"]] = {"chars": len(text), "utf8_bytes": len(text.encode()),
                                  "utf16_units": len(text.encode("utf-16-le")) // 2}
    write_json(OUT / "sentinel_sent.json", {"at": ts, "sent": sent})
    print(json.dumps(sent, indent=1))


def sentinel_check(workspace: str) -> None:
    q = ('LLMAppLogs_CL | where app_name == "c3-units" | project session_id, stored_chars = strlen(tool_result), '
         'has_instruction = tool_result has "fix.sh"')
    res = subprocess.run(["az", "monitor", "log-analytics", "query", "-w", workspace, "--analytics-query", q,
                          "--timespan", "P2D", "-o", "json"], capture_output=True, text=True, check=True)
    rows = json.loads(res.stdout)
    sent = json.loads((OUT / "sentinel_sent.json").read_text())["sent"]
    out = {r["session_id"]: {**sent.get(r["session_id"], {}), "stored_chars": int(r["stored_chars"]),
                             "instruction_survived": str(r["has_instruction"]).lower() == "true"} for r in rows}
    write_json(OUT / "sentinel_check.json", out)
    print(json.dumps(out, indent=1))


def wazuh() -> None:
    """Real ingestion path: logcollector tails a JSON file (configured by research.n1_wazuh_agent_path)."""
    import time
    cases = [("ascii", 63000), ("ascii", 66000), ("cjk", 21000), ("cjk", 23000), ("emoji", 44000),
             ("emoji", 47000)]
    results, lines = {}, []
    for encoding in ("utf8", "escaped"):
        for s, c in cases:
            sid = f"c3-{encoding}-{s}-{c}"
            ev = tool_event(filler(s, c) + "\n" + RUNTIME_INSTRUCTION, sid) | {"app_name": "c3-agent"}
            line = json.dumps(ev, ensure_ascii=(encoding == "escaped"))
            lines.append(line)
            results[sid] = {"encoding": encoding, "script": s, "chars": len(ev["tool_result"]),
                            "event_bytes": len(line.encode())}
    open("/tmp/c3_wazuh.jsonl", "w").write("\n".join(lines) + "\n")
    subprocess.run(["docker", "cp", "/tmp/c3_wazuh.jsonl", "wazuh-llmd:/tmp/c3.jsonl"], check=True)
    subprocess.run(["docker", "exec", "wazuh-llmd", "sh", "-c", "cat /tmp/c3.jsonl >> /var/log/llmapp.jsonl"],
                   check=True)
    time.sleep(20)
    alerts = subprocess.run(["docker", "exec", "wazuh-llmd", "sh", "-c",
                             "grep -h '\"c3-agent\"' /var/ossec/logs/alerts/alerts.json || true"],
                            capture_output=True, text=True).stdout
    alerted = {}
    for line in alerts.splitlines():
        try:
            a = json.loads(line)
        except json.JSONDecodeError:
            continue
        alerted[a.get("data", {}).get("session_id")] = a["rule"]["id"]
    for sid, r in results.items():
        r["alert_rule"] = alerted.get(sid)
        r["detected"] = sid in alerted
    write_json(OUT / "wazuh.json", results | {"_manifest": manifest()})
    for sid, r in results.items():
        print(f"{sid:28s} chars={r['chars']:6d} bytes={r['event_bytes']:6d} detected={r['detected']}")


def main() -> None:
    p = argparse.ArgumentParser(prog="research.c3_units")
    p.add_argument("part", choices=["observers", "sentinel-ingest", "sentinel-check", "wazuh"])
    p.add_argument("workspace", nargs="?")
    a = p.parse_args()
    {"observers": observers, "sentinel-ingest": sentinel_ingest, "wazuh": wazuh,
     "sentinel-check": lambda: sentinel_check(a.workspace)}[a.part]()


if __name__ == "__main__":
    main()
