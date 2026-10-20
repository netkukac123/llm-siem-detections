"""Upload a JSONL event file to LLMAppLogs_CL through the Logs Ingestion API.

    pip install azure-identity azure-monitor-ingestion
    export LOGS_INGESTION_ENDPOINT=https://<dcr-name>-xxxx.<region>-1.ingest.monitor.azure.com
    export LOGS_DCR_RULE_ID=dcr-0123456789abcdef0123456789abcdef
    python deploy/sentinel/ingest.py datasets/sample.jsonl --shift-to-now

Authentication uses DefaultAzureCredential (az login, managed identity or the
AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET variables). The identity
needs "Monitoring Metrics Publisher" on the DCR.

--shift-to-now moves the reference dataset's timestamps so the newest event is
"now". Without it the events land on 2026-10-19 and scheduled analytic rules,
which only look back over their query period, will not see them.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient

STREAM = "Custom-LLMAppLogs"


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("jsonl")
    p.add_argument("--shift-to-now", action="store_true")
    p.add_argument("--app-name", help="overwrite app_name, to tell test runs apart (see verify_live.py)")
    args = p.parse_args()

    with open(args.jsonl, encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    if args.app_name:
        for e in events:
            e["app_name"] = args.app_name
    if args.shift_to_now and events:
        delta = datetime.now(timezone.utc) - max(_parse(e["TimeGenerated"]) for e in events)
        for e in events:
            e["TimeGenerated"] = (_parse(e["TimeGenerated"]) + delta).isoformat().replace("+00:00", "Z")

    client = LogsIngestionClient(endpoint=os.environ["LOGS_INGESTION_ENDPOINT"], credential=DefaultAzureCredential())
    failed: list[dict] = []

    def on_error(err) -> None:
        print(f"chunk failed: {err.error}")
        failed.extend(err.failed_logs)

    client.upload(rule_id=os.environ["LOGS_DCR_RULE_ID"], stream_name=STREAM, logs=events, on_error=on_error)
    print(f"uploaded {len(events) - len(failed)} of {len(events)} events")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
