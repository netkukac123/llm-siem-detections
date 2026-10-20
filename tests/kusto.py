"""Minimal client for the Kusto emulator (Kustainer) REST API.

Kustainer runs the real Kusto engine locally, so the analytic rule queries are
executed exactly as written, not re-implemented in Python.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

import yaml

KUSTO_URL = os.environ.get("KUSTO_URL", "http://127.0.0.1:8080")
DB = "NetDefaultDB"
TABLE = "LLMAppLogs_CL"
SCHEMA_FILE = Path(__file__).resolve().parent.parent / "deploy" / "sentinel" / "table-schema.json"


class KustoError(RuntimeError):
    pass


def _post(kind: str, csl: str) -> dict:
    req = urllib.request.Request(f"{KUSTO_URL}/v1/rest/{kind}",
                                 data=json.dumps({"db": DB, "csl": csl}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        raise KustoError(exc.read().decode(errors="replace")[:2000]) from exc


def available() -> bool:
    try:
        _post("query", "print 1")
        return True
    except Exception:
        return False


def schema_columns() -> list[tuple[str, str]]:
    cols = json.loads(SCHEMA_FILE.read_text())["properties"]["schema"]["columns"]
    return [(c["name"], c["type"]) for c in cols]


def load_table(jsonl: Path, chunk: int = 100) -> None:
    kql_types = {"datetime": "datetime", "string": "string", "int": "long", "long": "long", "real": "real",
                 "dynamic": "dynamic", "boolean": "bool"}
    cols = ", ".join(f"{name}:{kql_types[typ]}" for name, typ in schema_columns())
    _post("mgmt", f".drop table {TABLE} ifexists")
    _post("mgmt", f".create table {TABLE} ({cols})")
    lines = jsonl.read_text(encoding="utf-8").splitlines()
    for i in range(0, len(lines), chunk):
        body = "\n".join(lines[i:i + chunk])
        _post("mgmt", f'.ingest inline into table {TABLE} with (format="multijson") <| {body}')


def query(csl: str) -> tuple[list[str], list[dict]]:
    res = _post("query", csl)
    table = res["Tables"][0]
    names = [c["ColumnName"] for c in table["Columns"]]
    return names, [dict(zip(names, row)) for row in table["Rows"]]


def rule_query(path: Path) -> str:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["query"]
