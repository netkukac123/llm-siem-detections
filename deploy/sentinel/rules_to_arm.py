"""Bundle the analytic rule YAMLs into one ARM template for Microsoft Sentinel.

    python deploy/sentinel/rules_to_arm.py > build/llmd-analytics-rules.json
    az deployment group create -g <rg> --template-file build/llmd-analytics-rules.json \
        --parameters workspace=<workspace-name>

Each rule becomes a Microsoft.SecurityInsights/alertRules (kind Scheduled)
extension resource on the workspace, keeping the YAML id as the rule GUID so
re-deploying updates rules in place instead of duplicating them.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parents[2] / "detections" / "sentinel"


def iso_duration(value: str) -> str:
    m = re.fullmatch(r"(\d+)([mhd])", value)
    if not m:
        raise ValueError(f"unsupported duration {value!r}")
    n, unit = m.groups()
    return f"P{n}D" if unit == "d" else f"PT{n}{unit.upper()}"


def rule_resource(rule: dict) -> dict:
    props = {
        "displayName": rule["name"],
        "description": rule["description"].strip(),
        "severity": rule["severity"],
        "enabled": True,
        "query": rule["query"].strip(),
        "queryFrequency": iso_duration(rule["queryFrequency"]),
        "queryPeriod": iso_duration(rule["queryPeriod"]),
        "triggerOperator": {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal"}[rule["triggerOperator"]],
        "triggerThreshold": rule["triggerThreshold"],
        "suppressionEnabled": False,
        "suppressionDuration": "PT1H",
        "tactics": rule.get("tactics", []),
        "techniques": rule.get("relevantTechniques", []),
        "entityMappings": rule.get("entityMappings", []),
        "customDetails": rule.get("customDetails") or None,
        # One alert per result row; the API default (SingleAlert) would merge different users.
        "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
        "incidentConfiguration": {
            "createIncident": True,
            "groupingConfiguration": {
                "enabled": True, "reopenClosedIncident": False, "lookbackDuration": "PT5H",
                "matchingMethod": "AllEntities", "groupByEntities": [], "groupByAlertDetails": [],
                "groupByCustomDetails": []}},
    }
    return {
        "type": "Microsoft.SecurityInsights/alertRules",
        "apiVersion": "2023-02-01",
        "scope": "[format('Microsoft.OperationalInsights/workspaces/{0}', parameters('workspace'))]",
        "name": rule["id"],
        "kind": "Scheduled",
        "properties": {k: v for k, v in props.items() if v is not None},
    }


def main() -> None:
    rules = [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(RULES_DIR.glob("LLMD-*.yaml"))]
    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {"workspace": {"type": "string", "metadata": {"description": "Sentinel-enabled workspace name"}}},
        "resources": [rule_resource(r) for r in rules],
    }
    json.dump(template, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
