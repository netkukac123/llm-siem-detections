# Deploying to Microsoft Sentinel

Path: application JSONL → Logs Ingestion API → data collection rule → `LLMAppLogs_CL` → scheduled
analytic rules. Based on Microsoft's
[Logs Ingestion API tutorial](https://learn.microsoft.com/azure/azure-monitor/logs/tutorial-logs-ingestion-api);
this uses the DCR's own ingestion endpoint (`kind: Direct`), so no data collection endpoint is
needed unless you use Private Link.

```bash
SUB=$(az account show --query id -o tsv)
RG=<resource-group>
WS=<sentinel-workspace>
WS_ID=$(az monitor log-analytics workspace show -g $RG -n $WS --query id -o tsv)
```

## 1. Custom table

```bash
az rest --method PUT \
  --url "https://management.azure.com${WS_ID}/tables/LLMAppLogs_CL?api-version=2022-10-01" \
  --body @deploy/sentinel/table-schema.json
```

## 2. Data collection rule

```bash
az deployment group create -g $RG --template-file deploy/sentinel/dcr.json \
  --parameters workspaceResourceId=$WS_ID \
  --query properties.outputs
```

Note `immutableId` and `logsIngestionEndpoint` from the output.

## 3. Permission to send

The identity that runs the ingest script needs **Monitoring Metrics Publisher** on the DCR:

```bash
DCR_ID=$(az monitor data-collection rule show -g $RG -n dcr-llm-app-logs --query id -o tsv)
az role assignment create --assignee <user-or-app-object-id> \
  --role "Monitoring Metrics Publisher" --scope $DCR_ID
```

Role assignments can take a few minutes to apply.

## 4. Send the reference dataset

```bash
pip install azure-identity azure-monitor-ingestion
export LOGS_INGESTION_ENDPOINT=<logsIngestionEndpoint>
export LOGS_DCR_RULE_ID=<immutableId>
python deploy/sentinel/ingest.py datasets/sample.jsonl --shift-to-now
```

`--shift-to-now` moves the timestamps so the newest event is now; otherwise the scheduled rules'
look-back windows will not see data dated 2026-10-19. First ingestion into a new table can take
5 to 15 minutes to become queryable.

## 5. Analytic rules

```bash
make arm
az deployment group create -g $RG --template-file build/llmd-analytics-rules.json \
  --parameters workspace=$WS
```

Rule GUIDs are fixed in the YAML files, so re-deploying updates the rules in place. To try a single
query by hand, paste the `query:` block from `detections/sentinel/*.yaml` into Logs.

## Running the live demo into Sentinel

Point the demo app at a model, then ship its log the same way:

```bash
python -m ragdemo chat --backend openai --base-url http://localhost:11434/v1 --model llama3.1
python deploy/sentinel/ingest.py logs/ragdemo.jsonl
```

For continuous shipping from a VM, use the Azure Monitor Agent with a custom JSON log DCR instead of
the script.
