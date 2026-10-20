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
WS_LOCATION=$(az monitor log-analytics workspace show -g $RG -n $WS --query location -o tsv)
WS_GUID=$(az monitor log-analytics workspace show -g $RG -n $WS --query customerId -o tsv)
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
  --parameters workspaceResourceId=$WS_ID location=$WS_LOCATION \
  --query properties.outputs
```

The DCR goes in the workspace's region, which is not necessarily the resource group's region.
(In the author's lab the resource group is in West Europe and the workspace in East US; defaulting
to the resource group region failed with `RequestDisallowedByAzure`.)

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

`--shift-to-now` moves the timestamps so the newest event is now; otherwise the data is dated
2026-10-19. The dataset spans about ten hours, so after shifting most of it is older than the
scheduled rules' look-back windows: the rules are deployed for real traffic, the dataset is checked
with the next step. First ingestion into a new table can take 5 to 15 minutes to become queryable.

**Schema changes: wait before sending.** After adding columns to the table and the DCR, both
updates report `Succeeded` immediately, but ingestion keeps using the old schema for several
minutes. Rows sent in that window are accepted and land with the new columns empty, without any
error. (Observed in the author's lab: the first upload after adding 8 columns came through with
`tool_desc_sha256` empty on all 552 rows; the same upload 15 minutes later was complete.)

## 4b. Check every rule against the live workspace

```bash
python deploy/sentinel/ingest.py datasets/sample.jsonl --shift-to-now --app-name check-1
python deploy/sentinel/verify_live.py $WS_GUID --app-name check-1
```

Runs each rule query over the last two days and compares the hits with `datasets/labels.json`, the
same way the Kustainer tests do. `--app-name` tags one upload and scopes the check to it, so earlier
test uploads in the same table do not interfere.

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
