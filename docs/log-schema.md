# Log schema

The detections need telemetry that most LLM applications do not produce by default. This page is the
contract: one JSON object per line, one line per event, flat keys. The same file is shipped to
Sentinel (as table `LLMAppLogs_CL`, schema in `deploy/sentinel/table-schema.json`) and read by the
Wazuh agent with `log_format json`.

## Event types

A user turn produces several events that share a `request_id`:

```
[tool_registry (one per MCP tool, once per session)]
prompt ─▶ retrieval (0..k, incl. recalled memory) ─▶ tool_call (0..n) ─▶ completion
   │                                                  └─ memory_write (when the agent stores a note)
   └─ or guardrail (block), which ends the turn
```

## Common fields (every event)

| Field | Type | Meaning | Closest OpenTelemetry GenAI attribute |
|---|---|---|---|
| `TimeGenerated` | datetime | Event time, UTC, ISO 8601 | span / event timestamp |
| `app_name` | string | Emitting application | `service.name` |
| `event_type` | string | `prompt`, `guardrail`, `retrieval`, `tool_call`, `completion`, `memory_write`, `tool_registry` | `gen_ai.operation.name` (partly) |
| `request_id` | string | One user turn | `gen_ai.response.id` / trace id |
| `session_id` | string | Conversation | `gen_ai.conversation.id` |
| `user_id` | string | Authenticated identity, human or service principal | `enduser.id` |
| `src_ip` | string | Client address as the app sees it | `client.address` |
| `model` | string | Model or deployment | `gen_ai.request.model` |

## Per event type

| Event | Field | Meaning | OTel GenAI |
|---|---|---|---|
| prompt | `prompt` | User message, truncated to 2000 chars | `gen_ai.input.messages` |
| prompt | `prompt_chars` | Untruncated length | |
| guardrail | `guardrail_action` | `block` (or `allow` if you log those) | |
| guardrail | `guardrail_rule` | Rule or category that decided | |
| guardrail | `prompt` | The blocked prompt | |
| retrieval | `doc_id` | Document identifier | `gen_ai.data_source.id` (closest) |
| retrieval | `doc_source` | **Provenance**: `internal-wiki`, `external-upload`, `agent-memory`, ... | none |
| retrieval | `doc_title`, `retrieval_score` | Title, retriever score | |
| retrieval | `chunk_text` | Text exactly as placed into the context, truncated | `gen_ai.retrieval.documents` |
| tool_call | `tool_name` | Tool invoked | `gen_ai.tool.name` |
| tool_call | `tool_args` | Arguments as a JSON string, truncated | `gen_ai.tool.call.arguments` |
| tool_call | `tool_target` | **Normalized destination**: email domain, URL host, file path | none |
| tool_call | `tool_status` | `ok`, `denied`, `error` | |
| tool_call | `tool_risk` | `read`, `write`, `egress`, `destructive`, `exec`, `external` (MCP) | `gen_ai.tool.type` (partly) |
| tool_call | `tool_approval` | `not_required`, `auto` (no human configured), `approved`, `rejected` | none |
| tool_call | `tool_result` | Tool output as returned to the model, truncated to 1000 chars | `gen_ai.tool.call.result` |
| tool_call | `mcp_server` | MCP server providing the tool, empty for local tools | none |
| tool_registry | `mcp_server`, `tool_name`, `tool_key` | Server, tool, and `server/tool` as a stable key | `gen_ai.tool.name` |
| tool_registry | `tool_description` | Description exactly as the model receives it, truncated | `gen_ai.tool.description` |
| tool_registry | `tool_desc_sha256` | SHA-256 of the full description | none |
| memory_write | `memory_text` | What the agent stored for future sessions | `gen_ai.memory.*` (closest) |
| completion | `completion` | Final answer of the turn, truncated | `gen_ai.output.messages` |
| completion | `input_tokens`, `output_tokens` | Summed over every model call in the turn | `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` |
| completion | `finish_reason` | Of the last model call | `gen_ai.response.finish_reasons` |

OTel attribute names are from the
[OpenTelemetry GenAI semantic conventions](https://github.com/open-telemetry/semantic-conventions-genai)
(`model/gen-ai/registry.yaml`). If your application is already instrumented with OTel, the mapping
above is what a collector transform or a DCR `transformKql` has to produce.

## The fields that matter most

Most of the schema is what any LLM gateway logs. These fields are not, and the agentic detections
depend on them:

- **`tool_desc_sha256`** on `tool_registry`: hash what each MCP tool tells the model, every time a
  client connects. Without it, a rug pull (LLMD-014) is invisible: the tool name never changes.
- **`tool_risk` and `tool_approval`**: whether a human was in the loop for a dangerous tool is a
  configuration fact the application knows and the SIEM cannot infer (LLMD-016).
- **`tool_result`**: tool output enters the model's context with full authority; logging a preview
  is the only way to see runtime-response injection (LLMD-021).

- **`doc_source`**: without provenance on retrieved chunks you cannot tell "the model read a vendor
  upload" from "the model read the HR policy", and LLMD-007 (external content followed by egress)
  cannot exist. Tag provenance at indexing time and carry it through retrieval.
- **`tool_target`**: raw tool arguments are free-form JSON. Reducing every side-effecting call to
  the place data goes (domain, host, path) is what makes LLMD-006 and LLMD-007 writable as simple
  allowlist logic.

## Privacy

Prompts and completions are personal data in most deployments. The demo truncates them; in
production decide deliberately: hash or drop `prompt`/`completion` and keep only derived fields
(matched rule, secret type, URL host), restrict table access with Sentinel table-level RBAC, and set
retention to what your DPIA allows. Rules LLMD-001, -002, -004, -005, -011 and -012 need the text;
the rest work on metadata only.
