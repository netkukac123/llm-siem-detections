# LLM attack detections for SIEM

Detection rules for attacks on LLM applications (prompt injection, RAG poisoning, data leakage,
agent tool abuse, cost harvesting) written for **Microsoft Sentinel (KQL)** and **Wazuh**, mapped
to the **OWASP Top 10 for LLM Applications 2025** and **MITRE ATLAS**. A deliberately vulnerable
RAG assistant produces the telemetry, and every rule is tested against a labelled dataset on the
real query engines.

Most LLM deployments have a guardrail in front of the model and nobody watching what happens
behind it. This project starts from the SOC side: what the application has to log, which attacks
show up in those logs, and which do not.

## What is inside

```
ragdemo/                 vulnerable RAG assistant (stdlib Python) that writes JSONL telemetry
simulate/                benign, attack and evasion scenarios with ground truth -> datasets/
datasets/                reference dataset (272 events) and labels
detections/sentinel/     12 scheduled analytic rules (Azure-Sentinel YAML format)
detections/wazuh/        the same 12 detections as a Wazuh ruleset + agent config
deploy/sentinel/         custom table, DCR (Logs Ingestion API), ingest script, rules -> ARM
tests/                   KQL rules on Kustainer, Wazuh rules on wazuh-logtest, app unit tests
docs/                    log schema, coverage analysis, deployment guides
```

## Detections

| ID | Detection | OWASP LLM 2025 | MITRE ATLAS |
|---|---|---|---|
| LLMD-001 | Direct prompt injection phrasing (EN + HU) | LLM01 | AML.T0051.000 |
| LLMD-002 | Instructions aimed at the model inside retrieved content | LLM01, LLM08 | AML.T0051.001, AML.T0070 |
| LLMD-003 | System prompt canary token in output | LLM07 | AML.T0056 |
| LLMD-004 | Credentials or IBANs in output **or tool arguments** | LLM02 | AML.T0057 |
| LLMD-005 | Auto-loading markdown image beacon to external host | LLM05, LLM02 | AML.T0077 |
| LLMD-006 | Side-effecting tool call to an external destination | LLM06 | AML.T0053, AML.T0086 |
| LLMD-007 | External content in context, then egress within 10 min | LLM01, LLM06 | AML.T0051.001, AML.T0086 |
| LLMD-008 | Burst of agent tool calls in one session | LLM06, LLM10 | AML.T0053 |
| LLMD-009 | Token consumption spike per identity | LLM10 | AML.T0034, AML.T0029 |
| LLMD-010 | Repeated guardrail blocks (jailbreak iteration) | LLM01 | AML.T0054 |
| LLMD-011 | Obfuscated prompt: base64, Unicode tags, zero-width; payload decoded | LLM01 | AML.T0068 |
| LLMD-012 | System prompt extraction attempt | LLM07 | AML.T0056, AML.T0069 |

ATLAS IDs are checked against ATLAS data v5.6.0. OWASP LLM03, LLM04 and LLM09 are model and supply
chain risks that do not appear in application telemetry, so they are out of scope.

## What it catches and what it does not

On the reference dataset (36 benign sessions including deliberate near misses, 11 attacks,
5 evasions) every attack raises at least one correct alert and no benign session raises a false one.
The five evasion scenarios exist to show the limits, and the tests assert that they stay undetected
so the documentation cannot quietly drift:

- a paraphrased injection gets past LLMD-001/012, but the canary (LLMD-003) still catches the leak;
- a secret spelled with spaces gets past LLMD-004;
- a clickable link instead of an image gets past LLMD-005;
- exfiltration to an allowlisted host gets past LLMD-006/007;
- token abuse spread thinly gets past LLMD-009.

Details and tuning notes per rule: [docs/coverage.md](docs/coverage.md). Full grid:
[docs/coverage-matrix.md](docs/coverage-matrix.md). This is a synthetic dataset written by the same
person who wrote the rules: it proves the rules behave as designed, it does not measure real-world
precision.

## Telemetry first

The rules are only as good as the logs. The schema ([docs/log-schema.md](docs/log-schema.md)) is
mapped to the OpenTelemetry GenAI semantic conventions and adds two fields most applications do not
log but several detections need:

- `doc_source`: provenance of every retrieved chunk (internal wiki vs. external upload);
- `tool_target`: the normalized place a tool call sends data (email domain, URL host, path).

## Quick start

Requires Python 3.10+ and Docker.

```bash
python -m venv .venv && . .venv/bin/activate
pip install pytest pyyaml

make engines        # Kustainer (Kusto emulator) + wazuh-manager 4.14.7
make test           # 33 tests: app, 12 KQL rules, 12 Wazuh rules
make engines-down
```

Regenerate the dataset after changing scenarios: `make dataset` (deterministic, the tests check
that the committed files match).

Talk to the vulnerable assistant with a real model through any OpenAI-compatible endpoint, for
example Ollama:

```bash
python -m ragdemo chat --backend openai --base-url http://localhost:11434/v1 --model llama3.1
# try: "Summarise the CargoLink price list" or "When is the CargoLink pickup cutoff?"
```

Events go to `logs/ragdemo.jsonl`. The reference dataset uses a scripted model instead, so that it
records what a model that *follows* the injection would do, independent of which model happens to
comply on a given day.

Deploying: [Microsoft Sentinel](docs/deploy-sentinel.md) | [Wazuh](docs/deploy-wazuh.md).

## How the tests work

- **KQL**: the analytic rule queries run unchanged on
  [Kustainer](https://learn.microsoft.com/azure/data-explorer/kusto-emulator-overview), the Kusto
  engine in a container, against the dataset loaded as `LLMAppLogs_CL`.
- **Wazuh**: the ruleset is copied into a wazuh-manager container and the dataset is replayed
  through the `wazuh-logtest` socket in one session, so frequency and correlation rules keep state.
- Each rule must flag exactly the sessions (or identities) labelled for it: no misses, no extras,
  and documented gaps stay silent. CI runs all of it on every push.

## References

- OWASP, [Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- MITRE, [ATLAS](https://atlas.mitre.org/) ([atlas-data](https://github.com/mitre-atlas/atlas-data), v5.6.0)
- Greshake et al., [Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection](https://arxiv.org/abs/2302.12173), 2023
- J. Rehberger, [ASCII Smuggler: Crafting Invisible Text and Decoding Hidden Codes](https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/), 2024
- OpenTelemetry, [GenAI semantic conventions](https://github.com/open-telemetry/semantic-conventions-genai)
- Microsoft, [Logs Ingestion API in Azure Monitor](https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview)

The AWS credentials in the demo corpus are AWS's documented example values
(`AKIAIOSFODNN7EXAMPLE`); all names, domains and accounts are fictional.

## License

MIT
