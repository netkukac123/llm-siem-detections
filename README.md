# LLM and AI agent attack detections for SIEM

[![test](https://github.com/netkukac123/llm-siem-detections/actions/workflows/test.yml/badge.svg)](https://github.com/netkukac123/llm-siem-detections/actions/workflows/test.yml)
![rules](https://img.shields.io/badge/detections-21-blue)
![Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-KQL-0078D4)
![Wazuh](https://img.shields.io/badge/Wazuh-4.14-3595F2)
![MCP](https://img.shields.io/badge/MCP-Python%20SDK%20v2-black)
![license](https://img.shields.io/badge/license-MIT-green)

Detection engineering for attacks on LLM applications and AI agents: prompt injection, RAG and
memory poisoning, MCP tool poisoning and rug pulls, agent tool abuse, data exfiltration and cost
harvesting. **21 detections** for **Microsoft Sentinel (KQL)** and **Wazuh**, mapped to the **OWASP
Top 10 for LLM Applications 2025**, the **OWASP Top 10 for Agentic Applications 2026** and **MITRE
ATLAS 2026.09**. A deliberately vulnerable RAG agent with a real MCP integration produces the
telemetry, and every rule is tested against a labelled dataset on the real query engines.

Most LLM deployments have a guardrail in front of the model and nobody watching what happens behind
it. This project starts from the SOC side: what an AI application has to log, which attacks show up
in those logs, and which do not.

## Highlights

- **Agentic and MCP coverage built on 2025-2026 research**: tool poisoning and rug pulls (Invariant
  Labs), runtime-response poisoning ("Agentjacking", 2026), persistent memory injection (SpAIware,
  Unit 42), agent config tampering (CVE-2025-53773, CVE-2025-54135), EchoLeak's reference-style image
  exfiltration (CVE-2025-32711), the "lethal trifecta" as a detection.
- **Real MCP, not a mock**: the demo agent talks to a third-party MCP server over stdio using the
  official Python SDK v2, and logs every advertised tool with a SHA-256 of its description.
- **Tested on real engines**: KQL runs unchanged on the Kusto engine (Kustainer), Wazuh rules run
  through `wazuh-logtest` on wazuh-manager 4.14.7, in CI on every push. **72 tests**.
- **Validated on a live Sentinel workspace**: table, DCR (Logs Ingestion API) and all 21 analytic
  rules deployed; 21/21 rules return exactly the labelled hits there too (2026-10-20).
- **Honest about limits**: evasion scenarios are asserted to stay undetected, Wazuh engine limits are
  pinned in tests, and [docs/coverage.md](docs/coverage.md) says what each rule misses.

## How it fits together

```mermaid
flowchart LR
    U[User / attacker] --> A[ragdemo agent]
    D[(Knowledge base<br/>internal + vendor uploads)] -->|retrieval| A
    M[(Long-term memory)] <-->|recall / remember| A
    A <-->|stdio, MCP SDK v2| S[Third-party MCP server<br/>clean / poisoned / rug pull / runtime]
    A -->|tools: email, http, files,<br/>shell, delete| T[Simulated side effects]
    A -->|JSONL telemetry<br/>OTel GenAI aligned| L[(LLMAppLogs)]
    L -->|Logs Ingestion API + DCR| SE[Microsoft Sentinel<br/>21 analytic rules]
    L -->|agent log_format json| W[Wazuh<br/>21 detections]
    G[simulate/ scenarios<br/>+ ground truth] --> A
    G -.labels.-> CI[CI: Kustainer + wazuh-logtest]
    L -.dataset.-> CI
```

## Detections

| ID | Detection | OWASP | MITRE ATLAS |
|---|---|---|---|
| LLMD-001 | Direct prompt injection phrasing (EN + HU) | LLM01 | AML.T0051.000 |
| LLMD-002 | Instructions aimed at the model inside retrieved content | LLM01, LLM08, ASI01 | AML.T0051.001, AML.T0070 |
| LLMD-003 | System prompt canary token in output | LLM07 | AML.T0056 |
| LLMD-004 | Credentials or IBANs in output **or tool arguments** | LLM02 | AML.T0057 |
| LLMD-005 | Auto-loading image beacon to external host (inline and EchoLeak reference-style) | LLM05, LLM02 | AML.T0077 |
| LLMD-006 | Side-effecting tool call to an external destination | LLM06, ASI02 | AML.T0053, AML.T0086 |
| LLMD-007 | Untrusted content in context, then egress within 10 min | LLM01, LLM06, ASI01 | AML.T0051.001, AML.T0086 |
| LLMD-008 | Burst of agent tool calls in one session | LLM06, LLM10, ASI02 | AML.T0053 |
| LLMD-009 | Token consumption spike per identity | LLM10 | AML.T0034, AML.T0029 |
| LLMD-010 | Repeated guardrail blocks (jailbreak iteration) | LLM01 | AML.T0054 |
| LLMD-011 | Obfuscated prompt: base64, Unicode tags, zero-width; payload decoded | LLM01 | AML.T0068 |
| LLMD-012 | System prompt extraction attempt | LLM07 | AML.T0056, AML.T0069 |
| **LLMD-013** | Persistent instruction written to agent long-term memory | ASI06 | AML.T0080.000, AML.T0094 |
| **LLMD-014** | MCP tool description changed after first use (rug pull) | ASI04 | AML.T0109, AML.T0110.000 |
| **LLMD-015** | Hidden instructions in an MCP tool description (tool poisoning) | ASI04, ASI01 | AML.T0110.000 |
| **LLMD-016** | Destructive agent tool executed without human approval | ASI02 | AML.T0101 |
| **LLMD-017** | Dangerous shell command issued by an agent | ASI05 | AML.T0102, AML.T0072 |
| **LLMD-018** | Credential material targeted through agent tools | ASI03 | AML.T0098, AML.T0083 |
| **LLMD-019** | Private data read and sent out in the same turn (lethal trifecta) | ASI02, ASI01 | AML.T0085.001, AML.T0086 |
| **LLMD-020** | Agent modifies agent configuration (auto-approve, MCP config) | ASI03, ASI05 | AML.T0081 |
| **LLMD-021** | Instructions aimed at the agent inside a tool result | ASI01, ASI04 | AML.T0110.002 |

ATLAS IDs are checked against ATLAS data 2026.09. OWASP LLM03, LLM04 and LLM09 are model and supply
chain risks that do not show up in application telemetry, so they are out of scope.

## Grounded in real attacks

| Real-world attack or research | What it showed | Rule |
|---|---|---|
| Invariant Labs, MCP tool poisoning disclosure (2025) | Instructions hidden in MCP tool descriptions; descriptions that change after approval | 015, 014 |
| CVE-2025-54136 "MCPoison" (Cursor, 2025) | Approved MCP config swapped afterwards, persistent code execution | 014 |
| CVE-2025-53773 (GitHub Copilot, 2025) | Injection makes the agent enable auto-approve in its own settings, then run commands | 020, 017 |
| CVE-2025-54135 (Cursor, 2025) | Agent writes a new `.cursor/mcp.json` without approval | 020 |
| CVE-2025-32711 EchoLeak (Microsoft 365 Copilot, 2025) | Zero-click exfiltration through a reference-style markdown image | 005 |
| "Agentjacking" (Tenet Security, 2026) | Fake error reports with "fix" commands; coding agents ran attacker packages | 021, 017 |
| CVE-2026-75130 (Context7 MCP, 2026) | Poisoned instructions served through MCP make agents read `.env` and delete files | 021, 018 |
| SpAIware (Rehberger, 2024), Unit 42 on Bedrock Agents memory (2025) | Prompt injection persisted in long-term memory, exfiltration in later sessions | 013, 007 |
| GitHub MCP exploit (Invariant Labs, 2025), Supabase MCP leak (General Analysis, 2025) | Untrusted input, private data read, data written to an attacker-visible sink | 019 |
| "The lethal trifecta" (Simon Willison, 2025) | Private data + untrusted content + external communication = data theft | 019, 007 |

Each scenario in `simulate/scenarios.py` reproduces the *shape* of one of these attacks against the
demo agent; full references below.

## What it catches and what it does not

Reference dataset: 70 scenarios, 552 events. 40 benign scenarios, including deliberate near misses
(*"ignore the previous VPN profile"*, a pasted SHA-256, approved deletes and shell commands), 24
attacks, 6 evasions. Every attack raises at least one correct alert, no benign session raises a false
one (one benign session correctly raises LLMD-002 because it pulled a poisoned document into context).
The evasion scenarios exist to show the limits and are asserted to stay undetected:

- a paraphrased injection gets past LLMD-001/012, but the canary (LLMD-003) still catches the leak;
- a secret spelled with spaces gets past LLMD-004;
- a clickable link instead of an image gets past LLMD-005;
- exfiltration to an allowlisted host gets past LLMD-006/007;
- token abuse spread thinly gets past LLMD-009;
- a payload staged earlier and run as `python3 /tmp/update_check.py` gets past LLMD-017.

Wazuh implements all 21 detections, with two engine limits pinned in the tests (frequency counting
and nested correlation; see [docs/coverage.md](docs/coverage.md#wazuh-and-sentinel-differences)).
This is a synthetic dataset written by the same person who wrote the rules: it proves the rules
behave as designed, it does not measure real-world precision. Full grid:
[docs/coverage-matrix.md](docs/coverage-matrix.md).

## Telemetry first

The rules are only as good as the logs. The schema ([docs/log-schema.md](docs/log-schema.md)) is
aligned with the OpenTelemetry GenAI semantic conventions and adds the fields most AI applications do
not log, but agent detections need:

- `doc_source`: provenance of every chunk in context (internal wiki, external upload, agent memory);
- `tool_target`, `tool_risk`, `tool_approval`: where a tool call sends data, how dangerous the tool
  is, and whether a human approved it;
- `tool_result`: a preview of what the tool returned, where runtime-response injection arrives;
- `tool_registry` events with `tool_desc_sha256`: what each MCP tool told the model, hashed;
- `memory_write` events: what the agent stored for future sessions.

## Quick start

Requires Python 3.10+ and Docker.

```bash
python -m venv .venv && . .venv/bin/activate
pip install pytest pyyaml "mcp>=2.3,<3"

make engines        # Kustainer (Kusto emulator) + wazuh-manager 4.14.7
make test           # 72 tests: app, 21 KQL rules, 21 Wazuh rules
make engines-down
```

`make dataset` regenerates the dataset (deterministic; it starts the real MCP server in its four
variants). Talk to the vulnerable agent with a real model through any OpenAI-compatible endpoint,
for example Ollama:

```bash
python -m ragdemo chat --backend openai --base-url http://localhost:11434/v1 --model llama3.1
```

The reference dataset uses a scripted model instead, so it records what a model that *follows* the
injection would do, independent of which model complies on a given day.

Deploying: [Microsoft Sentinel](docs/deploy-sentinel.md) | [Wazuh](docs/deploy-wazuh.md).

## How the tests work

- **KQL**: the analytic rule queries run unchanged on
  [Kustainer](https://learn.microsoft.com/azure/data-explorer/kusto-emulator-overview), the Kusto
  engine in a container, against the dataset loaded as `LLMAppLogs_CL`.
- **Wazuh**: the ruleset is copied into a wazuh-manager container and the dataset is replayed through
  the `wazuh-logtest` socket in one session, so frequency and correlation rules keep state.
- Each rule must flag exactly the sessions (or identities) labelled for it: no misses, no extras, and
  documented gaps stay silent. CI runs all of it on every push.
- **Live Sentinel**: table, DCR and all analytic rules were deployed to a real Sentinel workspace,
  the dataset was sent through the Logs Ingestion API, and `deploy/sentinel/verify_live.py` checked
  every rule against the labels there (manual, not part of CI).
- Not covered by the tests: Wazuh `timeframe` lengths (logtest replays in seconds), Sentinel
  scheduling. See [docs/coverage.md](docs/coverage.md#what-the-tests-do-not-prove).

## References

Frameworks
- OWASP, [Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- OWASP, [Top 10 for Agentic Applications 2026](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) (December 2025)
- MITRE, [ATLAS](https://atlas.mitre.org/) ([atlas-data](https://github.com/mitre-atlas/atlas-data), 2026.09)
- Model Context Protocol, [Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- OpenTelemetry, [GenAI semantic conventions](https://github.com/open-telemetry/semantic-conventions-genai)

Attacks and research
- Invariant Labs, [MCP Security Notification: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), 2025
- Invariant Labs, [GitHub MCP Exploited: Accessing private repositories via MCP](https://invariantlabs.ai/blog/mcp-github-vulnerability), 2025
- General Analysis, [Supabase MCP can leak your entire SQL database](https://www.generalanalysis.com/blog/supabase-mcp-blog), 2025
- Check Point Research, [Cursor IDE: Persistent Code Execution via MCP Trust Bypass](https://blog.checkpoint.com/research/cursor-ide-persistent-code-execution-via-mcp-trust-bypass/) (CVE-2025-54136), 2025
- J. Rehberger, [GitHub Copilot: Remote Code Execution via Prompt Injection](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/) (CVE-2025-53773), 2025
- P. Reddy, A. S. Gujral, [EchoLeak: The First Real-World Zero-Click Prompt Injection Exploit in a Production LLM System](https://arxiv.org/abs/2509.10540) (CVE-2025-32711), 2025
- Tenet Security, [Agentjacking: coding agents hijacked with fake Sentry errors](https://tenetsecurity.ai/blog/agentjacking-coding-agents-with-fake-sentry-errors/), 2026
- NVD, [CVE-2026-75130](https://nvd.nist.gov/vuln/detail/CVE-2026-75130) (Context7 MCP prompt injection), 2026
- J. Rehberger, [Spyware Injection Into Your ChatGPT's Long-Term Memory (SpAIware)](https://embracethered.com/blog/posts/2024/chatgpt-macos-app-persistent-data-exfiltration/), 2024
- Unit 42, [When AI Remembers Too Much: Persistent Behaviors in Agents' Memory](https://unit42.paloaltonetworks.com/indirect-prompt-injection-poisons-ai-longterm-memory/), 2025
- S. Willison, [The lethal trifecta for AI agents](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/), 2025
- Z. Wang et al., [MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers](https://arxiv.org/abs/2508.14925), 2025
- Greshake et al., [Not what you've signed up for: Indirect Prompt Injection](https://arxiv.org/abs/2302.12173), 2023
- J. Rehberger, [ASCII Smuggler: Crafting Invisible Text and Decoding Hidden Codes](https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/), 2024

Defenses worth reading next to the detections: Debenedetti et al.,
[CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813) (2025);
Beurer-Kellner, Tramèr et al.,
[Design Patterns for Securing LLM Agents against Prompt Injections](https://arxiv.org/abs/2506.08837) (2025);
Meta, [LlamaFirewall](https://arxiv.org/abs/2505.03574) (2025).

The AWS credentials in the demo corpus are AWS's documented example values (`AKIAIOSFODNN7EXAMPLE`);
all names, domains and accounts are fictional. No command is ever executed and nothing leaves the
machine: every side-effecting tool is simulated.

## License

MIT
