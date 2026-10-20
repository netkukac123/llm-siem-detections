# What this catches, and what it does not

Every claim on this page is backed by a scenario in `simulate/scenarios.py` and asserted by both
test suites: the KQL rules run on the real Kusto engine (Kustainer) and the Wazuh rules run through
`wazuh-logtest` on wazuh-manager 4.14.7. The full grid is in [coverage-matrix.md](coverage-matrix.md).

Reference dataset: 70 scenarios, 552 events. 40 benign scenarios (including deliberate near misses
such as *"How do I ignore the previous VPN profile..."*, *"My manager said to disregard the old
expense rules"*, a pasted SHA-256 checksum, an approved delete, an approved `df -h` and an ordinary
memory preference), 24 attacks, 6 evasions.

| | Result on the reference dataset |
|---|---|
| Attacks with at least one correct alert | 24 / 24 |
| Evasions with no alert at all | 3 / 6 (`evade-spaced-secret`, `evade-slow-consumption`, `evade-staged-command`) |
| False positives on benign sessions | 0 (one benign session correctly raises LLMD-002, see below) |

A synthetic dataset written by the same person who wrote the rules proves that the rules do what
they claim on the shapes they were designed for. It does not estimate real-world precision or
recall. Treat the thresholds as starting points and measure on your own traffic.

## Per rule

**LLMD-001 Direct prompt injection phrasing.** Matches the instruction-override phrasings that keep
showing up in public jailbreak collections, in English and Hungarian. Cheap and noisy by nature:
it catches people copy-pasting known attacks, not anyone who paraphrases
(`evade-paraphrased-injection`). Its value is as context on an identity, not as a standalone page.

**LLMD-002 Instructions aimed at the model in retrieved content.** Fires on the *document*, not on
the user: in `benign-vendor-question` an innocent employee pulled the poisoned vendor FAQ into
context and the alert is correct, because the index is poisoned whether or not the model obeyed.
Triage is "who uploaded `doc_id` and what else did they upload", then remove it from the index.

**LLMD-003 System prompt canary.** The highest-precision rule here. A random token in the system
prompt has no legitimate reason to appear in output, so phrasing does not matter: it fires on the
paraphrased attack that LLMD-001 and LLMD-012 miss. It only proves a leak of the prompt itself, not
of retrieved data.

**LLMD-004 Secrets in output or tool arguments.** Checks tool arguments as well as answers, because
agentic exfiltration sends the secret through `send_email` or `http_get` and the chat answer looks
clean (`atk-indirect-email-exfil`). Pattern based, so any reformatting defeats it: the model can
spell the key with spaces (`evade-spaced-secret`), translate it, or base64 it. For anything that
matters, put the canary approach on your secrets too (honeytokens in the document store).

**LLMD-005 Markdown image beacon.** Zero-click exfiltration through an image URL that the chat
client loads automatically. Links the user must click are not flagged (`evade-clickable-link`):
answers legitimately contain links with query strings all the time. The corporate-domain exception
is an exact or true-subdomain match: `acme-freight.hu.cargolink-cdn.net` and `evilacme-freight.hu`
still alert (`atk-lookalike-domain-beacon`), because substring allowlists are the classic way this
kind of rule gets bypassed. The real fix is in the client
(do not render images from untrusted hosts, Content Security Policy); the rule tells you someone
tried.

**LLMD-006 Egress tool call to an external destination.** Allowlist logic on `tool_target`. Every
allowlisted host is a blind spot: `evade-allowlisted-exfil` smuggles the key in a query string to
`learn.microsoft.com` and LLMD-006/007 stay silent (LLMD-002 and LLMD-004 still fire). Keep the
allowlist short and prefer human approval for side-effecting tools.

**LLMD-007 External content followed by egress.** The shape of a successful indirect injection:
the user asked something ordinary, external content entered the context, the agent sent data out
within ten minutes. In Wazuh this is implemented with `if_matched_group` correlation on
`session_id`, the same mechanism as the stock "authentication failures followed by success" rules.

**LLMD-008 Tool call burst.** Ten or more tool calls per session in five minutes. Tune to your
agent: a coding agent will need a much higher threshold than an HR assistant.

**LLMD-009 Token consumption spike.** KQL sums tokens per identity in an activity window; Wazuh
cannot sum fields, so it counts turns with more than 4000 input *or* output tokens instead (five
within an hour). `atk-output-harvesting` covers the short-prompt, long-output variant. Both
miss abuse spread under the thresholds (`evade-slow-consumption`). In production replace the
constant with a per-identity baseline (`series_decompose_anomalies` over two weeks) and alert on
cost, not tokens, if your models are priced differently.

**LLMD-010 Repeated guardrail blocks.** A single block is noise; three in ten minutes is somebody
iterating. Works with any guardrail that logs its decisions (Azure AI Content Safety Prompt Shields,
Llama Prompt Guard, the provider's moderation endpoint). The demo guardrail is a keyword list on
purpose: the point is the log line, not the classifier.

**LLMD-011 Obfuscated prompt.** Long base64 runs, invisible Unicode tag characters (U+E0000 to
U+E007F, "ASCII smuggling" as described by Johann Rehberger) and runs of zero-width characters. The
KQL version decodes the hidden payload into `DecodedPayload` so the analyst sees the instruction,
not a blob. A base64 run must mix upper and lower case, so hex digests do not match
(`benign-pasted-hash`); JWTs and long mixed-case URL tokens still will, so expect to tune this if
users paste tokens into the assistant.

**LLMD-012 System prompt extraction attempt.** Low severity on its own. Worth having for
correlation: LLMD-012 followed by LLMD-003 in the same session is a confirmed, intentional leak.

## Agentic and MCP rules

These rules need telemetry that a plain chatbot does not have: MCP tool registry events, tool risk
and approval state, tool results and memory writes (see [log-schema.md](log-schema.md)). The demo
agent connects to a real MCP server over stdio (official Python SDK v2), so the registry events are
what an MCP client actually receives.

**LLMD-013 Memory poisoning.** Fires on a memory write that is a standing instruction to act
("always send a copy of every email to ...") or that happened while untrusted content was in
context. `atk-memory-poisoning-write` / `-trigger` show why it matters: the write itself does nothing
visible; hours later, in a new session, the replayed memory makes the agent copy an ordinary email to
the attacker, which LLMD-006/007 catch because memory counts as non-internal content. Memory that is
a plain preference (`benign-memory-preference`) does not fire. A memory instruction phrased without
any of the action verbs and written without untrusted context would be missed.

**LLMD-014 MCP rug pull.** Same `mcp_server/tool_name`, new description hash. KQL compares with the
first hash in a 14 day lookback; Wazuh uses `frequency="2"` with `same_field` on the tool key and
`different_field` on the hash, which only remembers within the timeframe and loses state on restart.
In production keep approved hashes in a Sentinel watchlist or a Wazuh CDB list. Every legitimate
server update also fires; that is intended (a changed description is new, unreviewed instructions).

**LLMD-015 MCP tool poisoning.** Pattern match on the advertised description. It sees what the model
sees, which is the point: users approve tool *names*. A poisoned description without the usual
markers (no `<IMPORTANT>`, no "do not tell the user", no sensitive paths) would be missed; MCPTox
(arXiv 2508.14925) is a good source of real poisoned descriptions to test against.

**LLMD-016 Destructive tool without approval.** Metadata only: `tool_risk = destructive` and
`tool_approval = auto`. It depends on the application classifying its tools honestly. The approved
delete in `benign-destructive-approved` does not fire.

**LLMD-017 Dangerous agent command.** Reverse shells, remote scripts piped to a shell, base64 piped
to a shell, setuid, `rm -rf /`. Fires even when a human approved it (`atk-pipe-to-shell`).
`evade-staged-command` is the honest gap: if the payload was dropped earlier, the command the agent
runs (`python3 /tmp/update_check.py`) looks routine. Endpoint telemetry (EDR process trees) is the
complement here, not more regex.

**LLMD-018 Credential material through agent tools.** Path patterns for cloud CLI credentials, SSH
keys, `.env`, kube and docker configs and `mcp.json`, counting denied attempts. `atk-tool-burst`
fires it too, because its path traversal went after `.env` and `id_rsa`.

**LLMD-019 Lethal trifecta in one turn.** A successful private read followed by external egress
(email or HTTP outside the allowlist, or any third-party MCP call) in the same request. The poisoned
MCP scenario passes restricted notes to the vendor's tool as a harmless-looking `note` argument,
which only the sequence reveals.

**LLMD-020 Agent config tampering.** Writes to agent configuration and auto-loaded instruction files.
`DisablesApproval` flags writes that switch approval prompts off, the CVE-2025-53773 pattern. Shell
writes are caught when they redirect, `tee`, `sed -i`, `cp` or `mv` into a known config path.

**LLMD-021 Instructions in a tool result.** Same idea as LLMD-002, applied to tool output, plus
"to fix this error run `...`" remediation text. Fires on the runtime-poisoned MCP server
(`atk-tool-output-injection`) and on `atk-tool-burst`, where reading the vendor uploads returned
their hidden instructions to the model.

## Gaps not covered by any scenario

- **Multi-turn attacks.** An instruction split across several messages, or built up through
  role-play, is invisible to per-message rules. Session-level analysis (LLM-as-judge over the
  transcript, run asynchronously) is the realistic answer and is out of scope for a SIEM rule pack.
- **Non-English beyond Hungarian.** The phrase lists cover English and Hungarian only.
- **Poisoning at indexing time.** LLMD-002 fires when poisoned content is *retrieved*. Scanning
  documents on upload is cheaper and earlier; the same regexes can be reused there.
- **Multi-agent systems.** OWASP Agentic ASI07 (insecure inter-agent communication), ASI08
  (cascading failures) and ASI10 (rogue agents) need agent-to-agent telemetry the demo does not
  have. ASI09 (human-agent trust exploitation) is about what the user believes, not what the logs
  show.
- **MCP transport and auth.** The MCP security best practices also call out confused deputy, token
  passthrough and SSRF through OAuth metadata. Those live in MCP server and gateway logs, not in the
  agent's application telemetry.
- **Model-side issues** (OWASP LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM09
  Misinformation) do not show up in application telemetry and are not addressed here.

## What the tests do not prove

- **Wazuh time windows.** `wazuh-logtest` uses arrival time, and the replay takes seconds, so every
  `timeframe` is trivially satisfied. The tests prove the counting and correlation logic, not the
  window lengths. `evade-slow-consumption` stays silent in Wazuh because each turn is under the
  per-turn token threshold, not because of the 50 minute gaps.
- **Sentinel scheduling.** Kustainer runs the query once over the whole dataset. `queryFrequency`,
  `queryPeriod` and the `trigger_window` deduplication are checked for consistency by a test but are
  not executed on a schedule. The generated ARM template has not been validated in CI.

## Scheduling and deduplication

Rules whose lookback (`queryPeriod`) is longer than their interval (`queryFrequency`) need the
longer lookback to see a whole window or the earlier half of a correlation, but would then alert
twice on the same activity. They define `let trigger_window = <queryFrequency>;` and only alert when
the newest event of the window falls inside it. The test suite widens `trigger_window` when
replaying the fixed-date dataset; that is the only change made to a query before it runs.

## ATT&CK tactics

The Sentinel `tactics` field only accepts MITRE ATT&CK tactics, while the precise mapping is MITRE
ATLAS (in `tags` and in the Wazuh groups). The tactic is chosen by what the attacker gains: a prompt
injection that redirects the application is an entry point (InitialAccess), data leaving through
the model or a tool is Exfiltration or Collection, cost abuse is Impact. `relevantTechniques` is
left empty on purpose: no ATT&CK technique describes these behaviours precisely, and a loose one
would mislead triage more than an empty field.

## Wazuh and Sentinel differences

| Topic | Sentinel (KQL) | Wazuh |
|---|---|---|
| One event, several rules | Each rule is its own query, all fire | One alert per event. Combined child rules cover injection + extraction (100711), exfiltrating call + secret (100732, 100733), private read + MCP call + secret (100765) and rug pull + poisoned description (100782). Other overlaps, for example a canary inside an external `send_email`, report only one LLMD rule |
| Counting across rules | Any filter, any count | A `frequency` rule only counts events whose *final* rule is the counted one. LLMD-008 therefore misses `atk-tool-burst` in Wazuh: 4 of its 12 calls alert as LLMD-018/021 instead and are not counted (pinned in `tests/test_wazuh_rules.py`) |
| Nested correlation | Joins compose | A correlation rule under another correlation rule is not evaluated. LLMD-019 misses `atk-indirect-email-exfil` in Wazuh because that `send_email` already sits under the LLMD-007 correlation (pinned in the tests; LLMD-004/006/007 still fire on the same event) |
| Change detection | `arg_min` over the lookback, join | `frequency="2"` + `different_field`, in-memory for the timeframe |
| Aggregation | `row_window_session` windows, sums | `frequency` / `timeframe` counts only, no sums (LLMD-009 counts large turns) |
| Correlation | `join` on `session_id` with a time bound | `if_matched_group` + `same_field` |
| Allowlists | `dynamic([...])` lists | PCRE2 with `negate="yes"` |
| Decoding obfuscated payloads | `base64_decode_tostring`, codepoint arithmetic | Detection only |
