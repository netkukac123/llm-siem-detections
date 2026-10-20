# What this catches, and what it does not

Every claim on this page is backed by a scenario in `simulate/scenarios.py` and asserted by both
test suites: the KQL rules run on the real Kusto engine (Kustainer) and the Wazuh rules run through
`wazuh-logtest` on wazuh-manager 4.14.7. The full grid is in [coverage-matrix.md](coverage-matrix.md).

Reference dataset: 55 scenarios, 293 events. 37 benign scenarios (including deliberate near misses
such as *"How do I ignore the previous VPN profile..."*, *"My manager said to disregard the old
expense rules"* and a pasted SHA-256 checksum), 13 attacks, 5 evasions.

| | Result on the reference dataset |
|---|---|
| Attacks with at least one correct alert | 13 / 13 |
| Evasions with no alert at all | 2 / 5 (`evade-spaced-secret`, `evade-slow-consumption`) |
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

## Gaps not covered by any scenario

- **Multi-turn attacks.** An instruction split across several messages, or built up through
  role-play, is invisible to per-message rules. Session-level analysis (LLM-as-judge over the
  transcript, run asynchronously) is the realistic answer and is out of scope for a SIEM rule pack.
- **Non-English beyond Hungarian.** The phrase lists cover English and Hungarian only.
- **Poisoning at indexing time.** LLMD-002 fires when poisoned content is *retrieved*. Scanning
  documents on upload is cheaper and earlier; the same regexes can be reused there.
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
| One event, several rules | Each rule is its own query, all fire | One alert per event. Combined child rules cover injection + extraction (100711) and exfiltrating call + secret (100732, 100733). Other overlaps, for example a canary inside an external `send_email`, report only one LLMD rule |
| Aggregation | `row_window_session` windows, sums | `frequency` / `timeframe` counts only, no sums (LLMD-009 counts large turns) |
| Correlation | `join` on `session_id` with a time bound | `if_matched_group` + `same_field` |
| Allowlists | `dynamic([...])` lists | PCRE2 with `negate="yes"` |
| Decoding obfuscated payloads | `base64_decode_tostring`, codepoint arithmetic | Detection only |
