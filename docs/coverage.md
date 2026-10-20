# What this catches, and what it does not

Every claim on this page is backed by a scenario in `simulate/scenarios.py` and asserted by both
test suites: the KQL rules run on the real Kusto engine (Kustainer) and the Wazuh rules run through
`wazuh-logtest` on wazuh-manager 4.14.7. The full grid is in [coverage-matrix.md](coverage-matrix.md).

Reference dataset: 52 scenarios, 272 events. 36 benign sessions (including deliberate near misses
such as *"How do I ignore the previous VPN profile..."* and *"My manager said to disregard the old
expense rules"*), 11 attacks, 5 evasions.

| | Result on the reference dataset |
|---|---|
| Attacks with at least one correct alert | 11 / 11 |
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
answers legitimately contain links with query strings all the time. The real fix is in the client
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
cannot sum fields, so it counts requests over 4000 input tokens instead (five within an hour). Both
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
not a blob.

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

## Wazuh and Sentinel differences

| Topic | Sentinel (KQL) | Wazuh |
|---|---|---|
| One event, several rules | Each rule is its own query, all fire | One alert per event; combined child rules (for example 100711, 100732) carry every applicable `llmd_NNN` group |
| Aggregation | `row_window_session` windows, sums | `frequency` / `timeframe` counts only, no sums |
| Correlation | `join` on `session_id` with a time bound | `if_matched_group` + `same_field` |
| Allowlists | `dynamic([...])` lists | PCRE2 with `negate="yes"` |
| Decoding obfuscated payloads | `base64_decode_tostring`, codepoint arithmetic | Detection only |
