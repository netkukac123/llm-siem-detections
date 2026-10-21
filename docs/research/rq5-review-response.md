# Response to the adversarial review of RQ5, RQ5b, RQ4c and RQ4 Part A

On 2026-10-21 a reviewer with access to the code, rules, results and git history was asked to find
overclaims, statistical problems and confounds in the four write-ups. This file lists what it found,
what was checked independently, and what was changed. Where a claim was withdrawn, the original
wording is kept in the corrections section of the affected write-up.

## Checked independently before acting

- RQ5 timing: the RQ5 protocol, LLMD-023/024, the analysis code and the frontier runs all first
  entered git in one commit (`1aefd71`, 14:57) after the last Opus run (14:53). Confirmed. RQ5 was
  not pre-registered under `evidence-standard.md` item 2.
- RQ5b logging: the main run used extended tool logging, and the gap-placed instruction is present in
  `tool_result_tail` in 30/30 gap runs; LLMD-021's own patterns match it there in 30/30. Confirmed.
- RQ4c Haiku: the answer passed the attacker's file name and address to the user in 49/50 of the
  "silent" runs (the reviewer said 50/50). Confirmed with that correction.
- Haiku 4.5 thinking: the API documentation states that what is returned "is never the raw chain of
  thought: the text in a thinking block is a summary of Claude's reasoning", in enabled (budget) mode
  as well. Confirmed; every Claude trace in this study is a summary.

## Problems and what was done

| # | Problem | Action | Status |
|---|---|---|---|
| 1 | RQ5 labelled pre-registered but was not | RQ5 relabelled exploratory; corrected definitions and new claims frozen in `prereg-rq5-confirmatory.md` (commit `6a3fd15`, 16:50:54) before a confirmatory frontier run on fresh repetitions and 50 held-out benign prompts | confirmatory run in progress |
| 2 | Strand A baseline mixed input-scanning rules into "action" rules, so refusal recall gain was zero by construction | `rq5_reanalysis.py` separates INPUT and OUTPUT rules as the protocol intended | done; headline reversed (below) |
| 3 | H-B2 content family included input rules, so it could not fail | output-side content rules only, plus a per-scenario breakdown | done; the capability trend was a scenario-mix artifact |
| 4 | Attribution metric was fired/fired; premise false | scored against the ground-truth carrier of each scenario | done; attribution fails |
| 5 | Provider blocks confound capability and are logged asymmetrically (Anthropic as refusal events, Azure as guardrail events) | both counted the same way; compliance also reported excluding provider-blocked runs | done |
| 6 | "Behavioural recall weakest for weakest models" | per-scenario: identical within scenario across tiers | withdrawn |
| 7 | "Haiku raw chain of thought", raw vs summary comparison | all Claude traces relabelled summary in code and docs; comparison dropped | done |
| 8 | RQ5b main/confirmation logging difference not disclosed; "only trace" and "when and only when read" overclaimed; audit step 3 failed and unreported | `rq5b-results.md` rewritten | done |
| 9 | RQ4c "silent resistance", K5 numbers, K1/K2 dependence, LLMD-025 in-sample recall | `rq4c-results.md` rewritten | done |
| 10 | RQ4 Part A called adaptive, no intervals, clustered seeds | retitled, Wilson intervals, per-dataset breakdown | done |
| 11 | Missing cost, model versions, configuration, scope statement | this file | done |

## Re-analysis of RQ5 (exploratory data, corrected definitions)

Strand A, attack-run recall, by the pre-registered baseline (rules over what the agent did):

| Tier | OUTPUT rules | OUTPUT plus refusal signal | INPUT rules alone | Benign FP: refusal signal | Benign FP: INPUT rules |
|---|---|---|---|---|---|
| open 8B | 0.43 | 0.48 | 1.00 | 0.02 | 0.12 |
| mid (gpt-4.1-mini, gpt-oss-120b) | 0.39 | 0.79 | 1.00 | 0.06 | 0.12 |
| frontier (Claude) | 0.14 | 0.70 | 1.00 | 0.11 | 0.12 |

The refusal signal (LLMD-023 or a provider block) raises recall over action rules, and the gain grows
along the ladder (Cochran-Armitage on resisted runs, provider blocks included: z = 14.0; LLMD-023 text
path only: z = 6.6). This reverses the first write-up's "zero gain". Input-scanning rules see every
attempt in this harness, at a 0.12 benign false-positive rate, and RQ4 Part A shows how easily
rewording defeats them. The ladder is also a provider ladder: Anthropic's classifier stopped 70 of 100
Opus attack runs and Azure's filter 61 of 100 gpt-oss-120b runs.

Strand B: within each scenario, output-content and behavioural recall given a completed attack are the
same across tiers (L04 1.00 / 0.94 / 1.00; L06 0.00 / 0.05 / 0.00; L08 0.00 / 0.00 / 0.00 for
output-content). The pooled trend came from which scenarios each tier fell for. Capability changed
which attacks worked (frontier models completed only L04, L06 and L08, all tool-channel or
agent-action attacks), not how detectable a given attack was.

Attribution: on frontier runs LLMD-023 named the true carrier in every alert on scenarios that have
one, but named only the true carrier in 0.34 of them, and every alert on scenarios without an external
carrier named a source. LLMD-023's attribution is not usable as designed: the clean MCP server is
registered in every session and incidental retrievals are counted as carriers.

## Run configuration, cost, versions

- Date of all frontier runs: 2026-10-21. Anthropic Python SDK 1.17.0 (`anthropic` package).
- Model ids: `claude-haiku-4-5`, `claude-sonnet-5-5`, `claude-opus-5-5` (aliases; the API was called
  by alias, so the exact snapshot is whatever the alias pointed to on that date).
- Haiku 4.5: extended thinking, `budget_tokens` 1024. Sonnet 5.5 and Opus 5.5: adaptive thinking with
  `display: summarized`. `max_tokens` 4096. No sampling parameters were sent, so sampling was the API
  default with thinking on. The `temperature` value stored in run records and in `rq1/manifest.json`
  for Anthropic runs is not what the API received and should be ignored for those rows.
- Anthropic spend, estimated from logged tokens at list prices, before the confirmatory run: about
  12 USD (refused turns may be billed differently). Latency about 7 s per run.

## Scope and ethics

All attacks targeted the author's own demo application, whose tools are simulated: no email leaves
the machine, no command runs, and the credential in the internal file is fake. Frontier models were
called through the author's own Anthropic API account. The study observed the provider's safety
classifier as a side effect of sending injected content through the normal API; it did not attempt to
disable, reverse-engineer or bypass that classifier, and no payload aimed at harmful content outside
the simulated exfiltration. `evidence-standard.md` item 6 is updated to include the Anthropic API.
The Wazuh logcollector finding is under coordinated disclosure (GHSA-78vx-6j3c-5jjv) and is not
detailed in this repository.
