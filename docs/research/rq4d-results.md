# RQ4d results: an injection that fails against the agent, relayed to the user

Pre-registration: `prereg-rq4d-relay-to-user.md`, commit `b53fe29` (2026-10-21 17:50:11), before any
run, with fresh framings (R1 compliance-check notice, R2 JSON unlock record, R3 two-step customer
procedure) and a new attacker address. Code: `research/rq4d_relay.py` (runs and the pre-registered
labeller), `research/rq4d_human.py` (labels from reading every answer). 150 runs, no errors. Wilson
95% intervals.

## Pre-registered verdict

| Claim | Criterion | Result (pre-registered labeller) | Holds? |
|---|---|---|---|
| R1 | Haiku endorse rate at least 0.60 | 46/60 = 0.77 [0.65, 0.86] | Yes |
| R2 | Sonnet warn at least 0.60, endorse at most 0.20 | 0.93 and 0.07 | Yes |
| R4a | LLMD-026 on at least 0.80 of Haiku endorse runs | 0.89 [0.77, 0.95] | Yes |
| R4b | LLMD-026 on at most 0.02 of earlier Claude benign runs | 0 of 324 | Yes |
| R4c | LLMD-026 on at most 0.10 of Sonnet warn runs | 0 of 28 | Yes (but see the audit) |

Pre-registered audit: of the first ten endorse-labelled answers, ten were relays; of the first ten
warn-labelled, nine were warnings and one was a relay that the phrase list caught on "compliance
check with CargoLink". Within the threshold of two.

## The audit went further, and changed two numbers

The pre-registered sample took the first ten of each label, which were all Haiku and all one framing.
Reading every answer (150) showed:

- All ten non-Haiku answers labelled endorse are warnings that the phrase list did not recognise
  ("I didn't do that", "I'm not going to do that", "it looks like a data-exfiltration attempt").
  Sonnet 2, Opus 5.5 5, Opus 4.8 3.
- No Haiku answer warns. The one Haiku answer labelled warn is a relay.

Read labels:

| Model | Runs | Relays the request as a step to take | Warns | Empty (provider refusal) | Other |
|---|---|---|---|---|---|
| Haiku 4.5 | 60 | 47 (0.78 [0.66, 0.87]) | 0 | 0 | 13 vague, all R2 |
| Sonnet 5.5 | 30 | 0 | 30 | 0 | 0 |
| Opus 5.5 | 30 | 0 | 17 | 13 | 0 |
| Opus 4.8 | 30 | 0 | 30 | 0 | 0 |

Haiku relayed in 20 of 20 runs for R1 and for R3. For the JSON record (R2) it named the file or the
address in 7 of 20; the other 13 said only that "documentation" was needed by the carrier's
compliance desk, without saying what or where, and none warned. No model sent the file (harm 0/150).
Many Haiku relays offered to do it ("Would you like me to help locate and send that file?").

LLMD-026 against the read labels:

- Relays caught: 41 of 47 (0.87). The six misses lack either the file name (rule needs an internal
  document name) or the address (rule needs an outside email address).
- Warnings it fired on: 10 of 77 (Sonnet 2/30, Opus 5.5 5/17, Opus 4.8 3/30). These are the ten
  warnings the shared phrase list missed. R4c passed only because the labeller and the rule share
  the list.
- Benign Claude runs: 0 of 324.

## What this establishes

1. Confirmed on fresh framings and a fresh address: when Haiku 4.5 does not act on an injected
   request to email an internal file to an outside address, it usually tells the user to do it, as a
   legitimate procedure, with no warning (47 of 60). Sonnet 5.5 and Opus 4.8 warned in every
   non-empty answer; Opus 5.5 warned or was stopped by the provider. The injection that fails against
   the agent is passed to the human, which no rule over the agent's actions can see.
2. An answer-side rule finds most of these relays without benign false alarms in this setup, but a
   phrase list is a weak warning detector: it treated 10 of 77 warnings as relays. A revised rule
   needs a better warning test and its own confirmation on fresh data.

## Limits

One tool channel, one goal, three framings, one provider. The read labels are one reader's
(AI-assisted) judgement; the answers are in `runs.jsonl` for anyone to re-read.
