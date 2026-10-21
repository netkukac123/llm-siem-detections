# RQ5b results: when the SIEM is blinded by the view gap

Pre-registration: `prereg-rq5b-view-gap-blinding.md` (main run) and
`prereg-rq5b-addendum-confirmation.md` (post-hoc observations and the confirmation design, committed
before the confirmation run). Code: `research/rq5b_eval.py`, `research/rq5b_confirm.py`. Models:
Claude Haiku 4.5, Sonnet 5.5, Opus 5.5. Wilson 95% intervals.

## Finding (confirmed on a fresh injection)

When an injected command sits in the gap between what the model reads (2000 characters of a tool
result) and what the application logs (1000), the SIEM's content rule is blind to it, and on the two
frontier models whose provider runs a safety classifier, the logged provider refusal is the only
SIEM-visible trace that an attack was attempted. That refusal fires when, and only when, the model
has read the instruction.

| | Main run (original wording) | Confirmation (fresh wording) |
|---|---|---|
| LLMD-021 recall, instruction in view (P0) | 1.00 [0.89, 1.00] pooled | 1.00 [0.89, 1.00] |
| LLMD-021 recall, instruction in the gap | 0.00 [0.00, 0.11] | 0.00 [0.00, 0.11] |
| Compliance in the gap, all three models | 0/30 | 0/30 |
| Opus provider refusal in the gap | 10/10 | 10/10 |
| Opus provider refusal, instruction outside the read window | 0/60 | 0/10 |
| Sonnet provider refusal in the gap | 2/10 | 10/10 |
| Other rules flagging a resisted gap run | 0 | 0 |

In the main run, Opus's provider classifier (category cyber) fired in every cell where the
instruction was inside the read window (gap 10/10, in-view middle 10/10, P0 7/10) and in none of the
60 runs where it was outside. Over the RQ5 workload the same provider refusal fired on 70 of 100 Opus
attack runs and 4 of 58 benign runs, and on Sonnet 23 of 100 and 1 of 58.

## What it means

RQ5 found that refusal telemetry adds nothing when the injection is in content the SIEM scans. RQ5b
shows the other side: an attacker who places the instruction past the logged window blinds the
content rule completely, and the logged provider refusal is then the only signal. A SIEM that drops
the refusal event, or an application that does not log it, sees nothing at all.

The useful form of the refusal rule is the provider path. The rule was split after the main run, and
the split was confirmed on fresh data: LLMD-023a (provider refusal event) had zero alerts on the
beyond-window controls in both runs, while LLMD-023b (refusal phrasing in the answer) produced false
positives there (Sonnet 0.20 in confirmation, 6 of 60 in the main run), firing on text such as "I
couldn't get a delivery status".

## Limits, stated plainly

- Haiku 4.5 returned no provider refusal in any run. On Haiku the gap-placed injection was neither
  followed, refused, nor mentioned, so it left no trace that any rule could use.
- The provider refusal here is the cyber category, triggered by a shell command. Whether it fires for
  other payload classes, such as data exfiltration by email, is tested in RQ4c, not assumed.
- How strongly the classifier fires depends on the exact payload: Sonnet refused 2 of 10 with the
  original wording and 10 of 10 with the reworded one.
- No frontier model complied with the gap-placed injection, so this is a result about detecting the
  attempt, not about catching a successful attack.
- When the provider refuses, the user gets an empty answer to an ordinary request. The injection does
  not succeed, but it does stop the agent from doing the user's task.

## Not reproduced

In the main run, LLMD-024 fired on three Sonnet gap runs whose reasoning said the model had noticed an
embedded instruction. In the confirmation it fired on none, because the provider refusal cut those
runs off before any reasoning was returned. This is reported as a main-run observation that did not
hold up.
