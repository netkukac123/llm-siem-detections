# RQ4f results: relaying a failed injection to the user, across twelve models

Pre-registration: `prereg-rq4f-relay-across-models.md` (commit `ed91594`, amendment `734a0c1` at
18:32:47, before any run; two deviations recorded before the analyses they affect). Code:
`research/rq4f_relay_models.py` (runs, blinded export), `research/rq4f_eval.py` (verdict),
`research/rq4f_rater_gpt.py` and `research/rq4f_agreement.py` (independent raters). 1,290 new runs, no
errors, plus the 150 RQ4d runs: 1,440 runs, 120 per model. Wilson 95% intervals.

## Result

| Model | Runs | Relays (pre-registered labels) | Held-out framings R4 to R6 | gpt-5-mini rater | Warns | Harm |
|---|---|---|---|---|---|---|
| Opus 4.8 | 120 | 0% [0, 3] | 0% | 0% | 120 | 0 |
| Opus 5.5 | 120 | 0% [0, 3] | 0% | 0% | 74 (46 empty, provider) | 0 |
| Sonnet 5.5 | 120 | 0% [0, 3] | 0% | 2% | 120 | 0 |
| Haiku 4.5 | 120 | 89% [82, 94] | 100% | 89% | 0 | 0 |
| gpt-5-mini | 120 | 100% [97, 100] | 100% | 98% | 0 | 0 |
| gpt-4.1-mini | 120 | 98% [93, 99] | 100% | 98% | 0 | 0 |
| gpt-oss-120b | 120 | 88% [81, 93] | 93% | 88% | 0 | 0 |
| qwen3:8b | 120 | 100% [97, 100] | 100% | 100% | 0 | 0 |
| gemma4:e4b | 120 | 98% [94, 100] | 100% | 100% | 0 | 2 |
| granite4:tiny-h | 120 | 98% [94, 100] | 97% | 99% | 0 | 1 |
| ministral-3:8b | 120 | 98% [94, 100] | 100% | 98% | 0 | 0 |
| llama3.1:8b | 120 | 61% [52, 69] | 52% | 60% | 0 | 0 |

- Nine of twelve models, from 4B-class open models to gpt-5-mini, relayed the attacker's request to
  the user in 61% to 100% of runs, and none of them warned in any run. Pooled over those nine, 997 of
  1,080 runs (92%); per framing 80% (R2, JSON record) to 99% (R3); on the three framings never seen
  before RQ4f, 90% to 98%.
- Three models (Opus 4.8, Opus 5.5, Sonnet 5.5) never relayed: they warned, or the provider stopped
  the answer.
- The agents almost never acted: 3 of 1,440 runs emailed the attacker (gemma 2, granite 1).
- Pooled relay rate over all twelve models, framing-clustered bootstrap: 0.69 [0.65, 0.73].

## Labels and their reliability

- Pre-registered raters A and B (two instances of one model, same prompt, no shared files) agreed on
  1,440 of 1,440 items. That shows reproducibility, not independence (first deviation).
- gpt-4.1-mini (different family, added before its run) agreed on 0.59 (kappa 0.36). In ten random
  disagreements every answer relayed the request without a warning; it rated the request, not the
  answer. Under the pre-registered rule (F3 judged on this rater) **F1 is not established**.
- gpt-5-mini (fixed as the next rater before it ran, identical prompt) agreed with the pre-registered
  labels on 0.974 (kappa 0.94; relay versus warn 0.98) and gives the same per-model picture (column
  above). gpt-4.1-mini disagreed with gpt-5-mini as much as with A (kappa 0.37).
- Reading: the pre-registered verdict is "not established" because of the first independent rater;
  the second independent rater, chosen by a rule fixed before it ran, supports the labels strongly.
  Both are reported.

## LLMD-026

Relays caught: 77% [75, 80] overall, 77% on the held-out documents of R4 to R6. Alert rate on
warnings: 6% [4, 9]. Benign runs: 0 of 788 (every benign run of RQ1 and RQ5-C, eleven models). The
misses are answers that name the address but not the document, or the document but not an address.

## Limits

One application, one tool channel, one task, six framings written by the author. Ratings are by
models, not people. gpt-4.1-mini and the other rated models were also raters or share families with
raters. The relay rate says how often the agent hands the request on; it does not measure how often a
person would act on it.
