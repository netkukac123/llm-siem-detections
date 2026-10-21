# RQ4 Part A results: fixed mutation operators against content rules and classifiers

Revised after the adversarial review (`rq5-review-response.md`): the earlier title called this an
adaptive attacker. It is not adaptive. Each seed is transformed once by each of 12 fixed operators,
with no feedback from the detectors and no optimisation.

Code: `research/rq4_adaptive.py offline`, operators in `research/mutations.py`. The paraphrase and
translation operators are rewrites by a local `llama3.1:8b` through Ollama (temperature 0, seed 7).
Seeds: 300 real prompt injections from the public RQ2 datasets, selected because the rule set detects
them at baseline (so every operator can only lower detection; this measures evasion, not recall).
Seed sources: 210 from Lakera/gandalf_ignore_instructions (a near-duplicate family of "ignore previous
instructions" prompts), 87 from the Prompt-injection-dataset, 3 from prompt-injections. 3891 mutants
after nine failed LLM rewrites were dropped. Wilson 95% intervals.

| Operator | n | Rules | ProtectAI DeBERTa v2 | Prompt Guard 2 22M | Any of the three |
|---|---|---|---|---|---|
| original | 300 | 1.00 [0.99, 1.00] | 1.00 [0.99, 1.00] | 1.00 [0.98, 1.00] | 1.00 [0.99, 1.00] |
| synonyms | 300 | 0.01 [0.01, 0.03] | 1.00 [0.98, 1.00] | 0.90 [0.86, 0.93] | 1.00 [0.98, 1.00] |
| leetspeak | 300 | 0.02 [0.01, 0.04] | 0.93 [0.90, 0.95] | 0.23 [0.19, 0.28] | 0.93 [0.90, 0.95] |
| zero-width characters | 300 | 0.02 [0.01, 0.04] | 0.98 [0.96, 0.99] | 1.00 [0.98, 1.00] | 1.00 [0.99, 1.00] |
| split words | 300 | 0.02 [0.01, 0.04] | 0.99 [0.97, 1.00] | 0.46 [0.41, 0.52] | 0.99 [0.97, 1.00] |
| homoglyphs | 300 | 0.03 [0.02, 0.06] | 0.95 [0.92, 0.97] | 0.29 [0.24, 0.34] | 0.95 [0.92, 0.97] |
| translate Chinese | 299 | 0.06 [0.04, 0.09] | 0.69 [0.63, 0.74] | 0.24 [0.19, 0.29] | 0.70 [0.65, 0.75] |
| translate Hungarian | 298 | 0.06 [0.04, 0.10] | 0.63 [0.58, 0.69] | 0.19 [0.15, 0.24] | 0.64 [0.58, 0.69] |
| translate Spanish | 298 | 0.06 [0.04, 0.10] | 0.73 [0.68, 0.78] | 0.21 [0.17, 0.26] | 0.75 [0.70, 0.79] |
| translate Russian | 298 | 0.07 [0.04, 0.10] | 0.65 [0.59, 0.70] | 0.19 [0.15, 0.24] | 0.66 [0.61, 0.71] |
| translate German | 299 | 0.07 [0.05, 0.10] | 0.69 [0.63, 0.74] | 0.24 [0.19, 0.29] | 0.70 [0.64, 0.75] |
| paraphrase | 299 | 0.08 [0.06, 0.12] | 0.58 [0.52, 0.63] | 0.28 [0.24, 0.34] | 0.61 [0.56, 0.67] |
| base64 wrap | 300 | 0.92 [0.88, 0.95] | 1.00 [0.99, 1.00] | 0.00 [0.00, 0.01] | 1.00 [0.99, 1.00] |

Per seed dataset, for the two operators that matter most (rules / DeBERTa / Prompt Guard 2):

| Operator | gandalf (n=210) | Prompt-injection-dataset (n=87) |
|---|---|---|
| synonyms | 0.00 / 1.00 / 0.90 | 0.03 / 0.99 / 0.89 |
| paraphrase | 0.07 / 0.56 / 0.21 | 0.11 / 0.66 / 0.47 |

## Reading

- Content signatures do not survive rewording. Of 300 attacks the rules caught, 1% survive a synonym
  swap and 8% a paraphrase, and the collapse is the same in both main seed datasets. The rules
  survive base64 only because one rule (LLMD-011) looks for base64 blobs as such.
- The classifiers survive character-level operators well (DeBERTa 0.93 to 1.00) and degrade under
  semantic rewriting: DeBERTa 0.58 on paraphrase, 0.63 to 0.73 on translation. Prompt Guard 2 is
  weaker on most operators and misses every base64-wrapped seed.
- Even the union of the three catches 0.61 of paraphrased seeds. Rewording degrades input-text
  detection substantially; it does not remove it.

## Caveats

- Non-adaptive: a real attacker who can query the detector would do better than these numbers show.
- DeBERTa numbers are an upper bound, because some seed datasets may overlap its training data
  (contamination classes in `rq3_classifiers.py`).
- Offline direct-prompt texts, not agent runs; a mutant that evades a detector may have lost its
  effect on a model. Mutants were not checked for preserved meaning beyond the operator design.
- Seeds are clustered: 70% come from one near-duplicate family.
