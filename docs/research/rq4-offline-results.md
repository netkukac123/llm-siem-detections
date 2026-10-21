# RQ4 Part A results: an adaptive attacker against content rules and classifiers

Code: `research/rq4_adaptive.py offline`, mutation operators in `research/mutations.py` (the LLM-based
paraphrase and translation operators run on a local model through Ollama). Seeds: 300 real prompt
injections from the public RQ2 datasets that the rules detect at baseline. Each seed was mutated by
12 operators (3891 mutants after the few failed LLM rewrites were dropped). A mutant counts as
detected if the rule set, or the classifier at its 0.5 threshold, flags it.

| Operator | Rules | ProtectAI DeBERTa v2 | Prompt Guard 2 22M | Any of the three |
|---|---|---|---|---|
| original | 1.00 | 1.00 | 1.00 | 1.00 |
| synonyms | 0.01 | 1.00 | 0.90 | 1.00 |
| leetspeak | 0.02 | 0.93 | 0.23 | 0.93 |
| zero-width characters | 0.02 | 0.98 | 1.00 | 1.00 |
| split words | 0.02 | 0.99 | 0.46 | 0.99 |
| homoglyphs | 0.03 | 0.95 | 0.29 | 0.95 |
| translation (Chinese, Hungarian, Spanish, Russian, German) | 0.06 to 0.07 | 0.63 to 0.73 | 0.19 to 0.24 | 0.64 to 0.75 |
| paraphrase (LLM rewrite, same intent) | 0.08 | 0.58 | 0.28 | 0.61 |
| base64 wrap | 0.92 | 1.00 | 0.00 | 1.00 |

## Reading

- Content signatures do not survive rewording. Of 300 attacks the rules caught, 1% survive a synonym
  swap and 8% survive a paraphrase. The only operator they survive is base64, and only because one
  rule (LLMD-011) looks for base64 blobs as such.
- The classifiers survive character-level tricks well (DeBERTa 0.93 to 1.00) but lose much of their
  recall under semantic rewriting: DeBERTa falls to 0.58 on paraphrase and 0.63 to 0.73 on
  translation. Prompt Guard 2 is weaker on almost every operator and misses every base64-wrapped seed.
- Even the union of all three detectors catches only 61% of paraphrased attacks.
- So an attacker who rewrites the injected text defeats text-based detection at the input, which is
  why the rest of the study looks at behaviour and at the model's own telemetry.

## Caveats

- DeBERTa numbers are an upper bound: some seed datasets may overlap its training data (see the
  contamination classes in `rq3_classifiers.py`).
- These are direct prompt-injection texts scored offline, not agent runs; a mutant that evades a
  detector may also have lost its effect on the model. Whether evasive injections still work on live
  agents is what RQ4c measures.
- The mutator is a local open model, so paraphrase and translation quality varies; a few rewrites
  failed and were dropped.
