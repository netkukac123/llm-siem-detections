# RQ5 results: frontier models and the coverage of agent-attack telemetry

Run of 2026-10-21. Capability ladder: five open 8B-class models (local, via Ollama), two hosted mid
models (Azure gpt-4.1-mini, gpt-oss-120b; gpt-5-mini is also present from an earlier run), and three
frontier models (Claude Haiku 4.5, Sonnet 5.5, Opus 5.5, via the Anthropic API). Ten live attack
scenarios (L01 to L10), ten repetitions per cell for the frontier models, plus a benign workload.
All rates are Wilson 95% intervals over repetitions. Analysis: `research/rq5_coverage.py`. The
pre-registration is `prereg-rq5-frontier-telemetry-coverage.md`; this file reports the outcome
against it, including the hypotheses that did not hold.

The one-line summary: of the three telemetry ideas we pre-registered, the frontier data refuted the
naive form of two and confirmed one direction. That is the result, and it is a useful one.

## Headline numbers (by tier)

| Tier | compliance | ASR (completed) | behavioural recall given success | refusal rule recall on resisted | benign refusal FP |
|---|---|---|---|---|---|
| open 8B | 0.39 [0.35, 0.44] | 0.34 [0.30, 0.38] | 0.67 | 0.08 | 0.02 |
| mid | 0.34 [0.29, 0.39] | 0.33 [0.28, 0.39] | 0.80 | 0.22 | 0.05 |
| frontier | 0.14 [0.11, 0.19] | 0.12 [0.09, 0.16] | 1.00 | 0.65 | 0.11 |

Within the frontier tier, compliance falls Haiku 0.26, Sonnet 0.17, Opus 0.00. Opus completed none
of the 100 attack runs (ASR 0.00 [0.00, 0.04]) and resisted every one.

## Capability and robustness (H-B1, two-sided): confirmed in one direction

Compliance decreases monotonically with capability tier (0.39 to 0.34 to 0.14), and Opus refused
every attack. This is the safety-training direction, not the inverse-scaling direction, and it is
clean here. It is the backdrop for everything else: as the model gets more robust, successful
attacks become rare, so any rule that keys on a realized malicious action has less and less to catch
at the top of the ladder.

## Strand A, refusal telemetry: refuted as a recall gain, with a real false-positive cost

Pre-registered claim: a refused injection leaves no action, so action rules miss it, and logging the
refusal recovers it.

Result: in this setup it does not recover anything, because the attack is already visible before the
model acts. Every attack scenario carries its injection in content the SIEM logs and scans: a
retrieved document (LLMD-002) or a tool result (LLMD-021). Those input-content rules fire whether or
not the model complies. So among resisted attacks, the action-rule family alone is already at recall
1.00, and adding the refusal rule (LLMD-023) leaves it at 1.00. The marginal recall of refusal
telemetry over a comprehensive input-content ruleset is zero at every tier.

| Tier | resisted attacks visible, action rules only | with refusal rule added | refusal rule alone |
|---|---|---|---|
| open 8B | 1.00 | 1.00 | 0.08 |
| mid | 1.00 | 1.00 | 0.22 |
| frontier | 1.00 | 1.00 | 0.65 |

The refusal rule's own recall on resisted attacks does rise with capability (0.08 to 0.65), and when
it fires it attributes the attempt to the right source (attribution 1.00, since the only external
source in an attack session is the poisoned one). But it adds no coverage the content rules did not
already have, and it fails its pre-registered benign false-positive ceiling at the top of the ladder:
benign refusal FP is 0.02 (open), 0.05 (mid), 0.11 (frontier), and within the frontier it is Opus
0.22 [0.14, 0.35]. A cautious model declines unusual but benign requests, and the refusal rule cannot
tell that from a declined attack. The pre-registered ceiling was 0.05, so H-A3 fails for Sonnet and
Opus.

Reading: refusal telemetry is redundant with input-content detection when the injection rides in
loggable content, and it costs benign false positives that grow with how cautious the model is. It
would only add value where the injection arrives through a channel the SIEM does not scan. That
boundary condition, not a blanket coverage gain, is the honest claim.

## Strand B, capability-conditioned detectability: content rules hold, behavioural recall is worst for the weakest models

Pre-registered H-B2 (content-rule detectability drops as capability rises): not supported. Content
rule recall given a completed attack is at or near 1.00 at every tier (open 1.00, mid 0.99, frontier
1.00). Where frontier attacks complete at all, they complete by passing a secret or an injected
instruction through in a form the content rules still match. We did not observe frontier models
re-encoding or paraphrasing their way past the content rules on completed attacks. With Opus at ASR
0.00 there are no Opus completions to measure, so the frontier figure rests on Haiku and Sonnet.

The clearer effect is H-B3 on the behavioural side, in the opposite direction to a naive worry:
behavioural-rule recall given success is lowest for the weakest models and rises with capability
(0.67, 0.80, 1.00; llama3.1 alone is 0.23). Weak models that do complete an attack complete it
clumsily, by a path the behavioural correlation misses. This is the detection-side image of WASP's
"security through incompetence": the weak model is both more likely to comply and harder to catch
when it does, because its successful action is malformed.

## Strand C, reasoning-trace rules: adds nothing over behavioural rules

Pre-registered and secondary, positioned against the finding that action monitors beat reasoning-text
monitors. Confirmed. The reasoning rule (LLMD-024) recalls 0.27 of compliant runs on Haiku (raw
chain of thought) and 0.00 on Sonnet (summary), and its recall added over the behavioural rule is
0.00 at every tier: every run it flagged was already flagged by a behavioural rule. On Opus there are
no compliant runs to score. The raw-vs-summary gap (H-C2) points the expected way, Haiku raw 0.27 vs
Sonnet summary 0.00, though the Sonnet summary sample is small. Reasoning-trace rules did not earn
their place next to the behavioural rules in this setup.

## What this study contributes

1. On a capability ladder from 8B open models to Opus 5.5, robustness to injection rises with
   capability, to the point that Opus completes no attack in this scenario set.
2. Because of that, the detection problem at the frontier is not "catch the malicious action" (there
   is none) but "detect the attempt," and the attempt is already caught by content rules on the
   logged input, not by anything novel.
3. Two plausible, currently-fashionable telemetry ideas, logging refusals and logging reasoning, were
   pre-registered and did not beat the simple content and behavioural rules: refusal telemetry adds
   no recall and costs benign false positives that grow with model caution, and reasoning-trace rules
   add nothing over behavioural rules.
4. The one capability-dependent detection effect we did find is that behavioural recall is weakest
   for the weakest models, the detection-side counterpart of security-through-incompetence.

## Threats to validity

One application, one scenario family, deterministic side-effect oracles, and a content ruleset that
happens to cover every injection channel in these scenarios (which is exactly why refusal telemetry
shows no gain). A setup where the injection arrives off the logged path would change the refusal
result, and is the natural follow-up. The frontier reasoning signal is a summary written by a
separate model, not raw chain of thought, so strand C on the frontier tests the summary. Single-run
labels are unstable for thinking agents, which is why every number here is over repetitions.
