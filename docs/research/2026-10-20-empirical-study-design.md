# Empirical study design: SIEM detection of LLM and agent attacks

Working title: *Watching the Agents: An Empirical Study of SIEM-Based Detection for LLM and Agentic
AI Attacks.*

Status: design, 2026-10-20. Phase 1 uses open-weight models on local hardware; frontier models are a
later phase (RQ5) with the same harness.

## Why

The repository's current evidence is a synthetic, scripted dataset written by the same person as the
rules. It shows the rules behave as designed, nothing more. A reviewer's first questions are: do the
attacks work on real models, do the rules catch them when they do, what do the rules cost in false
positives on real traffic, how do they compare with ML detectors, and how fast do they break under an
adaptive attacker. This study answers those with measurements.

## Research questions

**RQ1. Live attacks.** When the scripted model is replaced by real open-weight models, how often do
the attacks succeed (attack success rate, ASR), and what fraction of successful attacks does the
rule pack detect? Also: how many *failed* attempts are still visible (attempt visibility), and what
is the false-positive rate on live benign traffic?

**RQ2. Real-world false positives and recall.** On public, labelled prompt-injection datasets and on
large corpora of real benign user prompts, what precision, recall and false-positive rate do the
text-based rules achieve (LLMD-001, -011, -012 on prompts; LLMD-002/-021 on documents and tool
output; LLMD-015 on tool descriptions)?

**RQ3. Rules versus ML detectors.** How do the rules compare with open prompt-injection classifiers
on the same data in precision, recall, latency and cost, and does a combination (union, or classifier
as a second stage) dominate either alone?

**RQ4. Adaptive attacker.** Under automated mutations (LLM paraphrase, translation, encoding and
obfuscation, splitting), how quickly does detection degrade, and, critically, how many mutations
evade detection *while the attack still succeeds* against the model?

**RQ5 (later phase). Frontier models and real agents.** The RQ1/RQ4 harness against frontier API
models, and against a real coding agent (Claude Code) in an isolated sandbox.

## Method

### Subjects
- Detection pack: the 21 rules at a pinned commit, run as KQL on Kustainer (pinned digest) and, where
  relevant, as Wazuh rules on wazuh-logtest 4.14.7.
- Models (RQ1, RQ4): 3 to 5 current open-weight instruction models from different vendors that
  support tool calling and fit an 8 GB GPU, served by Ollama. Exact tags and digests recorded.
- ML detectors (RQ3): open classifiers that run locally (selection in the experiment log).

### RQ1 protocol
- Scenarios are rewritten as *attacker-only*: the attacker controls a document, a memory entry, an
  MCP server variant or the user message; the model's behaviour is not scripted.
- Each scenario has an **independent success oracle** defined on side effects, never on the rules:
  email sent to an attacker domain, attacker URL in an image in the answer, canary in the output,
  restricted file content passed to a third-party tool, `run_shell` with the attacker command,
  attacker instruction written to memory, agent config written. Oracles are code, unit-tested.
- N = 10 runs per (scenario, model) at temperature 0.7 with fixed seeds, plus one run at 0.
- Benign traffic: the benign scenario prompts plus a sample of real benign prompts from RQ2 corpora,
  run through the same agent, for live false positives.
- Metrics: ASR with Wilson 95% intervals; detection recall on successful runs (by the scenario's
  intended rule and by any rule); attempt visibility on failed runs; false-positive rate on benign runs.

### RQ2 protocol
- Datasets: public, ungated, licensed for research; label semantics documented; duplicates removed.
- Prompts are wrapped as `prompt` events (documents as `retrieval`, tool descriptions as
  `tool_registry`) and the unchanged rule queries run on Kustainer.
- Metrics: precision, recall, F1, false-positive rate per 10 000 benign prompts, all with bootstrap
  95% intervals. Error analysis on a sample of false positives and false negatives.

### RQ3 protocol
- Same items as RQ2. Classifiers at their documented threshold, plus a threshold sweep (PR curves).
- Contamination control: datasets listed in a classifier's training data are reported separately and
  excluded from headline numbers.
- Latency per item on CPU and GPU; combinations: union, rules-then-classifier, classifier-then-rules.

### RQ4 protocol
- Seed set: attacks from RQ1 and RQ2 that the rules detect.
- Mutation operators: (m1) paraphrase by a local model, (m2) translation into 5 languages,
  (m3) encodings and obfuscation (base64, leetspeak, homoglyphs, zero-width insertion),
  (m4) splitting the instruction across turns or chunks, (m5) synonym substitution of trigger words.
- For each mutant: detected by rules? by classifier? and does the attack still succeed on the model
  (re-run through the RQ1 harness)? Headline metric: **evasion-preserving mutants** = undetected and
  still successful.

### Reproducibility
- One command per RQ; raw per-run JSONL, aggregated CSV, figures generated from CSV.
- Environment manifest per run: commit, model digests, Ollama version, GPU, seeds.
- Results and the paper live in the repository; large raw artefacts are compressed.

## Threats to validity (to be addressed in the paper)
- One demo application; real agents differ in prompts, tools and guardrails.
- Small open models behave differently from frontier models (RQ5 addresses this).
- Oracles capture the attacker's intended effect, not every possible harm.
- Public dataset labels are noisy; benign corpora are not production traffic.
- The rules and the attacks have the same author; RQ2 and RQ4 use third-party and automatically
  generated attacks to reduce this bias.

## Deliverables
- `research/` harness and results; arXiv-style paper (LaTeX, PDF via Tectonic) with figures;
  a results section in the README.

## Decisions made so far
- Open-weight models on the user's hardware first; frontier models later (user, 2026-10-20).
- No frontier API spend in phase 1 (user, 2026-10-20).
- Everything else above is the author's (assistant's) call and open to change.
