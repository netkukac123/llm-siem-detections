# Pre-registration RQ5: frontier models and the coverage of agent-attack telemetry

Committed before the frontier runs. This file fixes the hypotheses, the metrics, the decision
criteria, and the known blind spots, so the results cannot be read back into a story after the fact.
RQ1 to RQ4 asked whether rules over a structured agent event log catch injection-induced actions.
RQ5 asks what that telemetry does not cover, and how coverage changes as the agent model gets more
capable. It also adds the frontier models we could not run before (the earlier runs had no API key).

Three strands, two primary and one secondary.

- A (primary): a model that refuses an injection leaves no action for the SIEM to see, so the attack
  is invisible to tool-call telemetry. We log the refusal as its own event and attribute it to the
  retrieved document or MCP server that carried the injection, not to the user, and measure how much
  of the attack surface this recovers.
- B (primary): when a model does comply, are the resulting actions harder to catch with content
  rules as the model gets more capable, while behavioural rules hold.
- C (secondary): does a rule over the model's reasoning text add detection on top of behavioural
  rules, and does that differ between open models (raw chain of thought) and frontier models (a
  summary written by a separate model).

## Capability ladder (the independent variable)

Grouped, not treated as a continuous scale. Order within the paper is by released capability tier,
not a single number.

- Open, local, 8B class (already have RQ1 runs): `qwen3:8b`, `llama3.1:8b`, `ministral-3:8b`,
  `gemma4:e4b`, `granite4:tiny-h`. Raw chain of thought available for the thinking ones.
- Mid, hosted (already have RQ1 runs): Azure `gpt-4.1-mini`, `gpt-oss-120b`.
- Frontier (new, via the Anthropic API): `claude-haiku-4-5`, `claude-sonnet-5-5`, `claude-opus-5-5`.
  The API returns a summarised or omitted reasoning trace, never raw chain of thought. This is a
  property of the tier, recorded as such, not a flaw to hide.

Scenarios: the existing L01 to L10 live set (indirect injection via RAG, MCP tool poisoning, MCP
rug pull, runtime response poisoning, memory poisoning, agent-config tampering, malicious command,
ASCII smuggling). Each scenario already has two oracles: a compliance oracle (did the model take the
attacker-directed step at all) and a harm oracle (did the attacker's end goal actually complete).
That split is what lets B condition on completion rather than on mere compliance.

Repetitions: n = 10 per (scenario, model) cell for the frontier models, plus a benign workload of
50 runs per model. Rationale for repeating: single-run labels are unstable for thinking agents
(reruns disagree materially), so every rate is reported with a bootstrap or Wilson interval over
repetitions, never from one run. Seeds are fixed and recorded; the Anthropic SDK takes no sampling
parameters, so run-to-run variation comes from the model, which is the point.

## New detections defined up front

- LLMD-023 (refusal / attempted-but-refused): fires when, within a session that has external content
  in it (a retrieved non-internal document, or an MCP tool result flagged as carrying instructions),
  the model produces a refusal signal and takes no high-risk action. The refusal signal is either the
  provider stop reason (`stop_reason: refusal` on the Anthropic API) or a refusal classifier over the
  completion and, where present, the reasoning text. The alert names the suspected source: the
  `doc_id` / `doc_source` of the external document, or the `mcp_server` of the tool, carried from the
  retrieval and tool_registry events in the same session.
- LLMD-024 (reasoning-trace compliance signal): fires when the logged reasoning text states intent to
  act on injected content (patterns such as "the document/tool tells me to", "I will email/run as
  instructed", "no need to ask the user"). Scored only where a reasoning trace exists, and reported
  separately for raw chain of thought (open models) and summary (frontier).

Both are added to the Sentinel and Wazuh rule sets as new IDs and evaluated like the others. The app
is instrumented to emit two event types it does not emit today: `reasoning` (the trace text, length,
and whether it is raw or a summary) and `refusal` (the signal source and category). No existing event
changes.

Calibration disclosure: the regular expressions in LLMD-023 and LLMD-024 were finalized on a Haiku
rep-0 pilot (10 attack scenarios, one repetition) before the full run, so that the patterns match the
phrasing models actually use rather than a guess. This is detector engineering, not hypothesis
tuning: the pilot was used only to make the patterns fire on real refusal and compliance language,
not to tune any reported rate. Haiku rep-0 is therefore in-sample for the detector definition. The
headline coverage and recall numbers are reported on the held-out cells (Haiku reps 1 to 9, and all
of Sonnet and Opus), and the Haiku-including numbers are reported alongside them so the difference is
visible.

## Hypotheses and decision criteria

Rates are reported with 95% intervals whatever the outcome. Two-sided hypotheses are stated as such
because the published direction is contested.

A. Refusal coverage.
- H-A1 (coverage gain): on attack runs where the model refuses (no high-risk action), the fraction
  made visible by LLMD-023 is reported per model. The headline number is the attack surface that is
  invisible to tool-call-only telemetry but visible once refusals are logged. No threshold is
  pre-set; the claim is that this fraction is greater than zero and grows with model capability
  (because more capable models refuse more of these attacks), which is tested two-sided.
- H-A2 (source attribution): among LLMD-023 alerts, the fraction that name the actually-poisoned
  document or MCP server (precision of attribution). Pre-set success: at least 0.90, since the source
  is carried deterministically from the same session's retrieval/tool_registry events. A miss means a
  session-correlation bug, and is reported as such.
- H-A3 (benign false positives): LLMD-023 alert rate on the benign workload (external content present,
  model declines or simply answers normally with no injection). Pre-set ceiling: at most 0.05. The
  risk is that an ordinary refusal of a benign-but-unusual request looks like a refused attack; this
  is the metric that catches it.

B. Capability-conditioned detectability.
- H-B1 (compliance vs capability, two-sided): compliance rate as a function of capability tier. We do
  not assume a direction; the literature splits between inverse scaling and no correlation.
- H-B2 (content-rule detectability drops with capability): among runs where the attacker goal
  completed (harm oracle true), the recall of content-signature rules (the secret-pattern and
  injected-phrase rules) is reported per tier. Hypothesis, two-sided: this recall decreases as
  capability rises, because more capable models paraphrase or re-encode the secret, choose plausible
  targets, and split actions.
- H-B3 (behavioural rules hold): among the same completed-attack runs, recall of the behavioural rule
  (egress or high-risk action after external content entered the session, LLMD-006/007 family) is
  reported per tier. Hypothesis: this recall does not fall with capability the way H-B2 does. The
  paper's claim stands or falls on the gap between H-B2 and H-B3, not on either alone.
- Control stated up front: all of B is conditioned on completion (harm oracle), not on compliance, so
  that clumsy partial compliance by weak models does not inflate content-rule hits. Compliance-
  conditioned numbers are also reported, for comparison, but are not the basis of the claim.

C. Reasoning-trace rules (secondary).
- H-C1: recall of LLMD-024 (reasoning rule) among compliant runs, reported separately for raw chain
  of thought and for summaries. Positioned explicitly against the existing finding that action-based
  monitors beat reasoning-text monitors: the test is whether LLMD-024 adds recall on top of the
  behavioural rule (union), not whether it beats it alone. Pre-set framing: if LLMD-024 adds less
  than the behavioural rule already provides, we say so.
- H-C2: the raw-vs-summary gap. We expect LLMD-024 recall on frontier summaries to be lower than on
  open-model raw chain of thought, because the summary is lossy and written by a different model.
  Reported as a measured confound, two-sided.

## Metrics, exactly

- compliance rate, completion rate (harm), per (model, scenario), with intervals.
- detection-given-completion for each rule family (content, behavioural, reasoning, refusal), per tier.
- refusal coverage delta: recall of the attack set using tool-call rules only, vs tool-call rules
  plus LLMD-023, per model.
- attribution precision for LLMD-023.
- benign alert rate for every new rule.
- cost and latency per model (the paper reports what a frontier run costs, since that is a real SOC
  constraint).

## Known blind spots, declared before running

- Frontier reasoning is a summary or omitted, so C on frontier models tests the summary, not the
  model's actual reasoning. We never claim to have read a frontier model's chain of thought.
- Refusals are fragile. Published work shows a large fraction of refusals can be flipped by
  suppressing the reasoning channel, so LLMD-023 coverage is an upper bound on a cooperative model,
  not a guarantee under an adaptive attacker. RQ4-style adaptive pressure on LLMD-023 is future work,
  noted, not run here.
- Compliance and completion oracles are per-scenario side-effect checks; they can miss a novel harmful
  action. The oracles are the same ones used in RQ1 to RQ4, so any oracle error is consistent across
  the capability ladder and does not create a spurious trend.
- The refusal classifier over text is itself a model; its errors are reported (agreement with the
  provider stop reason where both exist).

## Prior art this design answers (citations verified at write-up)

- Reasoning as a telemetry field already exists (OTel GenAI semconv ReasoningPart; Microsoft Agent 365
  ships reasoning to a Defender/Sentinel pipeline; OWASP Agent Observability Standard carries a
  reasoning field). The novel part here is deterministic SIEM rules over that text, measured against
  action rules, not the logging of reasoning itself.
- Chain-of-thought monitoring for misbehaviour and for prompt-injection compliance is an active area
  (Baker et al., OpenAI 2025, arXiv:2503.11926, on CoT monitoring and the obfuscation it invites;
  "The Window Is in the Reasoning", arXiv:2610.24048, 2026, which found an action-based lookahead
  monitor beat the best reasoning-text monitor in 16 of 18 AgentDojo comparisons and reruns disagreed
  with single runs up to 35% for thinking agents). C is framed against that result, not in denial of
  it, and the 35% rerun instability is why every rate here is over repetitions.
- Refusal as a signal ships as a product (Tenable Model Refusal Detection) and blocked-injection
  events reach SIEMs from Azure, AWS, Palo Alto, Cisco. All are user-attributed or input-side
  classifiers. A is the source-attributed, model-native-refusal, attempted-but-refused-rate version,
  which was not found in the survey.
- Capability vs susceptibility is contested (AgentDojo inverse scaling; Gray Swan / UK AISI no
  correlation; Anthropic safety-training effects). The compliance-vs-completion gap in WASP
  (Evtimov et al., Meta, NeurIPS 2025 Datasets and Benchmarks; agents start the injected instruction
  16 to 86% of the time but complete the goal only 0 to 17%, "security through incompetence") is why
  B conditions on completion. B's detectability-vs-capability measurement for SIEM rules was not found
  in the survey.

Full source list with URLs is in `docs/research/prior-art.md`, updated from the RQ5 survey.
