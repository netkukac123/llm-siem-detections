# Pre-registration C2 and C3

Committed before any C2/C3 run. Prior art and verification: `docs/research/prior-art.md` (second
round, 2026-10-20). Closest work: *Prompt Overflow* (arXiv 2605.23196) for open guardrail classifiers
on direct injection; *LongPIBench* (2608.28411) for position effects; *LogJack* (2604.15368) for
Azure Prompt Shield on log-embedded payloads without a length dimension.

## C2: provider guardrail inspection window

Microsoft documents for Azure AI Foundry guardrails: "The first 1000 characters for text scenarios
will be moderated using Guardrails", and a 10K-character maximum for Prompt Shields input
(learn.microsoft.com, content-safety region-availability page, checked 2026-10-20).

- Target: the author's own Azure AI Foundry deployment `gpt-4.1-mini` with the default content
  filter (no custom configuration). Only the author's resources are queried.
- Seed payloads: up to 50 injection prompts from the RQ2 corpus (clean datasets) that the provider
  filter blocks at offset 0 in the user message; selected by running offset 0 first.
- Factor 1, offset of the payload after benign filler: 0, 500, 900, 1 100, 2 000, 5 000, 9 500,
  10 500, 20 000 characters.
- Factor 2, channel: (a) user message; (b) tool result message (the payload returned by a tool the
  model called).
- Filler: benign shipment-history text (same generator as N1).
- Measure: blocked (HTTP 400 content_filter) or not, and the returned filter annotations.
  `max_tokens` = 16 to keep cost minimal.
- H-C2a: block rate in the user channel is at least 90% at offsets below 1 000 and drops by at
  least 50 percentage points at offsets above 1 000.
- H-C2b: the tool-result channel is blocked less often than the user channel at offset 0.
- Null results are reported. If the boundary does not appear at 1 000, the documented behaviour does
  not hold for this deployment and that is the result.
- Disclosure: the window is documented by the vendor, so this is a measurement of documented
  behaviour, not a vulnerability report. Results will still be shared with Microsoft (MSRC) before
  publication of the paper.

## C3: unit mismatch between observers

- Same N1 payload, with filler of equal character count in three scripts: ASCII, CJK (3 bytes per
  character in UTF-8) and emoji (4 bytes, 2 UTF-16 units).
- Observers: application preview (characters, Python `str`), Wazuh event limit (bytes, measured
  65 319 B for logtest), Sentinel Logs Ingestion field limit (documented 64 KB), classifier window
  (tokens).
- H-C3: the offset (in characters) at which each observer loses the payload differs by script, so
  that for some offset the payload is visible to one observer and not to another while inside the
  model's context.
- Measured deterministically (no model calls) except for a confirmation that the models still
  follow the instruction with CJK filler at one large offset (n = 10 per Azure model).
