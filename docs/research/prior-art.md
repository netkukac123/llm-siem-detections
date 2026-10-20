# Prior-art check for new injection techniques (2026-10-20)

Every arXiv entry below was opened and its title checked against the claim (script:
`curl https://arxiv.org/abs/<id>`). Vendor pages marked *unverified here* could not be loaded from
the author's machine (Cloudflare challenge) and are cited from a second-hand check.

| Idea | Verdict | Closest prior work |
|---|---|---|
| A. Fragmented / compositional injection across sources | Exists (attack). Extension possible: heterogeneous channels split across time, plus SIEM correlation detection | *Divide and Inject* (arXiv 2609.36576, 2026-09); *Context Contamination in LLM Analysis of Network Security Logs* (2607.14493, USENIX Sec '26); *TopoGuard* (2607.20437); *Exploiting Programmatic Behavior of LLMs* (2302.05733, payload splitting); *Hiding in Plain Floats* (2606.08403) |
| B. MCP full-schema poisoning | Exists | CyberArk *Poison Everywhere* (2025, unverified here); *MCP-ITP* (2601.07395); *Unicode TAG-Block Concealment of Tool-Metadata Payloads in MCP* (2607.05744) |
| C. Approval-UI deception | Exists | Checkmarx *Lies-in-the-Loop* and *HITL Dialog Forging* (2025, unverified here); *Loopjacking* (2609.21081) |
| D. Provenance laundering via memory | Exists, including the name | *Memory Provenance Laundering in LLM Agents* (2607.29167); *Trojan Hippo Bench* (2605.01970); *From Untrusted Input to Trusted Memory* (2606.04329); *Governance Decay* (2606.22528) |

Adjacent work on evading monitors: *Poisoning the Watchtower* (2605.24421, log content against
LLM-augmented SOCs); *Control-Token Injection Suppresses Chain-of-Thought* (2609.27542); *Silent
Egress* (2602.22450); ARMO, *Prompt Injection Telemetry for Autonomous Agents: The Attribution
Ceiling Decides What You Detect* (2026-08).

## Selected direction: telemetry-view divergence

No prior work found on attacks that place the payload where the model sees it but the *logging
view* used by detection does not: beyond application preview limits, OpenTelemetry/Application
Insights attribute limits (8,192 characters per property value), Logs Ingestion API field
truncation (64 KB), Data Collector API truncation (32 KB), SIEM event size limits, or classifier
context windows (512 tokens). Limits are from Microsoft's Azure Monitor service-limits page
(checked 2026-10-20) and from the classifiers' tokenizer settings.

"Not found" is weaker evidence than "does not exist"; the paper states this as "to our knowledge".

## Second round (2026-10-20, deeper search; all titles re-checked by the author)

- Closest: *Prompt Overflow: What the Guardrail Inspects Is Not What the Model Infers* (2605.23196):
  guardrail-window mismatch for open classifiers, **direct** injection only, no telemetry, no commercial
  API. Our guardrail-window measurements on open classifiers are therefore a replication/extension.
- *LongPIBench* (2608.28411): injection position effects and detector segmentation in long context.
- *Classifier Context Rot* (2605.12366); *LLM Agents Can Easily Tamper With Their Own Traces*
  (2609.30266); *LogJack* (2604.15368, Azure Prompt Shield on log-embedded payloads);
  *Just Testing, Move Along* (2607.24174); *When Benchmarks Lie* (2602.14161); *Confidently Wrong*
  (2606.22659); *DriftNet* (2609.10892); *TrustShiftProbe* (2608.23763); *ADR* (2605.17380);
  *Will the User Ever Know?* (2608.30362); *Defusing Explosive Prompts* (2609.22510).
- Verified vendor facts: Microsoft documents that Foundry guardrails moderate "the first 1000
  characters" of text and that Prompt Shields takes at most 10K characters; Claude Code's OTel export
  truncates content attributes at 60 KB and emits `<attr>_truncated` / `<attr>_original_length`;
  CVE-2026-81869 (OpenTelemetry-Go attribute truncation bypass via U+FFFD).
- Still open, to our knowledge: (C1) divergence across several observers at once for indirect
  injection through tool results, measured end to end with attack success; (C2) the inspection window
  of a commercial guardrail measured on indirect and direct channels; (C3) unit mismatch between
  observers (bytes, characters, UTF-16 units, tokens); (C4) truncation metadata as a detection
  signal.
Work on context-window evasion of *classifiers* is related and will be cited if found during
writing.
