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
Work on context-window evasion of *classifiers* is related and will be cited if found during
writing.
