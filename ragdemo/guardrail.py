"""A deliberately thin input guardrail.

Real deployments put a classifier here (Azure AI Content Safety Prompt Shields,
Llama Prompt Guard, a provider moderation endpoint). What matters for the SOC is
that every block decision becomes a `guardrail` event, because repeated blocks
from one identity are a stronger signal than any single prompt.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_BLOCK_PATTERNS = {
    "jailbreak.dan": re.compile(r"\b(DAN|do anything now)\b", re.I),
    "jailbreak.dev_mode": re.compile(r"developer mode (enabled|on)|\bjailbreak(ed)?\b", re.I),
    "jailbreak.no_rules": re.compile(r"you (have|has) no (rules|restrictions|filters)", re.I),
}


@dataclass
class GuardrailDecision:
    action: str  # allow | block
    rule: str | None = None


def check_input(prompt: str) -> GuardrailDecision:
    for rule, pattern in _BLOCK_PATTERNS.items():
        if pattern.search(prompt):
            return GuardrailDecision("block", rule)
    return GuardrailDecision("allow")
