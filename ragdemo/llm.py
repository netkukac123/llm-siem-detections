"""Model backends.

`ScriptedModel` replays responses supplied by the caller. The simulator uses it
to reproduce what a model that *follows* an injection would do, so the log
corpus is deterministic and does not depend on which model happens to comply
today. `OpenAICompatModel` talks to any OpenAI-compatible endpoint (Ollama,
vLLM, LM Studio, Azure OpenAI with a compatible gateway) for live testing.
"""
from __future__ import annotations

import json
import math
import urllib.error
import urllib.request
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]
    id: str = field(default_factory=lambda: f"call_{uuid.uuid4().hex[:12]}")


@dataclass
class ModelResponse:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int | None = None
    output_tokens: int | None = None
    finish_reason: str = "stop"
    # Reasoning summary and refusal details, when the backend exposes them (Anthropic).
    thinking: str = ""
    refusal: str = ""
    reasoning_kind: str = ""  # "raw" (chain of thought) | "summary" (frontier rewrite) | ""


class ProviderFilterError(Exception):
    """The model provider's own guardrail refused the request (e.g. Azure AI Content Safety
    Prompt Shields returning HTTP 400 with code content_filter)."""

    def __init__(self, categories: list[str], raw: str):
        super().__init__(", ".join(categories) or "content_filter")
        self.categories = categories
        self.raw = raw


def estimate_tokens(text: str) -> int:
    # ~4 characters per token is the usual rule of thumb for English text.
    return max(1, math.ceil(len(text) / 4))


class ScriptedModel:
    name = "scripted-vulnerable-1"

    def __init__(self) -> None:
        self._queue: deque[ModelResponse] = deque()

    def script(self, *responses: ModelResponse) -> None:
        self._queue.extend(responses)

    def generate(self, messages: list[dict], tools: list[dict]) -> ModelResponse:
        prompt_text = "".join(str(m.get("content", "")) for m in messages)
        if self._queue:
            resp = self._queue.popleft()
        else:
            resp = ModelResponse(content=self._default_answer(messages))
        if resp.input_tokens is None:
            resp.input_tokens = estimate_tokens(prompt_text)
        if resp.output_tokens is None:
            resp.output_tokens = estimate_tokens(resp.content + json.dumps([tc.args for tc in resp.tool_calls]))
        if resp.tool_calls:
            resp.finish_reason = "tool_calls"
        return resp

    @staticmethod
    def _default_answer(messages: list[dict]) -> str:
        context = next((m["content"] for m in messages if m["role"] == "system" and m["content"].startswith("CONTEXT")), "")
        first_fact = next((ln for ln in context.splitlines() if ln and not ln.startswith(("CONTEXT", "[", "<!--"))), "")
        return f"According to the knowledge base: {first_fact}" if first_fact else "I could not find that in the knowledge base."


class AnthropicModel:
    """Anthropic Messages API backend (official SDK).

    Takes the same OpenAI-style message list the app builds and converts it. Each assistant
    turn's original content blocks are kept and sent back unchanged on tool-loop continuations,
    because current models reject edited histories (thinking blocks carry a signature).
    `thinking`: "adaptive" (Sonnet 5.5 / Opus 5.5, summarized text is returned) or "enabled"
    (Haiku 4.5, fixed budget). Refusals arrive as stop_reason "refusal", not as HTTP errors.
    """

    def __init__(self, model: str, api_key: str, max_tokens: int = 4096, thinking: str | None = "adaptive",
                 effort: str | None = None, workspace_id: str | None = None):
        import anthropic
        client_kw: dict[str, Any] = {"api_key": api_key, "max_retries": 5}
        if workspace_id:  # an org-level key must name the workspace on every request
            client_kw["default_headers"] = {"anthropic-workspace-id": workspace_id}
        self.client = anthropic.Anthropic(**client_kw)
        self.name = model
        self.model = model
        self.max_tokens = max_tokens
        self.thinking = thinking
        self.effort = effort
        self._turns: dict[str, list[dict]] = {}  # first tool_use id -> original assistant blocks

    @staticmethod
    def _tools(tools: list[dict]) -> list[dict]:
        return [{"name": t["function"]["name"], "description": t["function"]["description"],
                 "input_schema": t["function"]["parameters"]} for t in tools]

    def _convert(self, messages: list[dict]) -> tuple[str, list[dict]]:
        system, out = [], []
        for m in messages:
            role, content = m["role"], m.get("content") or ""
            if role == "system":
                system.append(content)
            elif role == "user":
                out.append({"role": "user", "content": content})
            elif role == "assistant":
                calls = m.get("tool_calls") or []
                if calls and calls[0]["id"] in self._turns:
                    out.append({"role": "assistant", "content": self._turns[calls[0]["id"]]})
                    continue
                blocks = [{"type": "text", "text": content}] if content else []
                blocks += [{"type": "tool_use", "id": c["id"], "name": c["function"]["name"],
                            "input": json.loads(c["function"]["arguments"])} for c in calls]
                if blocks:  # an empty assistant turn is not a valid block; dropping it is allowed
                    out.append({"role": "assistant", "content": blocks})
            elif role == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": content}
                last = out[-1] if out else None
                if last and last["role"] == "user" and isinstance(last["content"], list) \
                        and last["content"] and last["content"][0].get("type") == "tool_result":
                    last["content"].append(block)  # all results of one turn go in one user message
                else:
                    out.append({"role": "user", "content": [block]})
        return "\n\n".join(system), out

    def generate(self, messages: list[dict], tools: list[dict]) -> ModelResponse:
        system, conv = self._convert(messages)
        kw: dict[str, Any] = {"model": self.model, "max_tokens": self.max_tokens, "system": system,
                              "messages": conv, "tools": self._tools(tools)}
        if self.thinking == "adaptive":
            kw["thinking"] = {"type": "adaptive", "display": "summarized"}
            if self.effort:
                kw["output_config"] = {"effort": self.effort}
        elif self.thinking == "enabled":
            kw["thinking"] = {"type": "enabled", "budget_tokens": 1024}
        # The 1.x SDK takes no sampling parameters; run-to-run variability comes from repetitions.
        r = self.client.messages.create(**kw)

        thinking = "".join(getattr(b, "thinking", "") or "" for b in r.content if b.type == "thinking")
        text = "".join(b.text for b in r.content if b.type == "text")
        calls = [ToolCall(name=b.name, args=dict(b.input), id=b.id) for b in r.content if b.type == "tool_use"]
        if calls:
            self._turns[calls[0].id] = [b.model_dump() for b in r.content]
        finish = {"end_turn": "stop", "tool_use": "tool_calls", "max_tokens": "length"}.get(r.stop_reason, r.stop_reason)
        refusal = ""
        if r.stop_reason == "refusal" and getattr(r, "stop_details", None):
            refusal = f"{r.stop_details.category or 'unspecified'}: {r.stop_details.explanation or ''}".strip()
        # The Messages API never returns raw chain of thought: thinking text is always a summary of the
        # model's reasoning, in both adaptive and enabled (budget) mode, Haiku 4.5 included.
        kind = "summary" if thinking else ""
        return ModelResponse(content=text, tool_calls=calls, input_tokens=r.usage.input_tokens,
                             output_tokens=r.usage.output_tokens, finish_reason=finish,
                             thinking=thinking, refusal=refusal, reasoning_kind=kind)


class OpenAICompatModel:
    def __init__(self, base_url: str, model: str, api_key: str = "unused", timeout: float = 300,
                 temperature: float | None = None, seed: int | None = None, max_tokens: int | None = None,
                 token_param: str = "max_tokens"):
        self.base_url = base_url.rstrip("/")
        self.name = model
        self.api_key = api_key
        self.timeout = timeout
        self.temperature = temperature
        self.seed = seed
        self.max_tokens = max_tokens
        # Reasoning models on OpenAI-compatible APIs take max_completion_tokens instead.
        self.token_param = token_param

    def generate(self, messages: list[dict], tools: list[dict]) -> ModelResponse:
        payload: dict[str, Any] = {"model": self.name, "messages": messages, "tools": tools}
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        if self.seed is not None:
            payload["seed"] = self.seed
        if self.max_tokens is not None:
            payload[self.token_param] = self.max_tokens
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"})
        for attempt in range(6):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.load(resp)
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < 5:  # rate limited: honour Retry-After, then back off
                    import time
                    time.sleep(float(exc.headers.get("retry-after", 2 ** attempt * 5)))
                    continue
                self._raise_http(exc)
        choice = data["choices"][0]
        msg = choice["message"]
        calls = [ToolCall(tc["function"]["name"], json.loads(tc["function"]["arguments"] or "{}"), tc["id"])
                 for tc in msg.get("tool_calls") or []]
        usage = data.get("usage") or {}
        return ModelResponse(content=msg.get("content") or "", tool_calls=calls,
                             input_tokens=usage.get("prompt_tokens"),
                             output_tokens=usage.get("completion_tokens"),
                             finish_reason=choice.get("finish_reason", "stop"))

    @staticmethod
    def _raise_http(exc: urllib.error.HTTPError) -> None:
        raw = exc.read().decode(errors="replace")
        if exc.code == 400 and "content_filter" in raw:
            try:
                result = json.loads(raw)["error"]["innererror"]["content_filter_result"]
                cats = [k for k, v in result.items() if isinstance(v, dict) and v.get("filtered")]
            except (KeyError, ValueError, TypeError):
                cats = []
            raise ProviderFilterError(cats, raw) from exc
        raise exc
