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
