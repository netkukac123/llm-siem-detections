"""Agent tools. All side effects are simulated: nothing leaves the machine.

Every call is reduced to a normalized `tool_target` (email domain, URL host,
file path) because that is the field a SOC can actually write rules on.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .retriever import CORPUS_DIR, Retriever


@dataclass
class ToolResult:
    status: str  # ok | denied | error
    output: str
    target: str | None = None


@dataclass
class Toolbox:
    retriever: Retriever
    outbox: list[dict] = field(default_factory=list)
    allowed_read_dir: Path = CORPUS_DIR

    def specs(self) -> list[dict]:
        """OpenAI-style function specs, also used by the scripted backend."""
        def fn(name: str, desc: str, props: dict[str, str]) -> dict:
            return {"type": "function", "function": {
                "name": name, "description": desc,
                "parameters": {"type": "object",
                               "properties": {k: {"type": "string", "description": v} for k, v in props.items()},
                               "required": list(props)}}}
        return [
            fn("search_kb", "Search the internal knowledge base.", {"query": "search terms"}),
            fn("send_email", "Send an email on behalf of the user.",
               {"to": "recipient address", "subject": "subject line", "body": "message body"}),
            fn("http_get", "Fetch a URL.", {"url": "absolute URL"}),
            fn("read_file", "Read a file from the document store.", {"path": "file path"}),
        ]

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        handler: Callable[..., ToolResult] | None = getattr(self, f"_t_{name}", None)
        if handler is None:
            return ToolResult("error", f"unknown tool {name}")
        try:
            return handler(**args)
        except TypeError as exc:
            return ToolResult("error", f"bad arguments: {exc}")

    def _t_search_kb(self, query: str) -> ToolResult:
        hits = self.retriever.search(query, k=3)
        return ToolResult("ok", json.dumps([{"doc_id": d.doc_id, "title": d.title} for d, _ in hits]))

    def _t_send_email(self, to: str, subject: str = "", body: str = "") -> ToolResult:
        domain = to.rsplit("@", 1)[-1].lower() if "@" in to else None
        self.outbox.append({"to": to, "subject": subject, "body": body})
        return ToolResult("ok", f"queued email to {to}", target=domain)

    def _t_http_get(self, url: str) -> ToolResult:
        host = (urlparse(url).hostname or "").lower() or None
        return ToolResult("ok", "[demo] network disabled, request recorded only", target=host)

    def _t_read_file(self, path: str) -> ToolResult:
        resolved = (self.allowed_read_dir / path).resolve()
        if not resolved.is_relative_to(self.allowed_read_dir.resolve()):
            return ToolResult("denied", "path outside document store", target=path)
        if not resolved.is_file():
            return ToolResult("error", "no such file", target=path)
        return ToolResult("ok", resolved.read_text(encoding="utf-8"), target=path)
