"""Agent tools. All side effects are simulated: nothing leaves the machine and no
command is ever executed.

Every call is reduced to a normalized `tool_target` (email domain, URL host,
file path, MCP server) and a `tool_risk` class, because those are the fields a
SOC can actually write rules on. High-risk tools go through an approval hook;
`tool_approval` records whether a human was in the loop.
"""
from __future__ import annotations

import json
import shlex
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .mcp_bridge import McpServerConfig, McpTool, call as mcp_call
from .retriever import CORPUS_DIR, Retriever

# read: no side effect | write: changes agent state | egress: data leaves the org
# destructive: deletes or overwrites | exec: runs code | external: third-party MCP server
TOOL_RISK = {"search_kb": "read", "read_file": "read", "remember": "write", "write_file": "write",
             "send_email": "egress", "http_get": "egress", "delete_record": "destructive", "run_shell": "exec"}
NEEDS_APPROVAL = {"destructive", "exec"}

# Returns True (approved), False (rejected) or None (no human configured: auto-approve).
Approver = Callable[[str, dict], "bool | None"]


@dataclass
class ToolResult:
    status: str  # ok | denied | error
    output: str
    target: str | None = None
    risk: str = "read"
    approval: str = "not_required"  # not_required | auto | approved | rejected
    mcp_server: str | None = None


@dataclass
class Toolbox:
    retriever: Retriever
    outbox: list[dict] = field(default_factory=list)
    workspace_writes: list[dict] = field(default_factory=list)
    memory: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    allowed_read_dir: Path = CORPUS_DIR
    approver: Approver | None = None
    mcp_tools: dict[str, tuple[McpServerConfig, McpTool]] = field(default_factory=dict)
    current_user: str = ""

    def specs(self) -> list[dict]:
        """OpenAI-style function specs, also used by the scripted backend."""
        def fn(name: str, desc: str, props: dict[str, str]) -> dict:
            return {"type": "function", "function": {
                "name": name, "description": desc,
                "parameters": {"type": "object",
                               "properties": {k: {"type": "string", "description": v} for k, v in props.items()},
                               "required": list(props)}}}
        local = [
            fn("search_kb", "Search the internal knowledge base.", {"query": "search terms"}),
            fn("send_email", "Send an email on behalf of the user.",
               {"to": "recipient address", "subject": "subject line", "body": "message body"}),
            fn("http_get", "Fetch a URL.", {"url": "absolute URL"}),
            fn("read_file", "Read a file from the document store.", {"path": "file path"}),
            fn("remember", "Save a note to the user's long-term memory for future conversations.",
               {"note": "what to remember"}),
            fn("write_file", "Write a file in the project workspace.", {"path": "file path", "content": "file content"}),
            fn("delete_record", "Delete a shipment record from the ERP.", {"record_id": "record ID"}),
            fn("run_shell", "Run a shell command on the operations server.", {"command": "command line"}),
        ]
        return local + [tool.spec() for _, tool in self.mcp_tools.values()]

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        if name in self.mcp_tools:
            cfg, _ = self.mcp_tools[name]
            ok, out = mcp_call(cfg, name, args)
            return ToolResult("ok" if ok else "error", out, target=cfg.name, risk="external", mcp_server=cfg.name)
        handler: Callable[..., ToolResult] | None = getattr(self, f"_t_{name}", None)
        if handler is None:
            return ToolResult("error", f"unknown tool {name}")
        risk = TOOL_RISK[name]
        approval = "not_required"
        if risk in NEEDS_APPROVAL:
            decision = self.approver(name, args) if self.approver else None
            approval = {None: "auto", True: "approved", False: "rejected"}[decision]
            if decision is False:
                return ToolResult("denied", "rejected by the user", target=_target(name, args), risk=risk,
                                  approval=approval)
        try:
            result = handler(**args)
        except TypeError as exc:
            result = ToolResult("error", f"bad arguments: {exc}")
        result.risk, result.approval = risk, approval
        return result

    def _t_search_kb(self, query: str) -> ToolResult:
        hits = self.retriever.search(query, k=3)
        return ToolResult("ok", json.dumps([{"doc_id": d.doc_id, "title": d.title} for d, _ in hits]))

    def _t_send_email(self, to: str, subject: str = "", body: str = "") -> ToolResult:
        self.outbox.append({"to": to, "subject": subject, "body": body})
        return ToolResult("ok", f"queued email to {to}", target=_target("send_email", {"to": to}))

    def _t_http_get(self, url: str) -> ToolResult:
        return ToolResult("ok", "[demo] network disabled, request recorded only",
                          target=_target("http_get", {"url": url}))

    def _t_read_file(self, path: str) -> ToolResult:
        resolved = (self.allowed_read_dir / path).resolve()
        if not resolved.is_relative_to(self.allowed_read_dir.resolve()):
            return ToolResult("denied", "path outside document store", target=path)
        if not resolved.is_file():
            return ToolResult("error", "no such file", target=path)
        return ToolResult("ok", resolved.read_text(encoding="utf-8"), target=path)

    def _t_remember(self, note: str) -> ToolResult:
        self.memory[self.current_user].append(note)
        return ToolResult("ok", "saved to memory", target=f"memory:{self.current_user}")

    def _t_write_file(self, path: str, content: str = "") -> ToolResult:
        self.workspace_writes.append({"path": path, "content": content})
        return ToolResult("ok", f"[demo] {len(content)} bytes recorded for {path}, nothing written", target=path)

    def _t_delete_record(self, record_id: str) -> ToolResult:
        return ToolResult("ok", f"[demo] record {record_id} marked deleted", target=record_id)

    def _t_run_shell(self, command: str) -> ToolResult:
        return ToolResult("ok", "[demo] command recorded, not executed", target=_target("run_shell", {"command": command}))


def _target(name: str, args: dict) -> str | None:
    if name == "send_email":
        to = str(args.get("to", ""))
        return to.rsplit("@", 1)[-1].lower() if "@" in to else None
    if name == "http_get":
        return (urlparse(str(args.get("url", ""))).hostname or "").lower() or None
    if name == "run_shell":
        try:
            parts = shlex.split(str(args.get("command", "")))
        except ValueError:
            parts = str(args.get("command", "")).split()
        return Path(parts[0]).name if parts else None
    if name == "delete_record":
        return str(args.get("record_id"))
    return None
