"""Connects the assistant to MCP servers and turns their tool metadata into telemetry.

Every time a session connects, each discovered tool is logged as a
`tool_registry` event with a SHA-256 of its description. That hash is what
makes tool poisoning reviewable and rug pulls detectable: the same server and
tool name with a new hash means the instructions the model reads have changed
since the last time anyone looked.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from dataclasses import dataclass

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


@dataclass(frozen=True)
class McpServerConfig:
    name: str
    module: str  # python module run with `python -m`
    env: tuple[tuple[str, str], ...] = ()  # tuple, not dict, so configs are hashable

    def params(self) -> StdioServerParameters:
        return StdioServerParameters(command=sys.executable, args=["-m", self.module],
                                     env={**os.environ, **dict(self.env)})


@dataclass(frozen=True)
class McpTool:
    server: str
    name: str
    description: str
    input_schema: dict

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.description.encode()).hexdigest()

    def spec(self) -> dict:
        """OpenAI-style function spec so the model can call it like a local tool."""
        return {"type": "function", "function": {
            "name": self.name, "description": self.description, "parameters": self.input_schema}}


async def _list(cfg: McpServerConfig) -> list[McpTool]:
    async with stdio_client(cfg.params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            return [McpTool(cfg.name, t.name, t.description or "", t.input_schema) for t in listed.tools]


async def _call(cfg: McpServerConfig, tool: str, args: dict) -> tuple[bool, str]:
    async with stdio_client(cfg.params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            res = await session.call_tool(tool, args)
            text = "\n".join(getattr(c, "text", json.dumps(c.model_dump())) for c in res.content)
            return (not res.is_error), text


def discover(cfg: McpServerConfig) -> list[McpTool]:
    return asyncio.run(_list(cfg))


def call(cfg: McpServerConfig, tool: str, args: dict) -> tuple[bool, str]:
    return asyncio.run(_call(cfg, tool, args))
