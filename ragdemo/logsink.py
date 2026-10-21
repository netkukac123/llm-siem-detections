"""Structured JSONL event log for the demo app.

One line per event. The schema is documented in docs/log-schema.md and is the
contract every detection in detections/ is written against.
"""
from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import IO, Any

EVENT_TYPES = ("prompt", "guardrail", "retrieval", "tool_call", "completion", "memory_write",
               "tool_registry", "reasoning", "refusal")


class Clock:
    """Wall clock by default; the simulator swaps in a deterministic one."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


@dataclass
class SimClock(Clock):
    current: datetime
    step: timedelta = field(default_factory=lambda: timedelta(milliseconds=350))

    def now(self) -> datetime:
        self.current += self.step
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


@dataclass
class RequestContext:
    session_id: str
    user_id: str
    src_ip: str
    model: str
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])


class EventLog:
    def __init__(self, stream: IO[str], app_name: str = "ragdemo", clock: Clock | None = None):
        self._stream = stream
        self._lock = threading.Lock()
        self.app_name = app_name
        self.clock = clock or Clock()

    def emit(self, event_type: str, ctx: RequestContext, **fields: Any) -> dict:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event_type {event_type!r}")
        ts = self.clock.now().isoformat(timespec="milliseconds").replace("+00:00", "Z")
        event = {
            "TimeGenerated": ts,
            "app_name": self.app_name,
            "event_type": event_type,
            "request_id": ctx.request_id,
            "session_id": ctx.session_id,
            "user_id": ctx.user_id,
            "src_ip": ctx.src_ip,
            "model": ctx.model,
        }
        event.update({k: v for k, v in fields.items() if v is not None})
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()
        return event
