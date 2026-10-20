"""Run the demo assistant interactively or as a small HTTP service.

    python -m ragdemo chat  --backend openai --base-url http://localhost:11434/v1 --model llama3.1
    python -m ragdemo serve --backend openai --base-url http://localhost:11434/v1 --model llama3.1

Events are appended to --log (default logs/ragdemo.jsonl).
"""
from __future__ import annotations

import argparse
import json
import os
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .app import RagApp
from .llm import OpenAICompatModel, ScriptedModel
from .logsink import EventLog


def build_app(args: argparse.Namespace) -> RagApp:
    Path(args.log).parent.mkdir(parents=True, exist_ok=True)
    log = EventLog(open(args.log, "a", encoding="utf-8"))
    if args.backend == "openai":
        model = OpenAICompatModel(args.base_url, args.model, os.environ.get("OPENAI_API_KEY", "unused"))
    else:
        model = ScriptedModel()
    return RagApp(log, model)


def cmd_chat(args: argparse.Namespace) -> None:
    app = build_app(args)
    session = uuid.uuid4().hex[:12]
    print(f"session {session}, logging to {args.log}. Ctrl-D to quit.")
    while True:
        try:
            msg = input("> ")
        except EOFError:
            break
        print(app.handle(msg, session_id=session, user_id=args.user, src_ip="127.0.0.1"))


def cmd_serve(args: argparse.Namespace) -> None:
    app = build_app(args)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/chat":
                self.send_error(404)
                return
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            answer = app.handle(body.get("message", ""),
                                session_id=body.get("session_id") or uuid.uuid4().hex[:12],
                                user_id=self.headers.get("X-User", "anonymous"),
                                src_ip=self.client_address[0])
            payload = json.dumps({"answer": answer}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    print(f"listening on http://{args.host}:{args.port}/chat")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


def main() -> None:
    p = argparse.ArgumentParser(prog="ragdemo")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("chat", cmd_chat), ("serve", cmd_serve)):
        s = sub.add_parser(name)
        s.set_defaults(fn=fn)
        s.add_argument("--backend", choices=["scripted", "openai"], default="openai")
        s.add_argument("--base-url", default="http://localhost:11434/v1")
        s.add_argument("--model", default="llama3.1")
        s.add_argument("--log", default="logs/ragdemo.jsonl")
        s.add_argument("--user", default="demo.user")
        if name == "serve":
            s.add_argument("--host", default="127.0.0.1")
            s.add_argument("--port", type=int, default=8000)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
