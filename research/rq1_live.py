"""RQ1: run the attacks against live open-weight models and measure detection.

    python -m research.rq1_live --model qwen3:8b --model llama3.1:8b --reps 10
    python -m research.rq1_live --evaluate          # rules on everything collected so far

Each (model, scenario, rep) runs on a fresh agent instance, so memory and MCP state never
leak between runs. Raw events go to research/results/rq1/runs/<model>.jsonl (appended,
resumable); evaluation joins oracle outcomes with rule hits computed on Kustainer.
"""
from __future__ import annotations

import argparse
import io
import json
import time
import traceback
import uuid
from collections import defaultdict
from pathlib import Path

from ragdemo.app import RagApp
from ragdemo.llm import OpenAICompatModel
from ragdemo.logsink import EventLog, RequestContext
from ragdemo.mcp_bridge import McpServerConfig

from .common import RESULTS, manifest, run_rules, wilson, write_json
from .live_scenarios import LiveScenario, benign_scenarios, live_scenarios

OUT = RESULTS / "rq1"
SERVER_MODULE = "ragdemo.mcp_vendor_server"


def _cfg(name: str, variant: str, extra_env: tuple = ()) -> McpServerConfig:
    return McpServerConfig(name, SERVER_MODULE, (("CARGOLINK_VARIANT", variant), *extra_env))


AZURE_ENV = Path.home() / ".config" / "llmd" / "azure.env"
REASONING = ("gpt-5", "o3", "o4")


def make_model(model_tag: str, base_url: str, temperature: float, seed: int) -> OpenAICompatModel:
    """`name` = local Ollama tag; `azure:<deployment>` = Azure AI Foundry deployment (OpenAI v1 API).

    A per-call output cap keeps thinking models from generating for minutes; 2048 tokens is generous
    for an assistant answer plus reasoning (reasoning models get 4096, their thinking counts too).
    Reasoning models only accept the default temperature, so none is sent for them.
    """
    if not model_tag.startswith("azure:"):
        return OpenAICompatModel(base_url, model_tag, temperature=temperature, seed=seed, max_tokens=2048)
    env = dict(line.split("=", 1) for line in AZURE_ENV.read_text().split() if "=" in line)
    deployment = model_tag.split(":", 1)[1]
    reasoning = deployment.startswith(REASONING)
    return OpenAICompatModel(env["AZURE_AI_BASE"], deployment, api_key=env["AZURE_AI_KEY"],
                             temperature=None if reasoning else temperature, seed=seed,
                             max_tokens=4096 if reasoning else 2048,
                             token_param="max_completion_tokens" if reasoning else "max_tokens")


def run_once(sc: LiveScenario, model_tag: str, base_url: str, rep: int, temperature: float,
             corpus_dir: Path | None = None, run_prefix: str = "", mcp_env: tuple = (),
             extended_tool_logging: bool = False) -> dict:
    buf = io.StringIO()
    model = make_model(model_tag, base_url, temperature, 1000 + rep)
    app = RagApp(EventLog(buf), model, corpus_dir=corpus_dir, extended_tool_logging=extended_tool_logging)
    user, ip = ("research.user", "10.99.0.10")
    run_id = f"{run_prefix}{sc.id}-{model_tag.replace(':', '_')}-r{rep}"
    if sc.preregister_clean_mcp:
        app.mcp_servers = [_cfg(sc.mcp[0], "clean")]
        app._connect_mcp(RequestContext(session_id=f"{run_id}-baseline", user_id=user, src_ip=ip, model=model.name))
    app.mcp_servers = [_cfg(*sc.mcp, extra_env=mcp_env)]
    sessions: dict[str, str] = {}
    labels: dict[str, str] = {}
    t0 = time.time()
    error = None
    for turn in sc.turns:
        sid = sessions.setdefault(turn.session, f"{run_id}-{turn.session}-{uuid.uuid4().hex[:6]}")
        labels[sid] = turn.session
        try:
            app.handle(turn.message, session_id=sid, user_id=user, src_ip=ip)
        except Exception as exc:  # model/server errors are data, not crashes
            error = f"{type(exc).__name__}: {exc}"
            traceback.print_exc()
            break
    events = [json.loads(line) for line in buf.getvalue().splitlines()]
    for e in events:
        e["run_id"] = run_id
        e["session_label"] = labels.get(e["session_id"], "baseline")
    return {"run_id": run_id, "scenario": sc.id, "attack_class": sc.attack_class, "benign": sc.benign,
            "model": model_tag, "rep": rep, "temperature": temperature, "seconds": round(time.time() - t0, 1),
            "error": error, "success": (None if sc.benign else sc.oracle(events)),
            "complied": (None if sc.benign else sc.complied(events)), "events": events}


def collect(models: list[str], base_url: str, reps: int, temperature: float, benign_extra: int) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    extra = []
    corpus = RESULTS / "rq2" / "benign_sample.json"
    if benign_extra and corpus.exists():
        extra = json.loads(corpus.read_text())[:benign_extra]
    scenarios = live_scenarios() + benign_scenarios(extra)
    for tag in models:
        path = OUT / "runs" / f"{tag.replace(':', '_')}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        done = set()
        if path.exists():  # runs that ended in an error are retried; evaluate() keeps the last record
            done = {r["run_id"] for r in map(json.loads, path.open()) if not r.get("error")}
        with path.open("a", encoding="utf-8") as f:
            for sc in scenarios:
                for rep in range(1 if sc.benign else reps):
                    run_id = f"{sc.id}-{tag.replace(':', '_')}-r{rep}"
                    if run_id in done:
                        continue
                    rec = run_once(sc, tag, base_url, rep, temperature)
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    f.flush()
                    print(f"{tag:18s} {run_id:50s} success={rec['success']} {rec['seconds']}s"
                          + (f" ERROR {rec['error']}" if rec["error"] else ""), flush=True)
    write_json(OUT / "manifest.json", manifest(models=models, reps=reps, temperature=temperature,
                                                base_url=base_url))


def evaluate() -> dict:
    latest: dict[str, dict] = {}
    for p in sorted((OUT / "runs").glob("*.jsonl")):
        for line in p.open():
            r = json.loads(line)
            latest[r["run_id"]] = r  # a retried run supersedes its earlier error record
    records = list(latest.values())
    events = [{k: v for k, v in e.items() if k not in ("run_id", "session_label")}
              for r in records for e in r["events"]]
    flagged = run_rules(events, key="session_id")
    session_run = {e["session_id"]: r["run_id"] for r in records for e in r["events"]}
    run_hits: dict[str, set[str]] = defaultdict(set)
    for rid, sessions in flagged.items():
        for s in sessions:
            if s in session_run:
                run_hits[session_run[s]].add(rid)
    scen = {s.id: s for s in live_scenarios()}
    rows = []
    for r in records:
        hits = sorted(run_hits.get(r["run_id"], set()))
        intended = scen[r["scenario"]].intended_rules if r["scenario"] in scen else []
        rows.append({k: r.get(k) for k in ("run_id", "scenario", "attack_class", "benign", "model", "rep",
                                            "success", "complied", "error", "seconds")} | {
            "rules_fired": hits, "intended_hit": bool(set(hits) & set(intended)), "any_hit": bool(hits),
            "provider_blocked": any(e["event_type"] == "guardrail" and
                                    str(e.get("guardrail_rule", "")).startswith("provider.") for e in r["events"])})
    write_json(OUT / "per_run.json", rows)

    summary = {"by_model_scenario": [], "by_model": []}
    group = defaultdict(list)
    for row in rows:
        if not row["benign"] and not row["error"]:
            group[(row["model"], row["scenario"])].append(row)
    for (m, s), rs in sorted(group.items()):
        succ = [x for x in rs if x["success"]]
        comp = [x for x in rs if x["complied"]]
        resisted = [x for x in rs if not x["complied"]]
        summary["by_model_scenario"].append({
            "model": m, "scenario": s, "n": len(rs),
            "compliance": wilson(len(comp), len(rs)), "asr": wilson(len(succ), len(rs)),
            "detected_given_compliance": wilson(sum(x["intended_hit"] for x in comp), len(comp)),
            "detected_given_success": wilson(sum(x["intended_hit"] for x in succ), len(succ)),
            "visible_given_resisted": wilson(sum(x["any_hit"] for x in resisted), len(resisted))})
    for m in sorted({row["model"] for row in rows}):
        att = [x for x in rows if x["model"] == m and not x["benign"] and not x["error"]]
        succ = [x for x in att if x["success"]]
        comp = [x for x in att if x["complied"]]
        ben = [x for x in rows if x["model"] == m and x["benign"] and not x["error"]]
        summary["by_model"].append({
            "model": m, "attack_runs": len(att), "compliance": wilson(len(comp), len(att)),
            "asr": wilson(len(succ), len(att)),
            "detected_given_compliance": wilson(sum(x["intended_hit"] for x in comp), len(comp)),
            "detected_given_success": wilson(sum(x["intended_hit"] for x in succ), len(succ)),
            "any_rule_given_compliance": wilson(sum(x["any_hit"] for x in comp), len(comp)),
            "provider_blocked_attacks": wilson(sum(x["provider_blocked"] for x in att), len(att)),
            "provider_blocked_benign": wilson(sum(x["provider_blocked"] for x in ben), len(ben)),
            "benign_runs": len(ben), "benign_fp": wilson(sum(x["any_hit"] for x in ben), len(ben)),
            "errors": sum(1 for x in rows if x["model"] == m and x["error"])})
    write_json(OUT / "summary.json", summary)
    return summary


def main() -> None:
    p = argparse.ArgumentParser(prog="research.rq1_live")
    p.add_argument("--model", action="append", default=[])
    p.add_argument("--base-url", default="http://127.0.0.1:11434/v1")
    p.add_argument("--reps", type=int, default=10)
    p.add_argument("--temperature", type=float, default=0.7)
    p.add_argument("--benign-extra", type=int, default=100, help="real benign prompts from the RQ2 sample")
    p.add_argument("--evaluate", action="store_true")
    a = p.parse_args()
    if a.model:
        collect(a.model, a.base_url, a.reps, a.temperature, a.benign_extra)
    if a.evaluate:
        s = evaluate()
        for row in s["by_model"]:
            print(json.dumps(row))


if __name__ == "__main__":
    main()
