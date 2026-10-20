"""RQ2/RQ3 data: download public datasets and normalise them into one JSONL file.

    python -m research.rq2_data            # -> research/data/rq2_items.jsonl (+ manifest)

Every item: {item_id, dataset, kind, text, label, meta}
  kind  = prompt | document | tool_description
  label = 1 attack / injection, 0 benign, None unlabelled (real traffic, reported as alert rate)

Caps keep the run to minutes on a laptop; they are recorded in the manifest and the paper.
"""
from __future__ import annotations

import ast
import json
import random
import urllib.request
from pathlib import Path

from datasets import load_dataset

from .common import ROOT, manifest, write_json

DATA = ROOT / "research" / "data"
OUT = DATA / "rq2_items.jsonl"
MAX_CHARS = 2000  # the demo app truncates logged text to the same length
SEED = 20261020
MCPTOX = "https://raw.githubusercontent.com/zhiqiangwang4/MCPTox-Benchmark/main/"


def _rows(name, config=None, split="train", streaming=False):
    return load_dataset(name, config, split=split, streaming=streaming)


def _take(it, n):
    out = []
    for row in it:
        out.append(row)
        if len(out) >= n:
            break
    return out


def _item(dataset, kind, text, label, idx, **meta):
    text = (text or "").strip()
    if not text:
        return None
    return {"item_id": f"{dataset.split('/')[-1]}:{kind[0]}:{idx}", "dataset": dataset, "kind": kind,
            "text": text[:MAX_CHARS], "label": label, "meta": meta}


def prompt_sets():
    for split in ("train", "test"):
        for i, r in enumerate(_rows("deepset/prompt-injections", split=split)):
            yield _item("deepset/prompt-injections", "prompt", r["text"], int(r["label"]), f"{split}{i}")
    for split in ("train", "test"):
        for i, r in enumerate(_rows("jackhhao/jailbreak-classification", split=split)):
            yield _item("jackhhao/jailbreak-classification", "prompt", r["prompt"],
                        int(r["type"] == "jailbreak"), f"{split}{i}", attack_type="jailbreak")
    for split in ("train", "validation", "test"):
        for i, r in enumerate(_rows("Lakera/gandalf_ignore_instructions", split=split)):
            yield _item("Lakera/gandalf_ignore_instructions", "prompt", r["text"], 1, f"{split}{i}")
    for split in ("train", "validation", "test"):
        for i, r in enumerate(_rows("neuralchemy/Prompt-injection-dataset", "core", split=split)):
            yield _item("neuralchemy/Prompt-injection-dataset", "prompt", r["text"], int(r["label"]),
                        f"{split}{i}", category=r.get("category"), tags=r.get("tags"))
    for i, r in enumerate(_rows("reshabhs/SPML_Chatbot_Prompt_Injection")):
        yield _item("reshabhs/SPML_Chatbot_Prompt_Injection", "prompt", r["User Prompt"],
                    int(r["Prompt injection"]), i)
    for i, r in enumerate(_rows("TrustAIRLab/in-the-wild-jailbreak-prompts", "jailbreak_2023_12_25")):
        yield _item("TrustAIRLab/in-the-wild-jailbreak-prompts", "prompt", r["prompt"], 1, f"j{i}",
                    attack_type="jailbreak", platform=r.get("platform"))
    regular = list(_rows("TrustAIRLab/in-the-wild-jailbreak-prompts", "regular_2023_12_25"))
    random.Random(SEED).shuffle(regular)
    for i, r in enumerate(regular[:5000]):
        yield _item("TrustAIRLab/in-the-wild-jailbreak-prompts", "prompt", r["prompt"], 0, f"r{i}",
                    platform=r.get("platform"))


def benign_prompt_sets():
    # Real user traffic, unlabelled: first user turn of non-toxic WildChat conversations.
    n = 0
    for i, r in enumerate(_rows("allenai/WildChat-1M", streaming=True)):
        if r.get("toxic"):
            continue
        conv = r["conversation"]
        first = next((t["content"] for t in conv if t.get("role") == "user"), "")
        it = _item("allenai/WildChat-1M", "prompt", first, None, i, language=r.get("language"))
        if it:
            yield it
            n += 1
        if n >= 20000:
            break
    k = 0
    for i, r in enumerate(_rows("OpenAssistant/oasst2")):
        if r["role"] == "prompter" and r["parent_id"] is None and not r["deleted"]:
            it = _item("OpenAssistant/oasst2", "prompt", r["text"], 0, i, lang=r.get("lang"))
            if it:
                yield it
                k += 1
            if k >= 10000:
                break
    for i, r in enumerate(_rows("databricks/databricks-dolly-15k")):
        yield _item("databricks/databricks-dolly-15k", "prompt", r["instruction"], 0, i, category=r["category"])


def document_sets():
    rng = random.Random(SEED)
    ph1 = _take(_rows("microsoft/llmail-inject-challenge", split="Phase1", streaming=True), 60000)
    rng.shuffle(ph1)
    for i, r in enumerate(ph1[:10000]):
        objectives = json.loads(r["objectives"]) if r.get("objectives") else {}
        yield _item("microsoft/llmail-inject-challenge", "document",
                    f"Subject: {r.get('subject') or ''}\n\n{r.get('body') or ''}", 1, i,
                    scenario=r.get("scenario"), exfil_sent=objectives.get("exfil.sent"),
                    defense_undetected=objectives.get("defense.undetected"))
    bipia = list(_rows("geodesic-research/bipia"))
    rng.shuffle(bipia)
    for i, r in enumerate(bipia[:5000]):
        yield _item("geodesic-research/bipia", "document", r["context"], 1, i,
                    attack_category=r.get("attack_category"), task=r.get("task_name"), position=r.get("position"))
    for i, r in enumerate(_rows("nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1")):
        inj = r.get("injection") or {}
        if isinstance(inj, str):
            try:
                inj = ast.literal_eval(inj)
            except (ValueError, SyntaxError):
                inj = {}
        # The text the attacker plants in the data source (chart notes, emails, ...).
        text = inj.get("injection_text") if isinstance(inj, dict) else None
        if not text:
            continue
        yield _item("nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1", "document", text, 1, i,
                    attack_category=r.get("attack_category"), vector=r.get("injection_vector"))
    for i, r in enumerate(_rows("databricks/databricks-dolly-15k")):
        if r["context"]:
            yield _item("databricks/databricks-dolly-15k", "document", r["context"], 0, i)
    k = 0
    for i, r in enumerate(_rows("OpenAssistant/oasst2")):
        if r["role"] == "assistant" and not r["deleted"]:
            it = _item("OpenAssistant/oasst2", "document", r["text"], 0, i)
            if it:
                yield it
                k += 1
            if k >= 5000:
                break


def _fetch_json(name):
    with urllib.request.urlopen(MCPTOX + name, timeout=120) as resp:
        return json.load(resp)


def tool_description_sets():
    # pure_tool.json: list of 45 servers, each {case_key: "<python dict literal>"}
    i = 0
    for server in _fetch_json("pure_tool.json"):
        for raw in server.values():
            try:
                c = ast.literal_eval(raw) if isinstance(raw, str) else raw
            except (ValueError, SyntaxError):
                continue
            if isinstance(c, dict) and c.get("tool_content"):
                yield _item("MCPTox/pure_tool", "tool_description", str(c["tool_content"]), 1, i,
                            server=c.get("server_name"), tool=c.get("tool_name"))
                i += 1
    seen = set()
    k = 0
    for r in _rows("wwh0411/MCP-Flow", split="test", streaming=True):
        try:
            tools = json.loads(r["tools"])
        except json.JSONDecodeError:
            continue
        for t in tools:
            fn = t.get("function", t)
            desc = fn.get("description") or ""
            key = (fn.get("name"), desc)
            if desc and key not in seen:
                seen.add(key)
                yield _item("wwh0411/MCP-Flow", "tool_description", desc, 0, k, tool=fn.get("name"))
                k += 1
        if k >= 10000:
            break


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    counts: dict[str, dict] = {}
    with OUT.open("w", encoding="utf-8") as f:
        for gen in (prompt_sets, benign_prompt_sets, document_sets, tool_description_sets):
            for it in gen():
                if it is None:
                    continue
                f.write(json.dumps(it, ensure_ascii=False) + "\n")
                c = counts.setdefault(f"{it['dataset']}|{it['kind']}", {"1": 0, "0": 0, "None": 0})
                c[str(it["label"])] += 1
            print(f"{gen.__name__} done", flush=True)
    write_json(DATA / "rq2_manifest.json", manifest(seed=SEED, max_chars=MAX_CHARS, counts=counts))
    for k, v in sorted(counts.items()):
        print(k, v)


if __name__ == "__main__":
    main()
