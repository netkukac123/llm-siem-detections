"""RQ3: score the RQ2 items with open prompt-injection classifiers (ONNX, CPU).

    python -m research.rq3_classifiers      # -> research/results/rq3/scores_<name>.jsonl
    python -m research.rq3_classifiers --eval

ONNX Runtime on CPU keeps the GPU free for the live experiments and reflects how a SOC
would run a detector next to a SIEM pipeline.
"""
from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path

import numpy as np

from .common import RESULTS, ROOT, bootstrap_ci, confusion, manifest, write_json

ITEMS = ROOT / "research" / "data" / "rq2_items.jsonl"
OUT = RESULTS / "rq3"
MAX_TOKENS = 512

CLASSIFIERS = {
    "protectai-deberta-v3-base-v2": {
        "repo": "protectai/deberta-v3-base-prompt-injection-v2", "model": "onnx/model.onnx",
        "tokenizer": "onnx/tokenizer.json", "positive_index": 1},
    "prompt-guard-2-22m": {
        "repo": "gravitee-io/Llama-Prompt-Guard-2-22M-onnx", "model": "model.onnx",
        "tokenizer": "tokenizer.json", "positive_index": 1},
}

# Contamination classes for ProtectAI v2 from its model card: jackhhao is listed by name; eight
# MIT-licensed training sets are not named, so pre-2024 MIT sets in our pool are "possible".
CONTAMINATION = {
    "jackhhao/jailbreak-classification": "definite",
    "Lakera/gandalf_ignore_instructions": "possible",
    "reshabhs/SPML_Chatbot_Prompt_Injection": "possible",
    "TrustAIRLab/in-the-wild-jailbreak-prompts": "possible",
}


class OnnxClassifier:
    def __init__(self, spec: dict):
        import onnxruntime as ort
        from huggingface_hub import hf_hub_download
        from tokenizers import Tokenizer

        self.tok = Tokenizer.from_file(hf_hub_download(spec["repo"], spec["tokenizer"]))
        self.tok.enable_truncation(MAX_TOKENS)
        self.tok.enable_padding()
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 12
        self.sess = ort.InferenceSession(hf_hub_download(spec["repo"], spec["model"]), opts,
                                         providers=["CPUExecutionProvider"])
        self.inputs = {i.name for i in self.sess.get_inputs()}
        self.pos = spec["positive_index"]

    def scores(self, texts: list[str]) -> np.ndarray:
        enc = self.tok.encode_batch(texts)
        feed = {"input_ids": np.array([e.ids for e in enc], dtype=np.int64),
                "attention_mask": np.array([e.attention_mask for e in enc], dtype=np.int64)}
        if "token_type_ids" in self.inputs:
            feed["token_type_ids"] = np.array([e.type_ids for e in enc], dtype=np.int64)
        logits = self.sess.run(None, {k: v for k, v in feed.items() if k in self.inputs})[0]
        e = np.exp(logits - logits.max(axis=1, keepdims=True))
        return (e / e.sum(axis=1, keepdims=True))[:, self.pos]


def score_all(name: str, batch: int = 16) -> None:
    clf = OnnxClassifier(CLASSIFIERS[name])
    items = [json.loads(l) for l in ITEMS.open(encoding="utf-8")]
    # Sort by length so padding stays small; keep the original id with each score.
    order = sorted(range(len(items)), key=lambda i: len(items[i]["text"]))
    out_path = OUT / f"scores_{name}.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    with out_path.open("w", encoding="utf-8") as f:
        for s in range(0, len(order), batch):
            idx = order[s:s + batch]
            sc = clf.scores([items[i]["text"] for i in idx])
            for i, p in zip(idx, sc):
                f.write(json.dumps({"item_id": items[i]["item_id"], "score": round(float(p), 6)}) + "\n")
            if s % (batch * 500) == 0:
                print(f"{name}: {s}/{len(order)} {time.time() - t0:.0f}s", flush=True)
    elapsed = time.time() - t0
    write_json(OUT / f"manifest_{name}.json", manifest(classifier=name, spec=CLASSIFIERS[name], items=len(items),
                                                       seconds=round(elapsed, 1),
                                                       ms_per_item=round(1000 * elapsed / len(items), 2)))


def evaluate() -> None:
    rule_preds = {json.loads(l)["item_id"]: json.loads(l) for l in (RESULTS / "rq2" / "preds.jsonl").open()}
    result = {"thresholds": 0.5, "rows": [], "pr_curves": {}}
    for name in CLASSIFIERS:
        path = OUT / f"scores_{name}.jsonl"
        if not path.exists():
            continue
        scores = {json.loads(l)["item_id"]: json.loads(l)["score"] for l in path.open()}
        groups = defaultdict(list)
        for iid, rp in rule_preds.items():
            if rp["label"] is None or iid not in scores:
                continue
            clean = CONTAMINATION.get(rp["dataset"], "clean")
            groups[(rp["kind"], rp["dataset"], clean)].append((rp, scores[iid]))
        for (kind, ds, clean), pairs in sorted(groups.items()):
            y = [bool(rp["label"]) for rp, _ in pairs]
            for variant, pred in (("rules", [rp["preds"]["any"] for rp, _ in pairs]),
                                  (name, [s >= 0.5 for _, s in pairs]),
                                  (f"rules OR {name}", [rp["preds"]["any"] or s >= 0.5 for rp, s in pairs]),
                                  (f"rules AND {name}", [rp["preds"]["any"] and s >= 0.5 for rp, s in pairs])):
                c = confusion(y, pred)
                row = {"classifier": name, "variant": variant, "kind": kind, "dataset": ds,
                       "contamination": clean, "n": len(y), "positives": sum(y), "tp": c.tp, "fp": c.fp,
                       "tn": c.tn, "fn": c.fn}
                if sum(y):
                    row["recall"] = (c.recall, *bootstrap_ci(y, pred, "recall", iters=300))
                if len(y) - sum(y):
                    row["fpr"] = (c.fpr, *bootstrap_ci(y, pred, "fpr", iters=300))
                result["rows"].append(row)
        # PR curve on clean, labelled prompt items (threshold sweep)
        pts = [(scores[i], bool(rp["label"])) for i, rp in rule_preds.items()
               if rp["label"] is not None and rp["kind"] == "prompt" and i in scores
               and CONTAMINATION.get(rp["dataset"], "clean") == "clean"]
        curve = []
        for t in [x / 100 for x in range(1, 100)]:
            c = confusion([y for _, y in pts], [s >= t for s, _ in pts])
            curve.append({"threshold": t, "precision": c.precision, "recall": c.recall, "fpr": c.fpr})
        result["pr_curves"][name] = curve
    write_json(OUT / "summary.json", result)
    print(f"{len(result['rows'])} rows written")


def main() -> None:
    p = argparse.ArgumentParser(prog="research.rq3_classifiers")
    p.add_argument("--only")
    p.add_argument("--eval", action="store_true")
    a = p.parse_args()
    if a.eval:
        evaluate()
        return
    for name in CLASSIFIERS:
        if a.only and a.only != name:
            continue
        score_all(name)


if __name__ == "__main__":
    main()
