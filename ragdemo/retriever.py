"""Tiny keyword retriever over the markdown corpus.

Deliberately simple: no embeddings, no vector store. The detections only care
about *what* was retrieved and *where it came from*, not how it was ranked.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

CORPUS_DIR = Path(__file__).parent / "corpus"
_TOKEN = re.compile(r"[a-z0-9áéíóöőúüű]+")
_STOP = {"the", "a", "an", "and", "or", "of", "to", "in", "is", "are", "for", "on", "what",
         "how", "do", "i", "my", "me", "can", "with", "be", "it", "this", "that", "you"}


@dataclass(frozen=True)
class Document:
    doc_id: str
    source: str
    title: str
    text: str
    path: Path


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP]


def load_corpus(corpus_dir: Path = CORPUS_DIR) -> list[Document]:
    docs = []
    for path in sorted(corpus_dir.glob("*.md")):
        raw = path.read_text(encoding="utf-8")
        _, header, body = raw.split("---", 2)
        meta = dict(line.split(":", 1) for line in header.strip().splitlines())
        meta = {k.strip(): v.strip() for k, v in meta.items()}
        docs.append(Document(meta["doc_id"], meta["source"], meta["title"], body.strip(), path))
    return docs


class Retriever:
    def __init__(self, docs: list[Document]):
        self.docs = docs
        self._tf = [Counter(_tokens(d.title + " " + d.text)) for d in docs]
        df = Counter(t for tf in self._tf for t in tf)
        self._idf = {t: math.log(1 + len(docs) / n) for t, n in df.items()}

    def search(self, query: str, k: int = 2, min_score: float = 3.6) -> list[tuple[Document, float]]:
        q = _tokens(query)
        scored = []
        for doc, tf in zip(self.docs, self._tf):
            score = sum(tf[t] * self._idf.get(t, 0.0) for t in q)
            if score >= min_score:
                scored.append((doc, round(score, 3)))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]
