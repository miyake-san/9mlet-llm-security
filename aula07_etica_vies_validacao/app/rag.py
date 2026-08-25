"""Recuperador (RAG) offline e determinístico sobre o corpus do Aurora.

Um retriever leve por sobreposição de tokens (cosseno TF) — suficiente para o
laboratório e 100% offline. Em produção, este componente seria um índice vetorial
(ex.: Azure AI Search); aqui o foco é **avaliar** a fundamentação da resposta
(RAGAS *faithfulness/context precision*), não otimizar a recuperação.

Referência:
    Es, S. et al. (2024). RAGAS. EACL. arXiv:2309.15217.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from src.security.text import tokenize

_CORPUS_DIR = Path(__file__).resolve().parents[1] / "data" / "rag_corpus"


@dataclass(frozen=True)
class Document:
    """Um documento recuperável do corpus do Aurora."""

    id: str
    title: str
    text: str


def load_corpus(corpus_dir: Path | None = None) -> list[Document]:
    """Carrega os documentos ``.md`` do corpus (título = 1ª linha de cabeçalho)."""
    directory = corpus_dir or _CORPUS_DIR
    docs: list[Document] = []
    if not directory.exists():
        return docs
    for path in sorted(directory.glob("*.md")):
        text = path.read_text(encoding="utf-8").strip()
        first_line = text.splitlines()[0] if text else path.stem
        title = first_line.lstrip("# ").strip()
        docs.append(Document(id=path.stem, title=title, text=text))
    return docs


class Retriever:
    """Índice TF em memória; busca top-k por similaridade de cosseno."""

    def __init__(self, documents: list[Document]) -> None:
        self.documents = documents
        self._vectors = [Counter(tokenize(d.text, canonical=True)) for d in documents]

    @classmethod
    def from_corpus(cls, corpus_dir: Path | None = None) -> Retriever:
        return cls(load_corpus(corpus_dir))

    @staticmethod
    def _cosine(a: Counter[str], b: Counter[str]) -> float:
        common = set(a) & set(b)
        if not common:
            return 0.0
        dot = sum(a[t] * b[t] for t in common)
        norm_a = math.sqrt(sum(v * v for v in a.values()))
        norm_b = math.sqrt(sum(v * v for v in b.values()))
        return dot / (norm_a * norm_b) if norm_a and norm_b else 0.0

    def search(self, query: str, top_k: int = 3) -> list[tuple[Document, float]]:
        """Retorna os ``top_k`` documentos mais similares à consulta (score desc)."""
        qv = Counter(tokenize(query, canonical=True))
        scored = [
            (doc, round(self._cosine(qv, dv), 4))
            for doc, dv in zip(self.documents, self._vectors, strict=True)
        ]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [(doc, score) for doc, score in scored[:top_k] if score > 0]
