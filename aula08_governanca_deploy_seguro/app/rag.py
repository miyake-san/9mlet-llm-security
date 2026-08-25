"""Recuperador RAG offline in-memory do Aurora Assist.

Carrega o corpus sintético de ``data/rag_corpus/*.md`` e recupera os documentos
mais relevantes por sobreposição de tokens de conteúdo. Mantém o lab
*offline-first*: em produção, o mesmo papel é cumprido pelo **qdrant**
(``docker-compose.yml``) com embeddings — documentado como caminho de nuvem.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.security.text import content_tokens

_ROOT = Path(__file__).resolve().parents[1]
_CORPUS_DIR = _ROOT / "data" / "rag_corpus"


@dataclass(frozen=True)
class Document:
    doc_id: str
    text: str


class Retriever:
    """Índice invertido simples por token de conteúdo (BM25-lite offline)."""

    def __init__(self, documents: list[Document]) -> None:
        self.documents = documents

    @classmethod
    def from_corpus(cls, corpus_dir: Path | None = None) -> Retriever:
        directory = corpus_dir or _CORPUS_DIR
        docs: list[Document] = []
        if directory.exists():
            for path in sorted(directory.glob("*.md")):
                docs.append(Document(doc_id=path.stem, text=path.read_text(encoding="utf-8")))
        return cls(docs)

    def search(self, query: str, top_k: int = 3) -> list[tuple[Document, float]]:
        """Retorna os ``top_k`` documentos com maior sobreposição de tokens."""
        q = content_tokens(query)
        scored: list[tuple[Document, float]] = []
        for doc in self.documents:
            overlap = len(q & content_tokens(doc.text))
            if overlap:
                scored.append((doc, float(overlap)))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:top_k]
