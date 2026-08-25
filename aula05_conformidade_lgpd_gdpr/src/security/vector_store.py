"""Vector store com purga seletiva — direito ao esquecimento (Aula 05).

Operacionaliza o **direito à exclusão** na camada de RECUPERAÇÃO (Doc 04, §10 /
Snippet 3): remove seletivamente TODOS os vetores associados a um titular. É a
resposta técnica ao "direito ao esquecimento" no RAG — filtrar por ``subject_id``
e excluir os documentos, análogo à purga no Azure AI Search.

Dois backends com o mesmo contrato (:class:`VectorStore`):
    * :class:`InMemoryVectorStore` — offline/testes (padrão).
    * :class:`QdrantVectorStore`   — produção-like (requer ``uv sync --group qdrant``).

O *embedding* é **determinístico e leve** (hashing trick): o objetivo pedagógico
é a **purga**, não a qualidade de recuperação — por isso evitamos modelos pesados
e mantemos o Lab reprodutível e offline.

⚠️ Limite honesto (Doc 04, §10): purgar vetores NÃO apaga o conhecimento
absorvido em *fine-tuning*. Isso é *machine unlearning* (SISA — Bourtoule et al.,
2021), área imatura; a limitação deve constar no DPIA.

Referência:
    BOURTOULE, L. et al. (2021). Machine Unlearning. IEEE S&P.
    Microsoft. Azure AI Search — delete documents. · Doc 04, §10.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Protocol

from src.security.schemas import PurgeResult

logger = logging.getLogger(__name__)

_EMBED_DIM = 64
_TOKEN_RE = re.compile(r"\w+", re.UNICODE)


def embed(text: str, dim: int = _EMBED_DIM) -> list[float]:
    """Embedding determinístico por *hashing trick* (offline, sem modelos).

    Cada token é projetado num índice via hash; o vetor é L2-normalizado. Serve
    apenas para exercitar busca/purga no Lab (não é qualidade de produção).
    """
    vec = [0.0] * dim
    for token in _TOKEN_RE.findall(text.lower()):
        h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)  # noqa: S324 (não-cripto)
        vec[h % dim] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=False))


@dataclass
class VectorRecord:
    """Documento vetorizado no índice RAG (com o titular a que pertence)."""

    doc_id: str
    subject_id: str
    text: str
    vector: list[float] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "subject_id": self.subject_id,
            "text": self.text,
            "metadata": self.metadata,
        }


class VectorStore(Protocol):
    """Contrato mínimo de um vector store com purga por titular."""

    name: str

    def upsert(self, record: VectorRecord) -> None: ...  # pragma: no cover

    def search(
        self, query: str, top_k: int = 3
    ) -> list[tuple[VectorRecord, float]]: ...  # pragma: no cover

    def list_by_subject(self, subject_id: str) -> list[VectorRecord]: ...  # pragma: no cover

    def purge_subject(self, subject_id: str) -> PurgeResult: ...  # pragma: no cover

    def count(self) -> int: ...  # pragma: no cover


class InMemoryVectorStore:
    """Índice em memória (offline/testes). Busca por cosseno; purga por filtro."""

    name = "memory"

    def __init__(self) -> None:
        self._records: dict[str, VectorRecord] = {}
        self._lock = threading.Lock()

    def upsert(self, record: VectorRecord) -> None:
        if not record.vector:
            record.vector = embed(record.text)
        with self._lock:
            self._records[record.doc_id] = record

    def search(self, query: str, top_k: int = 3) -> list[tuple[VectorRecord, float]]:
        q = embed(query)
        with self._lock:
            scored = [(rec, _cosine(q, rec.vector)) for rec in self._records.values()]
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:top_k]

    def list_by_subject(self, subject_id: str) -> list[VectorRecord]:
        with self._lock:
            return [r for r in self._records.values() if r.subject_id == subject_id]

    def purge_subject(self, subject_id: str) -> PurgeResult:
        """Remove TODOS os vetores do titular (Snippet 3 do Doc 04)."""
        with self._lock:
            victims = [d for d, r in self._records.items() if r.subject_id == subject_id]
            for doc_id in victims:
                del self._records[doc_id]
        logger.info("Purga seletiva: subject=%s docs=%d", subject_id, len(victims))
        return PurgeResult(
            subject_id=subject_id, store=self.name, deleted_count=len(victims), doc_ids=victims
        )

    def count(self) -> int:
        with self._lock:
            return len(self._records)


class QdrantVectorStore:
    """Índice em Qdrant (produção-like; análogo ao Azure AI Search).

    Requer ``uv sync --group qdrant`` e um Qdrant no ar. A purga usa um filtro
    por ``subject_id`` (equivalente ao ``filter="subject_id eq '...'"`` do Search).
    """

    name = "qdrant"

    def __init__(self, url: str, collection: str) -> None:
        try:
            from qdrant_client import QdrantClient
            from qdrant_client.models import Distance, VectorParams
        except ImportError as exc:  # limite: dependência opcional
            raise RuntimeError(
                "VECTOR_STORE=qdrant requer o grupo opcional: `uv sync --group qdrant`."
            ) from exc
        self._client = QdrantClient(url=url)
        self._collection = collection
        existing = {c.name for c in self._client.get_collections().collections}
        if collection not in existing:
            self._client.create_collection(
                collection_name=collection,
                vectors_config=VectorParams(size=_EMBED_DIM, distance=Distance.COSINE),
            )

    def _point_id(self, doc_id: str) -> int:
        return int(hashlib.sha256(doc_id.encode("utf-8")).hexdigest()[:15], 16)

    def upsert(self, record: VectorRecord) -> None:
        from qdrant_client.models import PointStruct

        if not record.vector:
            record.vector = embed(record.text)
        self._client.upsert(
            collection_name=self._collection,
            points=[
                PointStruct(
                    id=self._point_id(record.doc_id),
                    vector=record.vector,
                    payload={
                        "doc_id": record.doc_id,
                        "subject_id": record.subject_id,
                        "text": record.text,
                        **record.metadata,
                    },
                )
            ],
        )

    def search(self, query: str, top_k: int = 3) -> list[tuple[VectorRecord, float]]:
        hits = self._client.search(
            collection_name=self._collection, query_vector=embed(query), limit=top_k
        )
        out: list[tuple[VectorRecord, float]] = []
        for h in hits:
            payload = h.payload or {}
            out.append(
                (
                    VectorRecord(
                        doc_id=payload.get("doc_id", str(h.id)),
                        subject_id=payload.get("subject_id", ""),
                        text=payload.get("text", ""),
                    ),
                    float(h.score),
                )
            )
        return out

    def _filter(self, subject_id: str):
        from qdrant_client.models import FieldCondition, Filter, MatchValue

        return Filter(must=[FieldCondition(key="subject_id", match=MatchValue(value=subject_id))])

    def list_by_subject(self, subject_id: str) -> list[VectorRecord]:
        points, _ = self._client.scroll(
            collection_name=self._collection,
            scroll_filter=self._filter(subject_id),
            with_payload=True,
            limit=1000,
        )
        return [
            VectorRecord(
                doc_id=(p.payload or {}).get("doc_id", str(p.id)),
                subject_id=subject_id,
                text=(p.payload or {}).get("text", ""),
            )
            for p in points
        ]

    def purge_subject(self, subject_id: str) -> PurgeResult:
        victims = self.list_by_subject(subject_id)
        self._client.delete(
            collection_name=self._collection, points_selector=self._filter(subject_id)
        )
        return PurgeResult(
            subject_id=subject_id,
            store=self.name,
            deleted_count=len(victims),
            doc_ids=[v.doc_id for v in victims],
        )

    def count(self) -> int:
        return int(self._client.count(collection_name=self._collection).count)


def build_vector_store(
    kind: str, *, url: str | None = None, collection: str = "aurora_rag"
) -> VectorStore:
    """Fábrica de vector store por configuração (Doc 04, §12 — 12-factor)."""
    kind = (kind or "memory").lower()
    if kind == "qdrant":
        return QdrantVectorStore(url or "http://localhost:6333", collection)
    return InMemoryVectorStore()
