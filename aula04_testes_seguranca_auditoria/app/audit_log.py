"""audit-log — serviço de trilha de auditoria imutável (Aula 04, vídeo 3).

Recebe eventos do Aurora Assist e os **encadeia por hash** (Doc 04, seção 11):
cada evento incorpora o hash do anterior, tornando adulterações retroativas
detectáveis. Indexa (best-effort) em um SIEM local (OpenSearch, análogo didático
ao Azure Sentinel — Doc 04, seção 12) e expõe verificação de integridade via
raiz de Merkle. A cadeia é persistida em modo append-only (WORM lógico); em
produção o destino seria o **Azure Blob Immutable Storage** (WORM real).

Endpoints:
    GET  /health   — liveness.
    GET  /         — descrição do serviço.
    POST /events   — anexa um evento à cadeia (retorna o elo criado).
    GET  /events   — lista os eventos registrados.
    GET  /verify   — verifica a integridade da cadeia (raiz de Merkle).

Referência:
    Merkle, R. C. (1988). CRYPTO '87.
    ISO/IEC 27001:2022 · ISO/IEC 42001:2023 (auditabilidade).
    Microsoft (2026). Azure Blob Immutable Storage (WORM).
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from app.config import get_settings
from src.security.hash_chain import HashChain

logger = logging.getLogger(__name__)

# Cadeia global do processo (carregada do disco no startup; persistida a cada append).
_chain = HashChain()


def _index_opensearch(record: dict, entry_hash: str) -> None:
    """Indexa o evento no SIEM (OpenSearch) — best-effort, não-fatal (Doc 04, seção 12)."""
    s = get_settings()
    try:
        httpx.post(
            f"{s.opensearch_url.rstrip('/')}/{s.opensearch_index}/_doc",
            json={**record, "audit_hash": entry_hash},
            timeout=3.0,
        )
    except httpx.HTTPError as exc:  # limite: SIEM externo; auditoria local não pode falhar
        logger.debug("OpenSearch indisponível (evento só na cadeia local): %s", exc)


@asynccontextmanager
async def lifespan(_: FastAPI):
    s = get_settings()
    logging.basicConfig(level=s.log_level)
    global _chain
    _chain = HashChain.load(s.audit_chain_path)
    logger.info(
        "audit-log pronto | elos carregados=%d | path=%s", len(_chain.entries), s.audit_chain_path
    )
    yield


app = FastAPI(
    title="Aurora audit-log",
    description="Trilha de auditoria imutável (hash chain + Merkle) — Aula 04.",
    version="1.0.0",
    lifespan=lifespan,
)


class AuditEvent(BaseModel):
    """Evento de auditoria. Aceita campos extras (metadados variáveis)."""

    model_config = ConfigDict(extra="allow")

    action: str = "chat"
    decision: str | None = None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, object]:
    return {
        "service": "aurora-audit-log",
        "entries": len(_chain.entries),
        "endpoints": ["/events", "/verify", "/health"],
    }


@app.post("/events")
def append_event(event: AuditEvent) -> dict[str, object]:
    """Anexa um evento à cadeia (h_i = H(h_{i-1} ‖ log_i)) e o indexa no SIEM."""
    record = event.model_dump()
    entry = _chain.append(record)
    settings = get_settings()
    try:
        _chain.save(settings.audit_chain_path)
    except OSError as exc:  # limite: filesystem (tmpfs) — não derruba o serviço
        logger.warning("Falha ao persistir a cadeia: %s", exc)
    _index_opensearch(record, entry.hash)
    return {
        "seq": entry.seq,
        "timestamp": entry.timestamp,
        "prev_hash": entry.prev_hash,
        "hash": entry.hash,
        "merkle_root": _chain.merkle_root(),
    }


@app.get("/events")
def list_events(limit: int = 100) -> dict[str, object]:
    """Lista os últimos eventos registrados (metadados + hashes)."""
    tail = _chain.entries[-limit:]
    return {
        "count": len(_chain.entries),
        "events": [
            {"seq": e.seq, "timestamp": e.timestamp, "hash": e.hash, "record": e.record}
            for e in tail
        ],
    }


@app.get("/verify")
def verify() -> dict[str, object]:
    """Verifica a integridade da cadeia inteira (Doc 04, seção 11)."""
    return _chain.verify().to_dict()
