"""consent-service — API de consentimento granular e solicitações do titular (Aula 05).

Serviço FastAPI que operacionaliza o **consentimento específico por finalidade e
versionado** (Doc 04, Hands On / §3) e o ciclo de vida das **solicitações do
titular** (DSR — arts. 17-22). É consumido pela ``rag-api`` (verificação de
consentimento antes de tratar) e pelo ``purge-worker`` (fila de exclusões).

Store versionado selecionável por env (``CONSENT_STORE``): memory | file | postgres
(análogo ao Azure Cosmos DB do Snippet 1). As DSRs residem neste serviço (fonte
única), e o worker as consome via HTTP.

Endpoints:
    GET   /health
    GET   /
    POST  /consent                          — concede/atualiza consentimento (nova versão)
    GET   /consent/{subject_id}             — consentimento vigente
    GET   /consent/{subject_id}/history     — todas as versões (trilha auditável)
    GET   /consent/{subject_id}/check       — ?purpose=... -> {allowed}
    POST  /consent/{subject_id}/revoke      — revogação instantânea (art. 18, IX)
    POST  /dsr                              — registra solicitação do titular
    GET   /dsr                              — ?status=pending -> lista
    PATCH /dsr/{request_id}                 — atualiza status (worker marca done)

Referência:
    BRASIL (2018). LGPD — arts. 7, 8, 17-22. · Doc 04, §3, Hands On (Snippet 1).
"""

from __future__ import annotations

import logging
import threading
import uuid
from contextlib import asynccontextmanager
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from app.config import Settings, get_settings
from src.security.consent import ConsentStore, build_consent_store
from src.security.schemas import (
    ConsentRecord,
    DataSubjectRequest,
    DSRStatus,
    DSRType,
    utc_now_iso,
)

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Store de DSRs (fonte única no consent-service; worker consome via HTTP)      #
# --------------------------------------------------------------------------- #
class DSRStore:
    """Repositório em memória das solicitações do titular (thread-safe)."""

    def __init__(self) -> None:
        self._items: dict[str, DataSubjectRequest] = {}
        self._lock = threading.Lock()

    def add(self, dsr: DataSubjectRequest) -> DataSubjectRequest:
        with self._lock:
            self._items[dsr.request_id] = dsr
            return dsr

    def get(self, request_id: str) -> DataSubjectRequest | None:
        with self._lock:
            return self._items.get(request_id)

    def list(self, status: DSRStatus | None = None) -> list[DataSubjectRequest]:
        with self._lock:
            items = list(self._items.values())
        if status is not None:
            items = [d for d in items if d.status == status]
        return items


@lru_cache
def _store(settings: Settings | None = None) -> ConsentStore:
    s = settings or get_settings()
    return build_consent_store(s.consent_store, path=s.consent_store_path, dsn=s.postgres_dsn)


@lru_cache
def _dsr_store() -> DSRStore:
    return DSRStore()


@asynccontextmanager
async def lifespan(_: FastAPI):
    s = get_settings()
    logging.basicConfig(level=s.log_level)
    logger.info("consent-service | store=%s terms=%s", s.consent_store, s.consent_terms_version)
    yield


app = FastAPI(
    title="Aurora consent-service",
    description="Consentimento granular/versionado + DSR (Aula 05 — LGPD arts. 7, 17-22).",
    version="1.0.0",
    lifespan=lifespan,
)


# --------------------------------------------------------------------------- #
# Schemas                                                                      #
# --------------------------------------------------------------------------- #
class ConsentIn(BaseModel):
    subject_id: str = Field(..., examples=["cli-90432"])
    purposes: dict[str, bool] = Field(
        default_factory=dict, examples=[{"consulta_saldo": True, "treino_modelo": False}]
    )
    terms_version: str | None = Field(default=None, examples=["2026-06-v3"])


class DSRIn(BaseModel):
    subject_id: str = Field(..., examples=["cli-90432"])
    dsr_type: DSRType = Field(..., examples=["erasure"])
    note: str = ""


class DSRPatch(BaseModel):
    status: DSRStatus
    note: str = ""


# --------------------------------------------------------------------------- #
# Endpoints                                                                    #
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, object]:
    return {
        "service": "aurora-consent-service",
        "endpoints": ["/consent", "/consent/{id}", "/consent/{id}/check", "/dsr"],
    }


@app.post("/consent")
def grant_consent(
    body: ConsentIn, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, object]:
    """Concede/atualiza consentimento — cria uma NOVA versão (art. 8)."""
    record = ConsentRecord(
        subject_id=body.subject_id,
        purposes=dict(body.purposes),
        terms_version=body.terms_version or settings.consent_terms_version,
    )
    saved = _store(settings).upsert(record)
    return saved.to_dict()


@app.get("/consent/{subject_id}")
def get_consent(
    subject_id: str, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, object]:
    record = _store(settings).get(subject_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Sem consentimento registrado.")
    return record.to_dict()


@app.get("/consent/{subject_id}/history")
def consent_history(
    subject_id: str, settings: Annotated[Settings, Depends(get_settings)]
) -> list[dict[str, object]]:
    return [r.to_dict() for r in _store(settings).history(subject_id)]


@app.get("/consent/{subject_id}/check")
def check_consent(
    subject_id: str,
    purpose: Annotated[str, Query(..., examples=["consulta_saldo"])],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, object]:
    """Verifica se há consentimento vigente para a finalidade (usado pela rag-api)."""
    record = _store(settings).get(subject_id)
    allowed = bool(record and record.allows(purpose))
    return {
        "subject_id": subject_id,
        "purpose": purpose,
        "allowed": allowed,
        "version": record.version if record else 0,
    }


@app.post("/consent/{subject_id}/revoke")
def revoke_consent(
    subject_id: str, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, object]:
    """Revogação instantânea do consentimento (art. 18, IX)."""
    record = _store(settings).revoke(subject_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Sem consentimento a revogar.")
    return record.to_dict()


@app.post("/dsr")
def create_dsr(body: DSRIn) -> dict[str, object]:
    """Registra uma solicitação do titular (acesso/exclusão/revisão…)."""
    dsr = DataSubjectRequest(
        request_id=f"dsr-{uuid.uuid4().hex[:12]}",
        subject_id=body.subject_id,
        dsr_type=body.dsr_type,
        note=body.note,
    )
    return _dsr_store().add(dsr).to_dict()


@app.get("/dsr")
def list_dsr(status: DSRStatus | None = None) -> list[dict[str, object]]:
    """Lista DSRs (o purge-worker consulta ``?status=pending``)."""
    return [d.to_dict() for d in _dsr_store().list(status)]


@app.patch("/dsr/{request_id}")
def update_dsr(request_id: str, body: DSRPatch) -> dict[str, object]:
    """Atualiza o status de uma DSR (o worker marca ``completed``)."""
    dsr = _dsr_store().get(request_id)
    if dsr is None:
        raise HTTPException(status_code=404, detail="DSR não encontrada.")
    dsr.status = body.status
    dsr.note = body.note or dsr.note
    if body.status in (DSRStatus.COMPLETED, DSRStatus.REJECTED):
        dsr.resolved_at = utc_now_iso()
    return dsr.to_dict()
