"""Aurora Assist v2.5 — rag-api COMPLIANT (Aula 05).

Traduz requisitos regulatórios em controles técnicos verificáveis (Doc 04). Cada
requisição percorre o **pipeline de conformidade** da Figura 1:

    consentimento (art. 7) -> minimização de PII (art. 6, V) -> RAG ->
    transparência EU AI Act (art. 50) -> registro de tratamento WORM (art. 37)

e **recusa decisões automatizadas de crédito** (GDPR art. 22 / LGPD art. 20),
mantendo o sistema em risco LIMITADO (Doc 04, §7). Também expõe os **direitos do
titular**: acesso (art. 18, I-II) e exclusão / direito ao esquecimento (art. 18,
VI) com purga seletiva no vector store (Doc 04, §10, Snippet 3).

Endpoints:
    GET  /health · GET / · GET /config
    POST /consent               — proxy p/ consent-service (fallback local offline)
    POST /chat                  — chat conforme (consent + minimização + tratamento)
    POST /rag/index             — indexa documento no vector store (por titular)
    POST /rag/search            — busca no índice
    POST /dsr/access            — acesso do titular (consent + vetores + tratamento)
    POST /dsr/erasure           — direito ao esquecimento (purga seletiva)
    GET  /treatment/records     — consulta o RoPA (art. 37)
    GET  /compliance/summary    — painel de conformidade (Azure Workbooks-like)

Referência:
    BRASIL (2018). LGPD — arts. 6, 7, 18, 20, 37.
    UNIÃO EUROPEIA (2016). GDPR — arts. 22, 25, 30. · (2024) EU AI Act.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Annotated

import httpx
import yaml
from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from app.config import Settings, get_settings
from app.llm import LLMBackend, get_backend
from src.security.consent import ConsentStore, InMemoryConsentStore
from src.security.dpia import classify_ai_system
from src.security.minimization import (
    DeterministicMinimizer,
    Minimizer,
    PresidioHttpMinimizer,
)
from src.security.schemas import ConsentRecord, PurgeResult, RiskTier
from src.security.treatment import (
    TreatmentRegistry,
    build_treatment_record,
    load_treatment_policies,
    pseudonymize,
)
from src.security.vector_store import VectorRecord, VectorStore, build_vector_store

logger = logging.getLogger(__name__)

_APP_DIR = Path(__file__).resolve().parent
_POLICY_PATH = _APP_DIR / "policies" / "aurora_assist_system_prompt.md"
_CONFIGS = _APP_DIR.parent / "configs"

# Verbos que caracterizam uma DECISÃO (não mera informação) sobre crédito.
_DECISION_VERBS = ("aprov", "nega", "recus", "decid", "conced", "libera", "reprov")
_CREDIT_TERMS = ("crédito", "credito", "empréstimo", "emprestimo", "financiamento", "limite")


@lru_cache
def _system_prompt() -> str:
    return _POLICY_PATH.read_text(encoding="utf-8")


@lru_cache
def _thresholds() -> dict:
    return yaml.safe_load((_CONFIGS / "thresholds.yaml").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Consent gateway: consent-service (HTTP) com fallback local (offline/testes)  #
# --------------------------------------------------------------------------- #
class ConsentGateway:
    """Verifica/concede consentimento via consent-service; cai em store local."""

    def __init__(self, base_url: str, local: ConsentStore, timeout: float = 3.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.local = local
        self._timeout = timeout

    def grant(self, record: ConsentRecord) -> ConsentRecord:
        try:
            resp = httpx.post(
                f"{self.base_url}/consent",
                json={
                    "subject_id": record.subject_id,
                    "purposes": record.purposes,
                    "terms_version": record.terms_version,
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return ConsentRecord.from_dict(resp.json())
        except httpx.HTTPError:  # limite: serviço externo — fallback offline
            return self.local.upsert(record)

    def allows(self, subject_id: str, purpose: str) -> bool:
        try:
            resp = httpx.get(
                f"{self.base_url}/consent/{subject_id}/check",
                params={"purpose": purpose},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return bool(resp.json().get("allowed", False))
        except httpx.HTTPError:  # fallback offline
            record = self.local.get(subject_id)
            return bool(record and record.allows(purpose))


# --------------------------------------------------------------------------- #
# Dependências (sobrescrevíveis em testes)                                     #
# --------------------------------------------------------------------------- #
def get_llm(settings: Annotated[Settings, Depends(get_settings)]) -> LLMBackend:
    return get_backend(settings)


@lru_cache
def get_consent_gateway() -> ConsentGateway:
    """Singleton do gateway de consentimento (limpe o cache em testes)."""
    settings = get_settings()
    return ConsentGateway(settings.consent_service_url, InMemoryConsentStore())


@lru_cache
def get_vector_store() -> VectorStore:
    """Singleton do vector store (limpe o cache em testes)."""
    settings = get_settings()
    return build_vector_store(
        settings.vector_store, url=settings.qdrant_url, collection=settings.qdrant_collection
    )


@lru_cache
def get_treatment_registry() -> TreatmentRegistry:
    """Singleton do registro de tratamento (limpe o cache em testes)."""
    settings = get_settings()
    return TreatmentRegistry(settings.treatment_log_path)


@lru_cache
def get_minimizer() -> Minimizer:
    """Singleton do minimizador de PII (Presidio se disponível; senão, BR determinístico)."""
    settings = get_settings()
    th = _thresholds()
    operators = th.get("pii", {}).get("operators", {})
    min_score = float(th.get("pii", {}).get("min_score", 0.5))
    if settings.presidio_analyzer_url and settings.presidio_anonymizer_url:
        presidio = PresidioHttpMinimizer(
            settings.presidio_analyzer_url, settings.presidio_anonymizer_url
        )
        # Testa disponibilidade; se falhar, cai no detector determinístico.
        try:
            httpx.get(f"{settings.presidio_analyzer_url.rstrip('/')}/health", timeout=2.0)
            return presidio
        except httpx.HTTPError:
            logger.warning("Presidio indisponível — usando detector BR determinístico.")
    return DeterministicMinimizer(min_score=min_score, operators=operators)


@asynccontextmanager
async def lifespan(_: FastAPI):
    s = get_settings()
    logging.basicConfig(level=s.log_level)
    tier, _, _ = classify_ai_system(_risk_capabilities(s))
    logger.info(
        "Aurora Assist %s | tier=%s consent=%s minimize=%s residency=%s",
        s.model_version,
        tier.value,
        s.enforce_consent,
        s.minimize_pii,
        s.data_residency_region,
    )
    yield


app = FastAPI(
    title="Aurora Assist v2.5 (compliant)",
    description="rag-api LGPD/GDPR/EU AI Act-compliant (Aula 05).",
    version="2.5.0",
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
    terms_version: str | None = None


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, examples=["Qual a taxa do CDB do Aurora?"])
    subject_id: str = Field(default="anon", examples=["cli-90432"])
    purpose: str = Field(default="faq_produtos", examples=["faq_produtos", "consulta_saldo"])
    top_k: int = Field(default=3, ge=0, le=10)


class ChatResponse(BaseModel):
    answer: str
    backend: str
    purpose: str
    consent_ok: bool
    blocked: bool
    block_reason: str | None = None
    minimized_entities: list[str] = Field(default_factory=list)
    treatment_index: int | None = None
    ai_act_tier: str
    data_residency: str


class IndexIn(BaseModel):
    doc_id: str
    subject_id: str
    text: str
    metadata: dict = Field(default_factory=dict)


class SearchIn(BaseModel):
    query: str
    top_k: int = Field(default=3, ge=1, le=10)


class SubjectIn(BaseModel):
    subject_id: str = Field(..., examples=["cli-90432"])


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _risk_capabilities(settings: Settings) -> list[str]:
    """Capabilities declaradas segundo o tier configurado (Doc 04, §7)."""
    caps = ["conversational", "informational_assistant", "balance_inquiry"]
    if settings.ai_act_risk_tier.lower() == "high":
        caps.append("credit_decision")
    return caps


def _is_credit_decision(text: str) -> bool:
    """Detecta pedido de DECISÃO automatizada de crédito (GDPR art. 22)."""
    low = text.lower()
    has_credit = any(term in low for term in _CREDIT_TERMS)
    has_decision = any(verb in low for verb in _DECISION_VERBS)
    return has_credit and has_decision


def _purpose_requires_consent(purpose: str) -> bool:
    op = (load_treatment_policies().get("operations") or {}).get(purpose, {})
    return bool(op.get("requires_consent", False))


# --------------------------------------------------------------------------- #
# Endpoints                                                                    #
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, object]:
    return {
        "service": "aurora-assist-compliant",
        "version": "2.5.0",
        "endpoints": [
            "/chat",
            "/rag/index",
            "/rag/search",
            "/dsr/access",
            "/dsr/erasure",
            "/treatment/records",
            "/compliance/summary",
            "/config",
        ],
    }


@app.get("/config")
def config(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, object]:
    tier, obligations, rationale = classify_ai_system(_risk_capabilities(settings))
    return {
        "model_version": settings.model_version,
        "ai_act_tier": tier.value,
        "ai_act_obligations": obligations,
        "ai_act_rationale": rationale,
        "enforce_consent": settings.enforce_consent,
        "minimize_pii": settings.minimize_pii,
        "refuse_automated_credit_decision": settings.refuse_automated_credit_decision,
        "ai_disclosure_enabled": settings.ai_disclosure_enabled,
        "data_residency_region": settings.data_residency_region,
    }


@app.post("/consent")
def set_consent(
    body: ConsentIn, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, object]:
    """Proxy de concessão de consentimento (consent-service; fallback local)."""
    gateway = get_consent_gateway()
    record = ConsentRecord(
        subject_id=body.subject_id,
        purposes=dict(body.purposes),
        terms_version=body.terms_version or settings.consent_terms_version,
    )
    return gateway.grant(record).to_dict()


@app.post("/chat", response_model=ChatResponse)
def chat(
    req: ChatRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    llm: Annotated[LLMBackend, Depends(get_llm)],
) -> ChatResponse:
    """Chat CONFORME: consent -> minimização -> RAG -> transparência -> tratamento."""
    tier, _, _ = classify_ai_system(_risk_capabilities(settings))
    subject_ref = pseudonymize(req.subject_id)

    # 1) Recusa de DECISÃO automatizada de crédito (GDPR art. 22; Doc 04, §5,§7).
    if settings.refuse_automated_credit_decision and _is_credit_decision(req.message):
        return ChatResponse(
            answer=(
                "Não realizo decisões automatizadas sobre crédito. Sua solicitação "
                "será encaminhada para análise humana, conforme a LGPD (art. 20) e o "
                "GDPR (art. 22). Você tem direito a revisão por uma pessoa."
            ),
            backend="policy",
            purpose=req.purpose,
            consent_ok=False,
            blocked=True,
            block_reason="automated_credit_decision",
            ai_act_tier=tier.value,
            data_residency=settings.data_residency_region,
        )

    # 2) Consentimento por finalidade (art. 7). Finalidades que exigem opt-in
    #    (ex.: treino_modelo) SÓ prosseguem com consentimento vigente.
    consent_ok = True
    if settings.enforce_consent and _purpose_requires_consent(req.purpose):
        consent_ok = get_consent_gateway().allows(req.subject_id, req.purpose)
        if not consent_ok:
            return ChatResponse(
                answer=(
                    "Não há consentimento vigente para esta finalidade. Sem base legal "
                    "adequada (LGPD art. 7), não posso prosseguir com este tratamento."
                ),
                backend="policy",
                purpose=req.purpose,
                consent_ok=False,
                blocked=True,
                block_reason="missing_consent",
                ai_act_tier=tier.value,
                data_residency=settings.data_residency_region,
            )

    # 3) Minimização de PII no prompt (art. 6, V; Doc 04, §2).
    minimized_entities: list[str] = []
    prompt = req.message
    if settings.minimize_pii:
        result = get_minimizer().minimize(req.message)
        prompt = result.text
        minimized_entities = sorted({m.entity.value for m in result.matches})

    # 4) RAG: recupera contexto e MINIMIZA o que foi recuperado (evita vazar PII
    #    de embeddings — Doc 04, §10). Consulta o vector store.
    context = ""
    if req.top_k:
        store = get_vector_store()
        hits = store.search(prompt, top_k=req.top_k)
        pieces = []
        for record, _score in hits:
            snippet = record.text
            if settings.minimize_pii:
                snippet = get_minimizer().minimize(snippet).text
            pieces.append(snippet)
        context = "\n".join(pieces)

    # 5) Modelo + transparência EU AI Act (art. 50 — informar que é IA).
    answer = llm.chat(system=_system_prompt(), user=prompt, context=context)
    if settings.ai_disclosure_enabled:
        disclosure = _thresholds().get("transparency", {}).get("ai_disclosure", "")
        if disclosure:
            answer = f"{disclosure}\n\n{answer}"

    # 6) Registro de tratamento (WORM) — art. 37. Apenas metadados (minimização).
    treatment_index: int | None = None
    try:
        record = build_treatment_record(req.purpose, subject_ref)
        entry = get_treatment_registry().record(record)
        treatment_index = entry.index
    except KeyError:
        logger.warning("Finalidade sem política de tratamento: %s", req.purpose)

    return ChatResponse(
        answer=answer,
        backend=llm.name,
        purpose=req.purpose,
        consent_ok=consent_ok,
        blocked=False,
        minimized_entities=minimized_entities,
        treatment_index=treatment_index,
        ai_act_tier=tier.value,
        data_residency=settings.data_residency_region,
    )


@app.post("/rag/index")
def rag_index(
    body: IndexIn, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, object]:
    """Indexa um documento no vector store (com o titular a que pertence)."""
    store = get_vector_store()
    store.upsert(
        VectorRecord(
            doc_id=body.doc_id, subject_id=body.subject_id, text=body.text, metadata=body.metadata
        )
    )
    return {"indexed": body.doc_id, "subject_id": body.subject_id, "total": store.count()}


@app.post("/rag/search")
def rag_search(
    body: SearchIn, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, object]:
    hits = get_vector_store().search(body.query, top_k=body.top_k)
    return {
        "query": body.query,
        "results": [
            {"doc_id": r.doc_id, "subject_id": r.subject_id, "score": round(s, 4)} for r, s in hits
        ],
    }


@app.post("/dsr/access")
def dsr_access(
    body: SubjectIn, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, object]:
    """Direito de confirmação e acesso (art. 18, I-II): tudo que sabemos do titular."""
    subject_ref = pseudonymize(body.subject_id)
    store = get_vector_store()
    registry = get_treatment_registry()
    local_consent = get_consent_gateway().local.get(body.subject_id)
    return {
        "subject_id": body.subject_id,
        "consent": local_consent.to_dict() if local_consent else None,
        "indexed_documents": [r.to_dict() for r in store.list_by_subject(body.subject_id)],
        "treatment_records": registry.query(subject_ref=subject_ref),
    }


@app.post("/dsr/erasure")
def dsr_erasure(
    body: SubjectIn, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, object]:
    """Direito ao esquecimento (art. 18, VI): purga seletiva no vector store.

    Cobre a camada de RECUPERAÇÃO (Doc 04, §10, Snippet 3). Registra a operação e
    revoga o consentimento. O limite do fine-tuning é honestamente sinalizado.
    """
    store = get_vector_store()
    purge: PurgeResult = store.purge_subject(body.subject_id)

    # Revoga consentimento e registra o tratamento de exclusão (art. 37).
    gateway = get_consent_gateway()
    if gateway.local.get(body.subject_id) is not None:
        gateway.local.revoke(body.subject_id)
    try:
        rec = build_treatment_record("faq_produtos", pseudonymize(body.subject_id))
        rec.operation = "direito_ao_esquecimento"
        get_treatment_registry().record(rec)
    except KeyError:
        pass

    return purge.to_dict()


@app.get("/treatment/records")
def treatment_records(
    settings: Annotated[Settings, Depends(get_settings)],
    subject_id: str | None = None,
    operation: str | None = None,
) -> dict[str, object]:
    """Consulta o registro de operações de tratamento (RoPA — art. 37)."""
    registry = get_treatment_registry()
    subject_ref = pseudonymize(subject_id) if subject_id else None
    return {
        "chain_integrity": registry.verify(),
        "records": registry.query(subject_ref=subject_ref, operation=operation),
    }


@app.get("/compliance/summary")
def compliance_summary(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, object]:
    """Painel de conformidade (análogo a um Azure Workbook — Doc 04, §Hands On)."""
    tier, obligations, _ = classify_ai_system(_risk_capabilities(settings))
    registry = get_treatment_registry()
    store = get_vector_store()
    return {
        "ai_act_tier": tier.value,
        "ai_act_obligations": obligations,
        "data_residency_region": settings.data_residency_region,
        "treatment_records": len(registry.entries()),
        "treatment_chain_integrity": registry.verify(),
        "indexed_documents": store.count(),
        "controls": {
            "enforce_consent": settings.enforce_consent,
            "minimize_pii": settings.minimize_pii,
            "refuse_automated_credit_decision": settings.refuse_automated_credit_decision,
            "ai_disclosure_enabled": settings.ai_disclosure_enabled,
        },
        "high_risk": tier == RiskTier.HIGH,
    }
