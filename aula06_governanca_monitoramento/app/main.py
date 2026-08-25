"""Aurora Assist v2.6 — app OTel-instrumentado (Aula 06 — LLMOps).

Cada requisição é OBSERVADA fim-a-fim (Doc 04, §Observabilidade): o /chat gera um
span com convenções **gen_ai.*** (modelo, tokens, custo, latência) e sinais de
segurança (bloqueio de jailbreak, groundedness, vazamento de PII). A telemetria
alimenta:

    * /metrics    — métricas SLI no formato Prometheus (raspadas pelo Grafana);
    * Langfuse    — tracing por step (opcional);
    * /drift/check — detecção de drift (KS/PSI/MMD/Wasserstein) sobre o tráfego;
    * /slo/report  — avaliação de SLIs/SLOs/Data SLOs com error budget;
    * /feedback    — loop de feedback governado (nunca PII em claro).

O app NÃO treina modelo: ele monitora e governa o Aurora Assist em produção.

Referência:
    OpenTelemetry (2024). gen_ai.* · Beyer et al. (2016). SRE.
    Doc 04, §Observabilidade, §SLOs, §"Feedback loops".
"""

from __future__ import annotations

import json
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Annotated

import yaml
from fastapi import Depends, FastAPI
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST
from pydantic import BaseModel, Field

from app.config import Settings, get_settings
from app.llm import LLMBackend, get_backend
from app.observability import Instrumentation, build_instrumentation
from src.security.drift import DriftDetector, embed
from src.security.metrics import aggregate_slis, lexical_overlap
from src.security.observability import new_span, pseudonymize, redact_preview
from src.security.pii import contains_pii
from src.security.schemas import (
    DriftMethod,
    FeedbackRecord,
    GenAISpan,
    RequestMetric,
)
from src.security.slo import evaluate_all, load_slo_definitions

logger = logging.getLogger(__name__)

_APP_DIR = Path(__file__).resolve().parent
_ROOT = _APP_DIR.parent
_POLICY_PATH = _APP_DIR / "policies" / "aurora_assist_system_prompt.md"
_CONFIGS = _ROOT / "configs"

# Marcadores simples de jailbreak (Aula 02) — instrumentados para monitorar a
# taxa de bloqueio como SLI de segurança (Doc 04, §SLOs).
_JAILBREAK_MARKERS = (
    "ignore as instru",
    "ignore previous",
    "desconsidere",
    "aja como",
    "sem restri",
    "modo desenvolvedor",
    "developer mode",
    "revele o system prompt",
    "system prompt",
    "jailbreak",
    "dan mode",
    "bypass",
)

# Base de conhecimento institucional (fallback se `data/knowledge` não existir).
_KNOWLEDGE_FALLBACK = [
    {
        "doc_id": "kb-horarios",
        "title": "Horários das Agências",
        "text": (
            "As agências do Banco Aurora funcionam de segunda a sexta. "
            "A agência central atende das 10h às 16h."
        ),
    },
    {
        "doc_id": "kb-cdb",
        "title": "Rendimento do CDB",
        "text": (
            "O CDB Aurora rende um percentual do CDI conforme o prazo. "
            "Acima de 720 dias, a alíquota de IR é de 15%."
        ),
    },
    {
        "doc_id": "kb-tarifas",
        "title": "Tarifas de Serviços",
        "text": (
            "O pacote essencial inclui 4 saques e 2 transferências por mês. "
            "A taxa do CDB acompanha o CDI."
        ),
    },
]


@lru_cache
def _system_prompt() -> str:
    if _POLICY_PATH.exists():
        return _POLICY_PATH.read_text(encoding="utf-8")
    return "Você é o Aurora Assist, assistente do Banco Aurora. Responda com base no contexto."


@lru_cache
def _thresholds() -> dict:
    path = _CONFIGS / "thresholds.yaml"
    if path.exists():
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    return {}


# --------------------------------------------------------------------------- #
# Base de conhecimento em memória (retrieval simples para groundedness)         #
# --------------------------------------------------------------------------- #
@dataclass
class _Doc:
    doc_id: str
    title: str
    text: str
    vector: list


class KnowledgeBase:
    """Índice em memória com embedding determinístico (frescor = idade da carga)."""

    def __init__(self, records: list[dict]) -> None:
        self.docs = [
            _Doc(r["doc_id"], r.get("title", ""), r["text"], list(embed(r["text"])))
            for r in records
        ]
        self.loaded_at = time.time()

    def search(self, query: str, top_k: int = 3) -> list[str]:
        if top_k <= 0 or not self.docs:
            return []
        q = embed(query)
        scored = [
            (doc, float(sum(a * b for a, b in zip(q, doc.vector, strict=False))))
            for doc in self.docs
        ]
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return [doc.text for doc, _ in scored[:top_k]]

    @property
    def age_seconds(self) -> float:
        """Frescor documental (Data SLO — Doc 04): segundos desde a última carga."""
        return time.time() - self.loaded_at


@lru_cache
def get_knowledge() -> KnowledgeBase:
    """Singleton da base de conhecimento (limpe o cache em testes)."""
    path = _ROOT / "data" / "knowledge" / "knowledge.jsonl"
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines if line]
        return KnowledgeBase(records)
    return KnowledgeBase(_KNOWLEDGE_FALLBACK)


@lru_cache
def get_instrumentation() -> Instrumentation:
    """Singleton da instrumentação (Prometheus/OTel/Langfuse). Limpe em testes."""
    return build_instrumentation(get_settings(), _thresholds())


class _FeedbackStore:
    """Store de feedback em memória (loop governado — Doc 04, §"Feedback loops")."""

    def __init__(self) -> None:
        self._items: list[FeedbackRecord] = []

    def add(self, record: FeedbackRecord) -> FeedbackRecord:
        self._items.append(record)
        return record

    def all(self) -> list[FeedbackRecord]:
        return list(self._items)


@lru_cache
def get_feedback_store() -> _FeedbackStore:
    """Singleton do store de feedback (limpe o cache em testes)."""
    return _FeedbackStore()


def get_llm(settings: Annotated[Settings, Depends(get_settings)]) -> LLMBackend:
    return get_backend(settings)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _is_jailbreak(text: str) -> bool:
    low = text.lower()
    return any(marker in low for marker in _JAILBREAK_MARKERS)


def _is_regulated(text: str) -> bool:
    terms = _thresholds().get("groundedness", {}).get("regulated_terms", [])
    low = text.lower()
    return any(term in low for term in terms)


@asynccontextmanager
async def lifespan(_: FastAPI):
    s = get_settings()
    logging.basicConfig(level=s.log_level)
    kb = get_knowledge()
    logger.info(
        "Aurora Assist %s | maturity=L%d backend=%s docs=%d cache=%s routing=%s",
        s.model_version,
        s.llmops_maturity_level,
        s.llm_backend,
        len(kb.docs),
        s.semantic_cache_enabled,
        s.model_routing_enabled,
    )
    yield


app = FastAPI(
    title="Aurora Assist v2.6 (observable)",
    description="app OTel-instrumentado com drift, SLOs e token economics (Aula 06).",
    version="2.6.0",
    lifespan=lifespan,
)


# --------------------------------------------------------------------------- #
# Schemas                                                                      #
# --------------------------------------------------------------------------- #
class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, examples=["Qual a taxa do CDB do Aurora?"])
    subject_id: str = Field(default="anon", examples=["cli-90432"])
    top_k: int = Field(default=3, ge=0, le=10)


class ChatResponse(BaseModel):
    answer: str
    backend: str
    model: str
    blocked: bool
    block_reason: str | None = None
    cache_hit: bool
    input_tokens: int
    output_tokens: int
    cost_usd: float
    latency_ms: float
    groundedness: float | None = None
    regulated: bool
    pii_leak: bool
    trace_id: str


class DriftWindow(BaseModel):
    prompts: list[str] = Field(default_factory=list)
    latency_ms: list[float] = Field(default_factory=list)
    response_len: list[float] = Field(default_factory=list)
    groundedness: list[float] = Field(default_factory=list)


class DriftRequest(BaseModel):
    reference: DriftWindow | None = None
    production: DriftWindow | None = None


class FeedbackIn(BaseModel):
    request_id: str = Field(..., examples=["trace-abc123"])
    rating: int = Field(..., ge=-1, le=1)
    subject_id: str = Field(default="anon")
    comment: str = Field(default="")


# --------------------------------------------------------------------------- #
# Endpoints — saúde e metadados                                                #
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, object]:
    return {
        "service": "aurora-assist-observable",
        "version": "2.6.0",
        "endpoints": [
            "/chat",
            "/metrics",
            "/drift/check",
            "/slo/report",
            "/feedback",
            "/traces",
            "/config",
        ],
    }


@app.get("/config")
def config(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, object]:
    return {
        "model_version": settings.model_version,
        "llmops_maturity_level": settings.llmops_maturity_level,
        "llm_backend": settings.llm_backend,
        "semantic_cache_enabled": settings.semantic_cache_enabled,
        "model_routing_enabled": settings.model_routing_enabled,
        "otel_traces_enabled": settings.otel_traces_enabled,
        "langfuse_enabled": settings.langfuse_enabled,
        "minimize_telemetry_pii": settings.minimize_telemetry_pii,
    }


# --------------------------------------------------------------------------- #
# /chat — o coração instrumentado (Doc 04, §Observabilidade)                    #
# --------------------------------------------------------------------------- #
@app.post("/chat", response_model=ChatResponse)
def chat(
    req: ChatRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    llm: Annotated[LLMBackend, Depends(get_llm)],
) -> ChatResponse:
    inst = get_instrumentation()
    regulated = _is_regulated(req.message)
    preview = redact_preview(req.message) if settings.minimize_telemetry_pii else req.message[:120]
    model, _is_complex = inst.route(req.message)

    # 1) Guardrail de jailbreak instrumentado (SLI de segurança — Doc 04, §SLOs).
    if _is_jailbreak(req.message):
        span = new_span(
            "aurora_assist.chat",
            system=settings.llm_backend,
            model=model,
            input_tokens=0,
            output_tokens=0,
            latency_ms=0.5,
            cost_usd=0.0,
            blocked=True,
            block_reason="jailbreak",
            regulated=regulated,
            prompt_preview=preview,
        )
        inst.record(span)
        return _to_response(span, backend=settings.llm_backend, answer=(
            "Não posso atender a esse pedido. Sigo as políticas de segurança do Banco Aurora."
        ))

    # 2) Cache semântico (token economics — hit = 0 tokens/custo).
    start = time.perf_counter()
    cached = inst.cache_lookup(req.message)
    if cached is not None:
        latency_ms = (time.perf_counter() - start) * 1000.0
        span = new_span(
            "aurora_assist.chat",
            system=settings.llm_backend,
            model=model,
            input_tokens=0,
            output_tokens=0,
            latency_ms=latency_ms,
            cost_usd=0.0,
            cache_hit=True,
            regulated=regulated,
            prompt_preview=preview,
            pii_leak=contains_pii(cached),
        )
        inst.record(span)
        return _to_response(span, backend=settings.llm_backend, answer=cached)

    # 3) RAG + modelo (medindo latência do passo caro).
    context = "\n".join(get_knowledge().search(req.message, top_k=req.top_k))
    result = llm.chat(system=_system_prompt(), user=req.message, context=context)
    latency_ms = (time.perf_counter() - start) * 1000.0

    grounded = lexical_overlap(result.text, context) if context else None
    cost = inst.cost.cost(model, result.input_tokens, result.output_tokens)
    span = new_span(
        "aurora_assist.chat",
        system=settings.llm_backend,
        model=model,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        latency_ms=latency_ms,
        cost_usd=cost,
        groundedness=grounded,
        regulated=regulated,
        prompt_preview=preview,
        pii_leak=contains_pii(result.text),
    )
    inst.record(span)
    inst.cache_store(req.message, result.text)
    return _to_response(span, backend=settings.llm_backend, answer=result.text)


def _to_response(span: GenAISpan, *, backend: str, answer: str) -> ChatResponse:
    return ChatResponse(
        answer=answer,
        backend=backend,
        model=span.gen_ai_request_model,
        blocked=span.blocked,
        block_reason=span.block_reason,
        cache_hit=span.cache_hit,
        input_tokens=span.input_tokens,
        output_tokens=span.output_tokens,
        cost_usd=round(span.cost_usd, 6),
        latency_ms=round(span.latency_ms, 2),
        groundedness=(round(span.groundedness, 4) if span.groundedness is not None else None),
        regulated=span.regulated,
        pii_leak=span.pii_leak,
        trace_id=span.trace_id,
    )


# --------------------------------------------------------------------------- #
# /metrics — exposição Prometheus (Doc 04, §Observabilidade)                    #
# --------------------------------------------------------------------------- #
@app.get("/metrics")
def metrics() -> Response:
    return Response(content=get_instrumentation().prometheus_text(), media_type=CONTENT_TYPE_LATEST)


# --------------------------------------------------------------------------- #
# /drift/check — detecção estatística de drift (Doc 04, §Drift)                 #
# --------------------------------------------------------------------------- #
def _load_traffic(path: str) -> dict[str, list]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    rows = [json.loads(line) for line in lines if line]
    return {
        "prompts": [r.get("prompt", "") for r in rows],
        "latency_ms": [float(r.get("latency_ms", 0.0)) for r in rows],
        "response_len": [float(r.get("response_len", 0.0)) for r in rows],
        "groundedness": [float(r.get("groundedness", 0.0)) for r in rows],
    }


@app.post("/drift/check")
def drift_check(
    body: DriftRequest, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, object]:
    """Compara janela de referência vs produção (corpo ou arquivos padrão)."""
    if body.reference and body.production:
        ref, now = body.reference.model_dump(), body.production.model_dump()
    else:
        try:
            ref = _load_traffic(settings.drift_reference_path)
            now = _load_traffic(settings.drift_production_path)
        except OSError:
            return {"error": "tráfego não encontrado — rode `uv run task seed-data`."}

    detector = DriftDetector(_thresholds().get("drift", {}))
    results = [
        detector.prompt_drift(ref["prompts"], now["prompts"]),
        detector.response_drift(ref["response_len"], now["response_len"], method=DriftMethod.KS),
        detector.response_drift(ref["groundedness"], now["groundedness"]),
        detector.credit_stability(ref["latency_ms"], now["latency_ms"]),
    ]
    inst = get_instrumentation()
    for res in results:
        inst.set_drift_score(res.method.value, res.statistic)
    assessment = detector.assess(results)
    return {"assessment": assessment, "results": [r.to_dict() for r in results]}


# --------------------------------------------------------------------------- #
# /slo/report — SLIs/SLOs/Data SLOs com error budget (Doc 04, §SLOs)            #
# --------------------------------------------------------------------------- #
@app.get("/slo/report")
def slo_report() -> dict[str, object]:
    inst = get_instrumentation()
    metrics_list: list[RequestMetric] = inst.metrics()
    slis = aggregate_slis(metrics_list)
    slis["knowledge_age_seconds"] = get_knowledge().age_seconds
    report = evaluate_all(load_slo_definitions(_CONFIGS / "slo.yaml"), slis)
    return {"slis": {k: round(v, 4) for k, v in slis.items()}, "report": report.to_dict()}


# --------------------------------------------------------------------------- #
# /feedback — loop de feedback governado (Doc 04, §"Feedback loops")            #
# --------------------------------------------------------------------------- #
@app.post("/feedback")
def feedback(body: FeedbackIn) -> dict[str, object]:
    """Registra feedback pseudonimizado; curadoria humana ocorre depois (não aqui)."""
    record = FeedbackRecord(
        request_id=body.request_id,
        rating=body.rating,
        subject_ref=pseudonymize(body.subject_id),
        comment=redact_preview(body.comment, max_chars=200),
        curated=False,
    )
    get_feedback_store().add(record)
    return {
        "stored": record.to_dict(),
        "note": "feedback não curado; sujeito a triagem/viés (Doc 04).",
    }


@app.get("/traces")
def traces(limit: int = 20) -> dict[str, object]:
    """Últimos spans (atributos gen_ai.* já mascarados) — Figura 3 do Doc 04."""
    spans = get_instrumentation().trace_store.spans()[-limit:]
    return {"count": len(spans), "spans": [s.to_otel_attributes() for s in spans]}
