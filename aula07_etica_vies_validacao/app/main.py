"""Aurora Assist v2.5 — target-api RAG avaliada (Aula 07).

Esta é a aplicação **avaliada** pela stack de IA Responsável desta aula. Ela faz
RAG (recupera documentos e responde) e também produz **decisões de encaminhamento**
de produto — as duas saídas que o ``eval-runner`` mede quanto a qualidade, viés e
fidelidade (Doc 04, "Saudável não é o mesmo que justo").

Duas flags de mitigação controlam o comportamento (padrão: desligadas, para expor
problemas mensuráveis; o Lab liga-as para medir E = 1 - R₁/R₀):
    * ``FAIRNESS_MITIGATION``   — neutraliza o atributo protegido na decisão.
    * ``RAG_STRICT_GROUNDING``  — abstém-se quando o fato não está no contexto.

Endpoints:
    GET  /health   — liveness.
    GET  /         — descrição do serviço.
    GET  /config   — flags de mitigação ativas (o Lab usa para medir E).
    POST /chat      — resposta RAG (answer + contextos recuperados).
    POST /decision  — encaminhamento de produto para um perfil (saída de fairness).

Referência:
    Microsoft (2022). Responsible AI Standard v2.
    Es, S. et al. (2024). RAGAS. EACL.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from app.config import Settings, get_settings
from app.llm import LLMBackend, Profile, get_backend
from app.rag import Retriever

logger = logging.getLogger(__name__)


@lru_cache
def _retriever() -> Retriever:
    """Índice RAG carregado uma única vez (corpus do Aurora)."""
    return Retriever.from_corpus()


def get_llm(settings: Annotated[Settings, Depends(get_settings)]) -> LLMBackend:
    """Dependência de backend de LLM (sobrescrevível em testes)."""
    return get_backend(settings)


@asynccontextmanager
async def lifespan(_: FastAPI):
    s = get_settings()
    logging.basicConfig(level=s.log_level)
    logger.info(
        "Aurora Assist %s | fairness_mitigation=%s strict_grounding=%s docs=%d",
        s.model_version,
        s.fairness_mitigation,
        s.rag_strict_grounding,
        len(_retriever().documents),
    )
    yield


app = FastAPI(
    title="Aurora Assist v2.5 (RAG, avaliado)",
    description="Alvo da avaliação de qualidade, viés e fidelidade (Aula 07).",
    version="2.5.0",
    lifespan=lifespan,
)


# --------------------------------------------------------------------------- #
# Schemas                                                                      #
# --------------------------------------------------------------------------- #
class ChatRequest(BaseModel):
    question: str = Field(..., min_length=1, examples=["Qual a taxa do CDB do Aurora Prime?"])


class ChatResponse(BaseModel):
    answer: str
    contexts: list[str]
    backend: str
    model_version: str


class DecisionRequest(BaseModel):
    id: str = Field(..., examples=["cli-001"])
    name: str = Field(..., examples=["Maria"])
    group: str = Field(..., examples=["A", "B"])
    qualified: int = Field(..., ge=0, le=1, examples=[1])
    income: float = Field(default=0.0, ge=0.0)
    request: str = Field(default="", examples=["crédito pessoal"])


class DecisionResponse(BaseModel):
    outcome: int
    product: str
    answer: str
    group: str
    backend: str
    model_version: str


# --------------------------------------------------------------------------- #
# Endpoints                                                                    #
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, object]:
    return {
        "service": "aurora-assist-rag",
        "version": "2.5.0",
        "endpoints": ["/chat", "/decision", "/config", "/health"],
    }


@app.get("/config")
def config(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, object]:
    """Expõe as flags de mitigação (o Lab usa para medir E = 1 - R₁/R₀)."""
    return {
        "model_version": settings.model_version,
        "fairness_mitigation": settings.fairness_mitigation,
        "rag_strict_grounding": settings.rag_strict_grounding,
        "rag_top_k": settings.rag_top_k,
    }


@app.post("/chat", response_model=ChatResponse)
def chat(
    req: ChatRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    llm: Annotated[LLMBackend, Depends(get_llm)],
) -> ChatResponse:
    """Resposta RAG: recupera contexto e gera resposta (fundamentada ou não)."""
    hits = _retriever().search(req.question, settings.rag_top_k)
    contexts = [doc.text for doc, _ in hits]
    answer = llm.generate(req.question, contexts, strict_grounding=settings.rag_strict_grounding)
    return ChatResponse(
        answer=answer,
        contexts=contexts,
        backend=llm.name,
        model_version=settings.model_version,
    )


@app.post("/decision", response_model=DecisionResponse)
def decision(
    req: DecisionRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    llm: Annotated[LLMBackend, Depends(get_llm)],
) -> DecisionResponse:
    """Encaminhamento de produto para um perfil (saída avaliável de fairness)."""
    profile = Profile(
        id=req.id,
        name=req.name,
        group=req.group,
        qualified=req.qualified,
        income=req.income,
        request=req.request,
    )
    result = llm.decide(profile, mitigate_fairness=settings.fairness_mitigation)
    return DecisionResponse(
        outcome=result.outcome,
        product=result.product,
        answer=result.answer,
        group=req.group,
        backend=llm.name,
        model_version=settings.model_version,
    )
