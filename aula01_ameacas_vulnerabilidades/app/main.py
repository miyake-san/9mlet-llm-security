"""Aurora Assist v0 — API FastAPI DELIBERADAMENTE VULNERÁVEL (Aula 01, vídeo 4).

Endpoints:
    GET  /health          — liveness.
    GET  /                — descrição do serviço.
    POST /chat            — chat ingênuo (sem guardrail) — expõe LLM01/LLM06.
    POST /rag             — RAG ingênuo — expõe injeção INDIRETA (LLM01).
    POST /tools/balance   — ferramenta insegura — expõe LLM07/LLM08.

⚠️ Nenhuma camada defensiva é aplicada, POR DESIGN. O objetivo é medir a
linha de base de insegurança que a Aula 02 (Guardrails) irá corrigir.

Referência:
    OWASP Foundation (2025). Top 10 for LLM Applications, v2025.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from app.config import Settings, get_settings
from app.llm import LLMBackend, get_backend
from app.rag import Document, build_context, load_corpus, naive_retrieve
from app.tools import extract_cpf, get_balance
from src.security.detectors import detect_injection

logger = logging.getLogger(__name__)

_POLICY_PATH = Path(__file__).resolve().parent / "policies" / "aurora_assist_system_prompt.md"


@lru_cache
def _system_prompt() -> str:
    """Carrega (uma vez) o system prompt ingênuo do Aurora Assist."""
    return _POLICY_PATH.read_text(encoding="utf-8")


@lru_cache
def _corpus() -> tuple[Document, ...]:
    """Corpus de RAG carregado sob demanda (imutável para o cache)."""
    return tuple(load_corpus())


def get_llm(settings: Annotated[Settings, Depends(get_settings)]) -> LLMBackend:
    """Dependência de backend de LLM (sobrescrevível em testes)."""
    return get_backend(settings)


@asynccontextmanager
async def lifespan(_: FastAPI):
    logging.basicConfig(level=get_settings().log_level)
    logger.warning(
        "Aurora Assist v0 — API VULNERAVEL por design (Aula 01). NAO usar em producao."
    )
    yield


app = FastAPI(
    title="Aurora Assist v0 (vulnerable)",
    description="API deliberadamente insegura para red team em laboratório (Aula 01).",
    version="0.1.0",
    lifespan=lifespan,
)


# --------------------------------------------------------------------------- #
# Schemas                                                                      #
# --------------------------------------------------------------------------- #
class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, examples=["Explique o CDB do Aurora."])


class ChatResponse(BaseModel):
    answer: str
    backend: str
    # Apenas OBSERVA injeção (não bloqueia). A Aula 02 transforma isto em bloqueio.
    detected_injection: list[str] = Field(default_factory=list)


class RagRequest(BaseModel):
    query: str = Field(..., min_length=1, examples=["Quais as tarifas da conta digital?"])


class RagResponse(BaseModel):
    answer: str
    backend: str
    retrieved: list[str]


class ToolRequest(BaseModel):
    message: str = Field(..., min_length=1, examples=["Qual o saldo do CPF 123.456.789-09?"])
    cpf: str | None = None


class ToolResponse(BaseModel):
    cpf: str | None
    balance: float | None
    currency: str = "BRL"
    note: str


# --------------------------------------------------------------------------- #
# Endpoints                                                                    #
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, object]:
    return {
        "service": "aurora-assist-v0",
        "warning": "VULNERÁVEL por design (Aula 01) — não usar em produção.",
        "endpoints": ["/chat", "/rag", "/tools/balance", "/health"],
    }


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest, llm: Annotated[LLMBackend, Depends(get_llm)]) -> ChatResponse:
    """Chat ingênuo: sem guardrail de entrada/saída (LLM01/LLM06)."""
    observed = [m.technique for m in detect_injection(req.message)]
    answer = llm.chat(system=_system_prompt(), user=req.message)
    return ChatResponse(answer=answer, backend=llm.name, detected_injection=observed)


@app.post("/rag", response_model=RagResponse)
def rag(req: RagRequest, llm: Annotated[LLMBackend, Depends(get_llm)]) -> RagResponse:
    """RAG ingênuo: texto recuperado entra CRU no contexto (injeção indireta)."""
    docs = naive_retrieve(req.query, list(_corpus()), k=3)
    context = build_context(docs)
    answer = llm.chat(system=_system_prompt(), user=req.query, context=context)
    return RagResponse(answer=answer, backend=llm.name, retrieved=[d.id for d in docs])


@app.post("/tools/balance", response_model=ToolResponse)
def tool_balance(req: ToolRequest) -> ToolResponse:
    """Ferramenta insegura: consulta saldo por CPF arbitrário (confused deputy)."""
    cpf = req.cpf or extract_cpf(req.message)
    if not cpf:
        return ToolResponse(cpf=None, balance=None, note="Nenhum CPF encontrado na mensagem.")
    balance = get_balance(cpf)
    return ToolResponse(
        cpf=cpf,
        balance=balance,
        note="Consulta SEM autenticação/autorização — demonstra LLM07/LLM08 (confused deputy).",
    )
