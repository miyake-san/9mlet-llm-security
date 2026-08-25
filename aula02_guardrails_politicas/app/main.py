"""FastAPI do Aurora Assist — gateway de guardrails OU backend RAG (Aula 02).

O papel é definido por ``APP_ROLE``:

- ``gateway`` (padrão, porta 8080): aplica o *defense-in-depth*
  (:class:`GuardrailPipeline`) e encaminha o pedido aprovado ao backend RAG.
  Endpoints: ``POST /chat`` (chat guardrailado) e ``POST /guardrail``
  (análise-somente, usada por ``task scan``).
- ``rag`` (porta 8000): o Aurora Assist propriamente dito — conversa com o LLM
  (Ollama/Azure/stub). Fica PROTEGIDO por trás do gateway.

O tratamento de erro fica nos LIMITES (entrada da API e chamadas externas),
conforme a diretriz de código idiomático do prompt da disciplina.

Referência:
    Doc 04, seção 1 (defense-in-depth) e seção 7 (integração/SDK).
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.guardrails import GuardrailPipeline
from app.llm import get_backend

APP_ROLE = os.getenv("APP_ROLE", "gateway").lower()
RAG_API_URL = os.getenv("RAG_API_URL", "http://localhost:8000").rstrip("/")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "60"))

Flow = Literal["faq", "authenticated", "transactional"]


class ChatRequest(BaseModel):
    """Contrato de entrada do chat (guardrail de entrada #0: schema Pydantic)."""

    message: str = Field(min_length=1, max_length=8000)
    flow: Flow = "faq"


class GuardrailRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    flow: Flow = "faq"


class RagRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)


# Estado do app (pipeline construído uma vez no startup do gateway).
_state: dict[str, object] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    if APP_ROLE == "gateway":
        _state["pipeline"] = GuardrailPipeline()
    else:
        _state["backend"] = get_backend()
    yield
    _state.clear()


app = FastAPI(
    title=f"Aurora Assist — {APP_ROLE}",
    description="Aula 02 — Guardrails e Políticas de Segurança para LLMs",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe (usado pelos healthchecks do docker-compose)."""
    return {"status": "ok", "role": APP_ROLE}


@app.get("/")
def root() -> dict[str, object]:
    endpoints = (
        ["POST /chat", "POST /guardrail"] if APP_ROLE == "gateway" else ["POST /chat"]
    )
    return {
        "service": "Aurora Assist",
        "role": APP_ROLE,
        "lesson": "Aula 02 — Guardrails e Políticas de Segurança para LLMs",
        "endpoints": endpoints,
    }


# ---------------------------------------------------------------------- #
# Papel RAG — backend Aurora Assist (protegido por trás do gateway)
# ---------------------------------------------------------------------- #
def _require_rag_backend():
    backend = _state.get("backend")
    if backend is None:  # defensivo: chamada antes do lifespan
        backend = get_backend()
        _state["backend"] = backend
    return backend


@app.post("/chat")
def chat(req: ChatRequest) -> dict[str, object]:
    """No papel *rag*: gera a resposta. No papel *gateway*: chat guardrailado."""
    if APP_ROLE == "rag":
        backend = _require_rag_backend()
        try:
            answer = backend.generate(req.message)
        except httpx.HTTPError as error:
            raise HTTPException(status_code=503, detail=f"LLM indisponível: {error}") from error
        return {"answer": answer, "role": "rag"}

    # Papel gateway: entrada → upstream RAG → saída.
    pipeline: GuardrailPipeline = _state["pipeline"]  # type: ignore[assignment]

    def _upstream(message: str) -> str:
        try:
            with httpx.Client(timeout=LLM_TIMEOUT) as client:
                response = client.post(f"{RAG_API_URL}/chat", json={"message": message})
                response.raise_for_status()
                return str(response.json().get("answer", ""))
        except httpx.HTTPError as error:
            raise HTTPException(status_code=502, detail=f"rag-api indisponível: {error}") from error

    return pipeline.guard_chat(req.message, upstream=_upstream, flow=req.flow)


# ---------------------------------------------------------------------- #
# Papel GATEWAY — análise-somente (não chama o LLM); usada por `task scan`
# ---------------------------------------------------------------------- #
@app.post("/guardrail")
def guardrail(req: GuardrailRequest) -> dict[str, object]:
    """Analisa a entrada nas camadas de guardrail SEM invocar o modelo."""
    if APP_ROLE != "gateway":
        raise HTTPException(status_code=404, detail="Endpoint disponível apenas no gateway")
    pipeline: GuardrailPipeline = _state["pipeline"]  # type: ignore[assignment]
    decision = pipeline.run_input(req.message, flow=req.flow)
    return {
        "blocked": not decision.allowed,
        "total_latency_ms": decision.total_latency_ms,
        "decision": decision.to_dict(),
    }
