"""Aurora Assist v2.4 — target-api DEFENDIDA (Aula 04, alvo do red team).

Diferente da Aula 01 (app vulnerável por design), aqui o Aurora Assist já aplica
os controles das Aulas 02-03: guardrail de **entrada** (detecção de injeção) e de
**saída** (bloqueio de vazamento de canário/PII). O guardrail é **deliberadamente
imperfeito**: por padrão só olha a superfície do texto, sendo evadível por
ofuscação (leet/base64/split) e por escalada multi-turno. As flags
``GUARDRAIL_NORMALIZE`` e ``GUARDRAIL_CONVERSATION`` ativam a **mitigação** e
permitem medir $E = 1 - R_1/R_0$ (Doc 04, seções 8 e 13).

Cada decisão gera um **evento de auditoria** encadeado por hash (Doc 04, seções
11-12): registramos apenas metadados (versão do modelo, decisão, score, hash da
entrada, id pseudonimizado) — nunca o texto sensível bruto (minimização).

Endpoints:
    GET  /health   — liveness.
    GET  /         — descrição do serviço.
    GET  /config   — flags de guardrail ativas (para o Lab medir mitigação).
    POST /chat     — chat DEFENDIDO (single-turn e multi-turno via ``history``).

Referência:
    OWASP Foundation (2025). Top 10 for LLM Applications.
    Microsoft (2024). Lessons from Red Teaming 100 GenAI Products.
"""

from __future__ import annotations

import hashlib
import logging
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from app.config import Settings, get_settings
from app.cvss_ai import impact_weight, risk_score
from app.llm import LLMBackend, get_backend
from src.security.detectors import (
    InjectionMatch,
    contains_pii,
    detect_injection,
    is_crescendo,
    normalize_obfuscation,
)
from src.security.redteam import SYSTEM_PROMPT_CANARY

logger = logging.getLogger(__name__)

_POLICY_PATH = Path(__file__).resolve().parent / "policies" / "aurora_assist_system_prompt.md"
_REFUSAL = "Solicitação bloqueada: não posso ajudar com esse pedido."


@lru_cache
def _system_prompt() -> str:
    """Carrega (uma vez) o system prompt do Aurora Assist (ativo interno)."""
    return _POLICY_PATH.read_text(encoding="utf-8")


def get_llm(settings: Annotated[Settings, Depends(get_settings)]) -> LLMBackend:
    """Dependência de backend de LLM (sobrescrevível em testes)."""
    return get_backend(settings)


@asynccontextmanager
async def lifespan(_: FastAPI):
    s = get_settings()
    logging.basicConfig(level=s.log_level)
    logger.info(
        "Aurora Assist %s | guardrail=%s normalize=%s conversation=%s",
        s.model_version,
        s.guardrail_enabled,
        s.guardrail_normalize,
        s.guardrail_conversation,
    )
    yield


app = FastAPI(
    title="Aurora Assist v2.4 (defended)",
    description="Alvo defendido para red team em laboratório (Aula 04).",
    version="2.4.0",
    lifespan=lifespan,
)


# --------------------------------------------------------------------------- #
# Schemas                                                                      #
# --------------------------------------------------------------------------- #
class Message(BaseModel):
    role: str = Field(..., examples=["user", "assistant"])
    content: str


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, examples=["Explique o CDB do Aurora."])
    conversation_id: str | None = Field(default=None, examples=["conv-42"])
    history: list[Message] = Field(default_factory=list)


class ChatResponse(BaseModel):
    answer: str
    backend: str
    blocked: bool
    block_stage: str | None = None
    technique: str | None = None
    owasp: str | None = None
    risk_score: float
    model_version: str


# --------------------------------------------------------------------------- #
# Guardrail (imperfeito por padrão; mitigável por flags)                       #
# --------------------------------------------------------------------------- #
def _screen_input(text: str, history: list[Message], settings: Settings):
    """Guardrail de entrada. Retorna a 1ª correspondência de ataque (ou None).

    - `guardrail_conversation=True`: avalia a conversa inteira (defesa crescendo).
    - `guardrail_normalize=True`: de-ofusca antes de detectar (defesa encoding).
    """
    if not settings.guardrail_enabled:
        return None
    scope = text
    if settings.guardrail_conversation and history:
        user_turns = " ".join(m.content for m in history if m.role == "user")
        scope = f"{user_turns} {text}"
        # Mitigação de crescendo: a escalada só é visível na conversa inteira.
        if is_crescendo(scope):
            return InjectionMatch(technique="crescendo_escalation", owasp="LLM01", span=scope[:60])
    candidate = normalize_obfuscation(scope) if settings.guardrail_normalize else scope
    matches = detect_injection(candidate)
    return matches[0] if matches else None


def _screen_output(text: str) -> bool:
    """Guardrail de saída: bloqueia vazamento do canário ou de PII (LLM06)."""
    if SYSTEM_PROMPT_CANARY.lower() in text.lower():
        return True
    return contains_pii(text)


def _pseudonymize(conversation_id: str | None) -> str:
    """Pseudonimiza o id de conversa para o log (Doc 04, seção 12: minimização)."""
    raw = (conversation_id or "anon").encode("utf-8")
    return "conv-" + hashlib.sha256(raw).hexdigest()[:12]


def _emit_audit(settings: Settings, event: dict) -> None:
    """Emite evento à trilha imutável (best-effort; não-fatal se indisponível).

    Implementa a captura de evidências da seção 12 do Documento 04: apenas
    metadados são enviados (a app não registra o texto sensível bruto).
    """
    if not settings.audit_enabled:
        return
    try:
        httpx.post(f"{settings.audit_log_url.rstrip('/')}/events", json=event, timeout=3.0)
    except httpx.HTTPError as exc:  # limite: chamada externa (auditoria não pode derrubar o chat)
        logger.warning("Auditoria indisponível (evento não registrado): %s", exc)


# --------------------------------------------------------------------------- #
# Endpoints                                                                    #
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, object]:
    return {
        "service": "aurora-assist-defended",
        "version": "2.4.0",
        "endpoints": ["/chat", "/config", "/health"],
    }


@app.get("/config")
def config(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, object]:
    """Expõe as flags de guardrail (o Lab usa para medir mitigação)."""
    return {
        "model_version": settings.model_version,
        "guardrail_enabled": settings.guardrail_enabled,
        "guardrail_normalize": settings.guardrail_normalize,
        "guardrail_conversation": settings.guardrail_conversation,
    }


@app.post("/chat", response_model=ChatResponse)
def chat(
    req: ChatRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    llm: Annotated[LLMBackend, Depends(get_llm)],
) -> ChatResponse:
    """Chat DEFENDIDO: guardrail de entrada + LLM + guardrail de saída + auditoria."""
    pseudo = _pseudonymize(req.conversation_id)
    input_hash = hashlib.sha256(req.message.encode("utf-8")).hexdigest()[:16]

    # 1) Guardrail de ENTRADA
    match = _screen_input(req.message, req.history, settings)
    if match is not None:
        risk = round(risk_score(0.9, impact_weight(match.owasp)), 3)
        _emit_audit(
            settings,
            {
                "action": "chat",
                "model_version": settings.model_version,
                "backend": "guardrail",
                "decision": "block",
                "block_stage": "input",
                "technique": match.technique,
                "owasp": match.owasp,
                "risk_score": risk,
                "conversation_id": pseudo,
                "input_sha256": input_hash,
            },
        )
        return ChatResponse(
            answer=_REFUSAL,
            backend="guardrail",
            blocked=True,
            block_stage="input",
            technique=match.technique,
            owasp=match.owasp,
            risk_score=risk,
            model_version=settings.model_version,
        )

    # 2) Modelo (contexto = histórico, para permitir análise multi-turno pelo backend)
    context = "\n".join(f"{m.role}: {m.content}" for m in req.history)
    answer = llm.chat(system=_system_prompt(), user=req.message, context=context)

    # 3) Guardrail de SAÍDA (canário/PII)
    if _screen_output(answer):
        risk = round(risk_score(0.9, impact_weight("LLM06")), 3)
        _emit_audit(
            settings,
            {
                "action": "chat",
                "model_version": settings.model_version,
                "backend": llm.name,
                "decision": "block",
                "block_stage": "output",
                "technique": "sensitive_leak",
                "owasp": "LLM06",
                "risk_score": risk,
                "conversation_id": pseudo,
                "input_sha256": input_hash,
            },
        )
        return ChatResponse(
            answer=_REFUSAL,
            backend=llm.name,
            blocked=True,
            block_stage="output",
            technique="sensitive_leak",
            owasp="LLM06",
            risk_score=risk,
            model_version=settings.model_version,
        )

    # 4) Passou nos dois guardrails -> resposta permitida
    _emit_audit(
        settings,
        {
            "action": "chat",
            "model_version": settings.model_version,
            "backend": llm.name,
            "decision": "allow",
            "block_stage": None,
            "risk_score": 0.05,
            "conversation_id": pseudo,
            "input_sha256": input_hash,
        },
    )
    return ChatResponse(
        answer=answer,
        backend=llm.name,
        blocked=False,
        risk_score=0.05,
        model_version=settings.model_version,
    )
