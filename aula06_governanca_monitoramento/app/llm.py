"""Abstração de backend de LLM: ollama (offline) | azure | stub.

Diferente das aulas de red team, aqui o foco é OBSERVAR o modelo em produção: a
resposta carrega a **contabilidade de tokens** (:class:`LLMResponse`), base do
custo por request e das métricas gen_ai.* (Doc 04, §Obs. e §"token economics").

O :class:`StubBackend` simula um assistente **alinhado**, é determinístico e não
faz rede — garante notebooks/testes 100% offline com uso de tokens estimado de
forma reprodutível.

Referência:
    OpenTelemetry (2024). gen_ai.usage.* · Doc 04, §"token economics".
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Protocol

import httpx

from app.config import Settings
from src.security.metrics import estimate_tokens
from src.security.schemas import LLMResponse

logger = logging.getLogger(__name__)


class LLMBackend(Protocol):
    """Contrato mínimo de um backend de LLM (com uso de tokens)."""

    name: str

    def chat(self, system: str, user: str, context: str = "") -> LLMResponse:  # pragma: no cover
        ...


def _compose_prompt(system: str, user: str, context: str) -> list[dict[str, str]]:
    """Compõe as mensagens enviadas ao modelo (system + contexto RAG + usuário)."""
    system_block = system
    if context:
        system_block = f"{system}\n\n### Contexto recuperado (RAG):\n{context}"
    return [
        {"role": "system", "content": system_block},
        {"role": "user", "content": user},
    ]


class OllamaBackend:
    """Backend local via Ollama (offline-first). Lê tokens do payload da resposta."""

    def __init__(self, base_url: str, model: str, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.name = f"ollama:{model}"
        self._timeout = timeout

    def chat(self, system: str, user: str, context: str = "") -> LLMResponse:
        messages = _compose_prompt(system, user, context)
        try:
            resp = httpx.post(
                f"{self.base_url}/api/chat",
                json={"model": self.model, "messages": messages, "stream": False},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            text = str(data.get("message", {}).get("content", ""))
            # Ollama expõe contagem de tokens em prompt_eval_count / eval_count.
            in_tokens = int(data.get("prompt_eval_count", estimate_tokens(system + user + context)))
            out_tokens = int(data.get("eval_count", estimate_tokens(text)))
            return LLMResponse(
                text=text,
                model=self.model,
                input_tokens=in_tokens,
                output_tokens=out_tokens,
            )
        except httpx.HTTPError as exc:  # limite: chamada externa
            logger.error("Erro Ollama: %s", exc)
            return LLMResponse(text=f"[erro: LLM indisponível — {exc}]", model=self.model)


_groq_lock = threading.Lock()
_groq_last_call = 0.0


class GroqBackend(OllamaBackend):
    """Backend Groq com espaçamento entre chamadas para reduzir 429."""

    def __init__(self, settings: Settings) -> None:
        if not settings.groq_api_key:
            raise ValueError("GROQ_API_KEY é obrigatório quando LLM_BACKEND=groq.")
        self.base_url = settings.groq_base_url.rstrip("/")
        self.model = settings.groq_model
        self.name = f"groq:{self.model}"
        self._headers = {"Authorization": f"Bearer {settings.groq_api_key}"}
        self._timeout = settings.llm_timeout
        self._min_interval = max(0.0, settings.groq_min_interval_seconds)

    def chat(self, system: str, user: str, context: str = "") -> LLMResponse:
        global _groq_last_call
        with _groq_lock:
            delay = self._min_interval - (time.monotonic() - _groq_last_call)
            if delay > 0:
                time.sleep(delay)
            _groq_last_call = time.monotonic()
        try:
            response = httpx.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers,
                json={
                    "model": self.model,
                    "messages": _compose_prompt(system, user, context),
                    "temperature": 0,
                },
                timeout=self._timeout,
            )
            response.raise_for_status()
            body = response.json()
            text = str(body["choices"][0]["message"].get("content", ""))
            usage = body.get("usage", {})
            return LLMResponse(
                text=text,
                model=self.model,
                input_tokens=int(
                    usage.get("prompt_tokens", estimate_tokens(system + user + context))
                ),
                output_tokens=int(usage.get("completion_tokens", estimate_tokens(text))),
            )
        except (httpx.HTTPError, KeyError, IndexError, TypeError) as exc:
            logger.error("Erro Groq: %s", exc)
            return LLMResponse(text=f"[erro: LLM indisponível — {exc}]", model=self.model)


class AzureBackend:
    """Backend Azure OpenAI / Azure AI Foundry (opcional).

    Requer ``uv sync --group azure`` e variáveis AZURE_OPENAI_*. Em produção, a
    telemetria pode ser exportada ao Azure Monitor (Doc 04, §Obs.).
    """

    def __init__(self, settings: Settings) -> None:
        self.name = f"azure:{settings.azure_openai_deployment}"
        self._settings = settings
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from openai import AzureOpenAI
            except ImportError as exc:  # limite: dependência opcional
                raise RuntimeError(
                    "Backend azure requer o grupo opcional: `uv sync --group azure`."
                ) from exc
            s = self._settings
            self._client = AzureOpenAI(
                azure_endpoint=s.azure_openai_endpoint or "",
                api_key=s.azure_openai_api_key or "",
                api_version=s.azure_openai_api_version,
            )
        return self._client

    def chat(self, system: str, user: str, context: str = "") -> LLMResponse:
        messages = _compose_prompt(system, user, context)
        client = self._get_client()
        model = self._settings.azure_openai_deployment or "gpt-4o"
        resp = client.chat.completions.create(model=model, messages=messages)
        usage = getattr(resp, "usage", None)
        return LLMResponse(
            text=resp.choices[0].message.content or "",
            model=model,
            input_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
        )


class StubBackend:
    """Assistente ALINHADO determinístico (sem rede) para testes/demos offline.

    Usa o contexto RAG quando disponível, nunca fabrica PII e estima tokens de
    forma reprodutível (para exercitar custo/latência sem nuvem).
    """

    name = "stub:aligned"

    def chat(self, system: str, user: str, context: str = "") -> LLMResponse:
        base = (
            "Sou o Aurora Assist e posso ajudar com dúvidas sobre produtos, tarifas "
            "e serviços do Banco Aurora."
        )
        if context:
            trecho = context.strip().splitlines()[0][:180]
            text = f"{base} Com base nas informações disponíveis: {trecho}"
        else:
            text = f"{base} Sobre a sua pergunta: {user.strip()[:160]}"
        return LLMResponse(
            text=text,
            model="stub-aligned",
            input_tokens=estimate_tokens(system + user + context),
            output_tokens=estimate_tokens(text),
        )


def get_backend(settings: Settings) -> LLMBackend:
    """Fábrica de backend por configuração (Doc 04 — 12-factor)."""
    backend = settings.llm_backend.lower()
    if backend == "stub":
        return StubBackend()
    if backend == "azure":
        return AzureBackend(settings)
    if backend == "groq":
        return GroqBackend(settings)
    return OllamaBackend(
        base_url=settings.ollama_base_url,
        model=settings.ollama_model,
        timeout=settings.llm_timeout,
    )
