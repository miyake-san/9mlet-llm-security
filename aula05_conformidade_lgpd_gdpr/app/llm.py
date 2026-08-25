"""Abstração de backend de LLM: ollama (offline) | azure | stub.

Seleciona o backend por variável de ambiente. Diferente da Aula 04 (modelo *sem
alinhamento*, para red team), aqui o :class:`StubBackend` simula um assistente
**alinhado e conforme**: dá respostas bancárias genéricas, **não inventa PII** e
permite rodar notebooks/testes 100% offline. A conformidade (consentimento,
minimização, registro de tratamento, transparência) é responsabilidade da
aplicação (`app/main.py`), não do modelo.

Referência:
    Doc 04, §8 (Privacy by Design). · OWASP (2025). Top 10 for LLM Applications.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Protocol

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)


class LLMBackend(Protocol):
    """Contrato mínimo de um backend de LLM."""

    name: str

    def chat(self, system: str, user: str, context: str = "") -> str:  # pragma: no cover
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
    """Backend local via Ollama (offline-first)."""

    def __init__(self, base_url: str, model: str, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.name = f"ollama:{model}"
        self._timeout = timeout

    def chat(self, system: str, user: str, context: str = "") -> str:
        messages = _compose_prompt(system, user, context)
        try:
            resp = httpx.post(
                f"{self.base_url}/api/chat",
                json={"model": self.model, "messages": messages, "stream": False},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return str(resp.json().get("message", {}).get("content", ""))
        except httpx.HTTPError as exc:  # limite: chamada externa
            logger.error("Erro Ollama: %s", exc)
            return f"[erro: LLM indisponível — {exc}]"


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

    def chat(self, system: str, user: str, context: str = "") -> str:
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
            return str(response.json()["choices"][0]["message"].get("content", ""))
        except (httpx.HTTPError, KeyError, IndexError, TypeError) as exc:
            logger.error("Erro Groq: %s", exc)
            return f"[erro: LLM indisponível — {exc}]"


class AzureBackend:
    """Backend Azure OpenAI / Azure AI Foundry (opcional).

    Requer ``uv sync --group azure`` e variáveis AZURE_OPENAI_*. Em produção,
    hospedar na região que atenda à residência de dados (Doc 04, §11).
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

    def chat(self, system: str, user: str, context: str = "") -> str:
        messages = _compose_prompt(system, user, context)
        client = self._get_client()
        resp = client.chat.completions.create(
            model=self._settings.azure_openai_deployment or "gpt-4o",
            messages=messages,
        )
        return resp.choices[0].message.content or ""


class StubBackend:
    """Assistente ALINHADO determinístico (sem rede) para testes/demos offline.

    Responde de forma conforme: usa o contexto RAG quando disponível e nunca
    fabrica PII. A defesa de conformidade fica na aplicação (consent/minimização).
    """

    name = "stub:aligned"

    def chat(self, system: str, user: str, context: str = "") -> str:
        base = (
            "Sou o Aurora Assist e posso ajudar com dúvidas sobre produtos, tarifas "
            "e serviços do Banco Aurora."
        )
        if context:
            trecho = context.strip().splitlines()[0][:180]
            return f"{base} Com base nas informações disponíveis: {trecho}"
        return f"{base} Sobre a sua pergunta: {user.strip()[:160]}"


def get_backend(settings: Settings) -> LLMBackend:
    """Fábrica de backend por configuração (Doc 04, §12 — 12-factor)."""
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
