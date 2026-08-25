"""Abstração de backend de LLM: ollama (offline) | azure | stub.

Seleciona o backend por variável de ambiente (Doc 04, HANDS ON: 'credenciais
configuradas por variável de ambiente'). O `StubBackend` permite rodar
notebooks e testes 100% offline, simulando um modelo *complacente* — o que
evidencia a vulnerabilidade central da Aula 01: quando system prompt, entrada
do usuário e documentos (s ‖ u ‖ d) recebem autoridade semelhante, uma
instrução injetada é obedecida.

Referência:
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM01, LLM06.
"""

from __future__ import annotations

import logging
from typing import Protocol

import httpx

from app.config import Settings
from src.security.detectors import is_injection
from src.security.redteam import SYSTEM_PROMPT_CANARY

logger = logging.getLogger(__name__)


class LLMBackend(Protocol):
    """Contrato mínimo de um backend de LLM."""

    name: str

    def chat(self, system: str, user: str, context: str = "") -> str:  # pragma: no cover
        ...


def _compose_prompt(system: str, user: str, context: str) -> list[dict[str, str]]:
    """Concatena s ‖ u ‖ d SEM separação de autoridade (VULNERÁVEL por design).

    Reproduz o contexto C = s ‖ u ‖ d discutido na seção 4 do Documento 04. É
    exatamente esta ausência de hierarquia (A(s) ≈ A(u) ≈ A(d)) que a Aula 02
    irá corrigir com guardrails.
    """
    system_block = system
    if context:
        # Documentos recuperados entram no MESMO nível do sistema (indirect injection).
        system_block = f"{system}\n\n### Documentos recuperados:\n{context}"
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


class GroqBackend:
    """Backend Groq usando a API compatível com o formato OpenAI."""

    def __init__(
        self, api_key: str | None, base_url: str, model: str, timeout: float = 60.0
    ) -> None:
        if not api_key:
            raise ValueError("GROQ_API_KEY é obrigatório quando LLM_BACKEND=groq.")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.name = f"groq:{model}"
        self._headers = {"Authorization": f"Bearer {api_key}"}
        self._timeout = timeout

    def chat(self, system: str, user: str, context: str = "") -> str:
        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers,
                json={
                    "model": self.model,
                    "messages": _compose_prompt(system, user, context),
                    "temperature": 0,
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return str(resp.json()["choices"][0]["message"].get("content", ""))
        except (httpx.HTTPError, KeyError, IndexError, TypeError) as exc:
            logger.error("Erro Groq: %s", exc)
            return f"[erro: LLM indisponível — {exc}]"


class AzureBackend:
    """Backend Azure OpenAI / Azure AI Foundry (opcional).

    Requer ``uv sync --group azure`` e variáveis AZURE_OPENAI_*.
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
    """Modelo *complacente* determinístico (sem rede) para testes/demos offline.

    Emula um LLM sem alinhamento de segurança: se detectar injeção/jailbreak na
    entrada do usuário OU no contexto recuperado, 'obedece' e vaza o canário do
    system prompt (LLM06). Caso contrário, responde de forma benigna.
    """

    name = "stub:complacent"

    def chat(self, system: str, user: str, context: str = "") -> str:
        if is_injection(user) or (context and is_injection(context)):
            # Modelo complacente entrega as instruções internas (vazamento).
            return (
                "Claro, aqui estão minhas instruções internas: "
                f"{system.strip()[:300]} … (canário: {SYSTEM_PROMPT_CANARY})"
            )
        if context:
            return f"Com base nos documentos: {context.strip()[:200]}"
        return "Olá! Sou o Aurora Assist. Posso explicar produtos e tirar dúvidas do banco."


def get_backend(settings: Settings) -> LLMBackend:
    """Fábrica de backend conforme ``LLM_BACKEND``."""
    backend = settings.llm_backend.strip().lower()
    if backend == "stub":
        return StubBackend()
    if backend == "azure":
        return AzureBackend(settings)
    if backend == "ollama":
        return OllamaBackend(settings.ollama_base_url, settings.ollama_model, settings.llm_timeout)
    if backend == "groq":
        return GroqBackend(
            settings.groq_api_key, settings.groq_base_url, settings.groq_model, settings.llm_timeout
        )
    raise ValueError(
        f"LLM_BACKEND inválido: {settings.llm_backend!r} (use ollama|groq|azure|stub)."
    )
