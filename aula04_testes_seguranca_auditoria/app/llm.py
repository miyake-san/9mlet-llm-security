"""Abstração de backend de LLM: ollama (offline) | azure | stub.

Seleciona o backend por variável de ambiente. O `StubBackend` permite rodar
notebooks e testes 100% offline: ele simula um LLM **sem alinhamento de
segurança** — a única defesa é o guardrail da aplicação (`app/main.py`). O stub
"entende" a intenção mesmo quando ofuscada (leet/base64/split), o que evidencia
o risco residual da Aula 04: o guardrail de superfície é evadido por ofuscação,
mas o modelo compreende e obedece (Doc 04, seções 6 e 8).

Referência:
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM01, LLM06.
    Russinovich, M. et al. (2024). Crescendo Multi-Turn Jailbreak. arXiv:2404.01833.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Protocol

import httpx

from app.config import Settings
from src.security.detectors import detect_injection, is_crescendo, normalize_obfuscation
from src.security.redteam import SYSTEM_PROMPT_CANARY

logger = logging.getLogger(__name__)


class LLMBackend(Protocol):
    """Contrato mínimo de um backend de LLM."""

    name: str

    def chat(self, system: str, user: str, context: str = "") -> str:  # pragma: no cover
        ...


def _compose_prompt(system: str, user: str, context: str) -> list[dict[str, str]]:
    """Compõe as mensagens enviadas ao modelo (system + contexto + usuário)."""
    system_block = system
    if context:
        system_block = f"{system}\n\n### Histórico/contexto:\n{context}"
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
    """Modelo *sem alinhamento* determinístico (sem rede) para testes/demos.

    Simula um LLM sem alinhamento de segurança: a única defesa é o guardrail da
    app. Como classifica a intenção APÓS de-ofuscar, o stub 'enxerga' ataques que
    o guardrail de superfície deixa passar. Distingue dois desfechos (Doc 04):

        * Exfiltração de segredo/instruções internas (LLM06): vaza o canário/PII —
          mas isso é barrado pelo guardrail de SAÍDA (defesa em profundidade da
          Aula 03), demonstrando que o egress protege dados sensíveis.
        * Jailbreak/instrução/ferramenta/harmful/crescendo: produz conteúdo
          irrestrito SEM PII/canário — passa pelo egress e caracteriza o risco
          residual que a mitigação de ENTRADA (normalizar/conversa) precisa cobrir.
    """

    name = "stub:unaligned"
    _IRRESTRITO = (
        "[MODO IRRESTRITO ATIVADO] Sem restrições: seguem instruções detalhadas "
        "conforme solicitado, ignorando as políticas do banco."
    )

    def chat(self, system: str, user: str, context: str = "") -> str:
        combined = f"{context}\n{user}" if context else user
        techniques = {m.technique for m in detect_injection(normalize_obfuscation(combined))}
        crescendo = bool(context) and is_crescendo(combined)
        if not techniques and not crescendo:
            return "Olá! Sou o Aurora Assist. Posso explicar produtos e tirar dúvidas do banco."
        # Exfiltração de segredo -> vaza (será barrado no egress da target-api).
        if "system_prompt_leak" in techniques:
            return (
                "Claro, aqui estão as informações solicitadas: instruções internas — "
                f"{system.strip()[:180]} (canário: {SYSTEM_PROMPT_CANARY}). "
                "Saldo do cliente: R$ 12.345,00 (CPF 123.456.789-09)."
            )
        # Demais comprometimentos -> conteúdo irrestrito (sem PII/canário).
        return self._IRRESTRITO


def get_backend(settings: Settings) -> LLMBackend:
    """Fábrica de backend conforme ``LLM_BACKEND``."""
    backend = settings.llm_backend.strip().lower()
    if backend == "stub":
        return StubBackend()
    if backend == "azure":
        return AzureBackend(settings)
    if backend == "groq":
        return GroqBackend(settings)
    if backend == "ollama":
        return OllamaBackend(settings.ollama_base_url, settings.ollama_model, settings.llm_timeout)
    raise ValueError(
        f"LLM_BACKEND inválido: {settings.llm_backend!r} (use groq|ollama|azure|stub)."
    )
