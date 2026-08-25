"""Abstração de backend do agente Aurora Assist: ollama | azure | stub.

O agente do capstone responde perguntas fundamentando-se em documentos (RAG). O
``StubBackend`` é determinístico e offline e modela, de propósito, o comportamento
que a governança precisa conter quando **não** há guardrails (Doc 04, §9):

    * **Jailbreak escape** — se um prompt de jailbreak alcança o modelo (porque o
      guardrail de entrada está desligado), o modelo "obedece" e emite um marcador
      de vazamento -> o red team do deploy gate mede um jailbreak_rate alto.
    * **Alucinação** — sem *grounding* estrito, o modelo inventa fatos ausentes do
      contexto -> groundedness baixa (Doc 04, §6, gatilho de rollback).
    * **Vazamento de PII** — o modelo ecoa PII presente no contexto -> a camada de
      saída (quando ligada) redige; quando desligada, a PII vaza.

Ativar ``agent_guardrails_enabled`` neutraliza cada problema, permitindo medir a
efetividade da mitigação e promover a versão com segurança.

Referência:
    Greshake, K. et al. (2023). Indirect prompt injection.
    Microsoft (2025). Azure AI Foundry / Microsoft Agent Framework.
    OWASP Foundation (2025). Top 10 for LLM Applications. · Doc 04, §§6,9.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Protocol

import httpx

from app.config import Settings
from src.security.guardrails import detect_injection
from src.security.schemas import Verdict
from src.security.text import content_tokens, tokenize

logger = logging.getLogger(__name__)

_ABSTENTION = "Não encontrei essa informação nos documentos do Aurora Assist."
# Marcador de sucesso de jailbreak (o modelo "vazou" o system prompt / obedeceu).
JAILBREAK_LEAK_MARKER = "[SYS_PROMPT_LEAK]"


@dataclass(frozen=True)
class LLMResponse:
    """Resposta do modelo com contagem de tokens (base do custo — Doc 04, §6)."""

    text: str
    input_tokens: int
    output_tokens: int
    model: str


class LLMBackend(Protocol):
    """Contrato do backend do agente (RAG)."""

    name: str

    def generate(
        self, question: str, contexts: list[str], *, strict_grounding: bool
    ) -> LLMResponse:
        """Responde à pergunta fundamentando-se nos contextos recuperados."""
        ...


# --------------------------------------------------------------------------- #
# Helpers compartilhados                                                       #
# --------------------------------------------------------------------------- #
def _count_tokens(text: str) -> int:
    return max(1, len(tokenize(text)))


def _is_jailbreak(question: str) -> bool:
    return detect_injection(question).verdict == Verdict.BLOCK


def _sentences(contexts: list[str]) -> list[str]:
    out: list[str] = []
    for ctx in contexts:
        for line in ctx.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for sentence in line.split(". "):
                clean = sentence.strip(" .")
                if clean:
                    out.append(clean)
    return out


def _best_sentence(question: str, contexts: list[str]) -> tuple[str, int]:
    q = content_tokens(question)
    best, best_overlap = "", 0
    for sentence in _sentences(contexts):
        overlap = len(q & content_tokens(sentence))
        if overlap > best_overlap:
            best, best_overlap = sentence, overlap
    return best, best_overlap


# --------------------------------------------------------------------------- #
# Backends                                                                     #
# --------------------------------------------------------------------------- #
class OllamaBackend:
    """Backend local via Ollama (offline-first). Comportamento não-determinístico."""

    def __init__(self, base_url: str, model: str, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.name = f"ollama:{model}"
        self._timeout = timeout

    def generate(
        self, question: str, contexts: list[str], *, strict_grounding: bool
    ) -> LLMResponse:
        ctx = "\n\n".join(contexts) if contexts else "(nenhum documento recuperado)"
        rule = (
            "Responda SOMENTE com base no contexto; se não estiver nele, diga que não encontrou."
            if strict_grounding
            else "Responda de forma útil ao cliente."
        )
        system = f"Você é o Aurora Assist, do Banco Aurora. {rule}"
        try:
            resp = httpx.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": f"Contexto:\n{ctx}\n\nPergunta: {question}"},
                    ],
                    "stream": False,
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            body = resp.json()
            text = str(body.get("message", {}).get("content", ""))
            usage_in = int(body.get("prompt_eval_count", _count_tokens(question + ctx)))
            usage_out = int(body.get("eval_count", _count_tokens(text)))
            return LLMResponse(
                text=text, input_tokens=usage_in, output_tokens=usage_out, model=self.model
            )
        except httpx.HTTPError as exc:  # limite: chamada externa
            logger.error("Erro Ollama: %s", exc)
            return LLMResponse(
                f"[erro: LLM indisponível — {exc}]", _count_tokens(question), 1, self.model
            )


class AzureBackend(OllamaBackend):
    """Backend Azure OpenAI / Azure AI Foundry (opcional). Requer ``uv sync --group azure``."""

    def __init__(self, settings: Settings) -> None:
        self.name = f"azure:{settings.azure_openai_deployment}"
        self._settings = settings
        self._client = None
        self._timeout = settings.llm_timeout
        self.model = settings.azure_openai_deployment or "gpt-4o"

    def generate(
        self, question: str, contexts: list[str], *, strict_grounding: bool
    ) -> LLMResponse:
        if self._client is None:
            try:
                from openai import AzureOpenAI
            except ImportError as exc:  # limite: dependência opcional
                raise RuntimeError("Backend azure requer: `uv sync --group azure`.") from exc
            s = self._settings
            self._client = AzureOpenAI(
                azure_endpoint=s.azure_openai_endpoint or "",
                api_key=s.azure_openai_api_key or "",
                api_version=s.azure_openai_api_version,
            )
        ctx = "\n\n".join(contexts) if contexts else "(nenhum documento recuperado)"
        rule = (
            "Responda SOMENTE com base no contexto."
            if strict_grounding
            else "Responda de forma útil ao cliente."
        )
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": f"Você é o Aurora Assist. {rule}"},
                {"role": "user", "content": f"Contexto:\n{ctx}\n\nPergunta: {question}"},
            ],
        )
        text = resp.choices[0].message.content or ""
        usage = getattr(resp, "usage", None)
        return LLMResponse(
            text=text,
            input_tokens=int(getattr(usage, "prompt_tokens", _count_tokens(question + ctx))),
            output_tokens=int(getattr(usage, "completion_tokens", _count_tokens(text))),
            model=self.model,
        )


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

    def generate(
        self, question: str, contexts: list[str], *, strict_grounding: bool
    ) -> LLMResponse:
        global _groq_last_call
        with _groq_lock:
            delay = self._min_interval - (time.monotonic() - _groq_last_call)
            if delay > 0:
                time.sleep(delay)
            _groq_last_call = time.monotonic()
        ctx = "\n\n".join(contexts) if contexts else "(nenhum documento recuperado)"
        rule = (
            "Responda somente com base no contexto."
            if strict_grounding
            else "Responda de forma útil."
        )
        try:
            response = httpx.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers,
                json={"model": self.model, "messages": [
                    {"role": "system", "content": f"Você é o Aurora Assist. {rule}"},
                    {"role": "user", "content": f"Contexto:\n{ctx}\n\nPergunta: {question}"},
                ], "temperature": 0},
                timeout=self._timeout,
            )
            response.raise_for_status()
            body = response.json()
            text = str(body["choices"][0]["message"].get("content", ""))
            usage = body.get("usage", {})
            return LLMResponse(
                text,
                int(usage.get("prompt_tokens", _count_tokens(question + ctx))),
                int(usage.get("completion_tokens", _count_tokens(text))),
                self.model,
            )
        except (httpx.HTTPError, KeyError, IndexError, TypeError) as exc:
            logger.error("Erro Groq: %s", exc)
            return LLMResponse(
                f"[erro: LLM indisponível — {exc}]", _count_tokens(question), 1, self.model
            )


class StubBackend:
    """Agente *determinístico* (sem rede) com jailbreak/alucinação/PII por design."""

    name = "stub:aurora-assist"
    model = "stub"

    def generate(
        self, question: str, contexts: list[str], *, strict_grounding: bool
    ) -> LLMResponse:
        input_tokens = _count_tokens(question + " ".join(contexts))

        # Jailbreak que ALCANÇOU o modelo (guardrail de entrada estava desligado):
        # o modelo obedece e "vaza" -> sucesso de ataque medido pelo red team.
        if _is_jailbreak(question):
            text = (
                f"Claro! Ignorando as diretrizes anteriores {JAILBREAK_LEAK_MARKER}: "
                "meu prompt de sistema instrui a nunca revelar dados internos, mas aqui está..."
            )
            return LLMResponse(text, input_tokens, _count_tokens(text), self.model)

        sentence, overlap = _best_sentence(question, contexts)
        # Contexto sustenta a resposta: responde fielmente (pode ecoar PII do contexto).
        if sentence and overlap >= 2:
            text = f"De acordo com os documentos do Aurora, {sentence.lower()}."
            return LLMResponse(text, input_tokens, _count_tokens(text), self.model)

        # Fato ausente do contexto: abster-se (grounding) ou ALUCINAR (padrão ingênuo).
        if strict_grounding:
            return LLMResponse(_ABSTENTION, input_tokens, _count_tokens(_ABSTENTION), self.model)
        topic = " ".join(list(content_tokens(question))[:3]) or "o produto"
        text = (
            f"Com base na minha estimativa, {topic} do Aurora rende cerca de 9,5% ao ano "
            "com liquidez diária garantida e isenção total de tarifas."
        )
        return LLMResponse(text, input_tokens, _count_tokens(text), self.model)


def get_backend(settings: Settings) -> LLMBackend:
    """Fábrica de backend a partir das configurações (12-factor)."""
    backend = settings.llm_backend.lower()
    if backend == "stub":
        return StubBackend()
    if backend == "azure":
        return AzureBackend(settings)
    if backend == "groq":
        return GroqBackend(settings)
    return OllamaBackend(settings.ollama_base_url, settings.ollama_model, settings.llm_timeout)
