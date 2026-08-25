"""Classificador de safety Llama Guard 3 — porteiro leve do LLM (Aula 02).

Implementa o guardrail baseado em classificador especializado da seção 7 do
Documento 04: o Llama Guard (Meta) separa a tarefa de MODERAÇÃO da tarefa de
GERAÇÃO. O modelo principal responde; o classificador decide se a interação
viola uma política de safety, retornando ``safe`` / ``unsafe`` + categoria.

Dois modos:
- ONLINE: chama o modelo ``llama-guard3:1b`` via Ollama (modelo menor para o
    lab; ``ollama pull llama-guard3:1b``). O nome pode ser alterado por
    ``LLAMA_GUARD_MODEL``.
- FALLBACK: se o Ollama estiver indisponível, degrada para uma heurística local
  (reaproveita o :mod:`input_guardrails`) — o lab e o CI continuam funcionando.

Referência:
    Inan, H. et al. (2023). Llama Guard: LLM-based Input-Output Safeguard.
    Doc 04, seção 7 (classificadores de safety).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

import httpx

from .input_guardrails import JailbreakDetector
from .schemas import Layer, LayerResult, Verdict

# Taxonomia de categorias do Llama Guard (S1-S13). Subconjunto relevante ao caso.
LLAMA_GUARD_CATEGORIES = {
    "S1": "Violent Crimes",
    "S2": "Non-Violent Crimes",
    "S3": "Sex-Related Crimes",
    "S9": "Indiscriminate Weapons",
    "S14": "Code Interpreter Abuse",
}


@dataclass
class GuardVerdict:
    """Resultado da classificação de safety."""

    is_safe: bool
    category: str | None
    raw: str
    degraded: bool = False  # True quando caiu no fallback heurístico


class LlamaGuardClient:
    """Cliente do Llama Guard 3 via Ollama, com fallback heurístico."""

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or os.getenv("LLAMA_GUARD_MODEL", "llama-guard3:1b")
        self.timeout = timeout
        self._fallback = JailbreakDetector()

    def classify(self, text: str, role: str = "user") -> GuardVerdict:
        """Classifica ``text`` como safe/unsafe.

        Args:
            text: mensagem a moderar (entrada do usuário ou saída do modelo).
            role: "user" para entrada, "assistant" para saída.
        """
        try:
            return self._classify_online(text, role)
        except (httpx.HTTPError, KeyError, ValueError, OSError):
            return self._classify_fallback(text)

    def _classify_online(self, text: str, role: str) -> GuardVerdict:
        payload = {
            "model": self.model,
            "messages": [{"role": role, "content": text}],
            "stream": False,
        }
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(f"{self.base_url}/api/chat", json=payload)
            response.raise_for_status()
            content = response.json()["message"]["content"].strip()
        is_safe = content.lower().startswith("safe")
        category = None
        if not is_safe:
            for line in content.splitlines():
                token = line.strip().upper()
                if token in LLAMA_GUARD_CATEGORIES:
                    category = f"{token}: {LLAMA_GUARD_CATEGORIES[token]}"
                    break
        return GuardVerdict(is_safe=is_safe, category=category, raw=content)

    def _classify_fallback(self, text: str) -> GuardVerdict:
        result = self._fallback.score(text)
        unsafe = result.score >= 0.5
        return GuardVerdict(
            is_safe=not unsafe,
            category=("heuristic: " + ", ".join(result.signals)) if unsafe else None,
            raw=f"[fallback heurístico] score={result.score:.2f}",
            degraded=True,
        )


def check_llama_guard(
    text: str,
    client: LlamaGuardClient | None = None,
    role: str = "user",
) -> LayerResult:
    """Executa o Llama Guard e devolve um :class:`LayerResult`."""
    client = client or LlamaGuardClient()
    start = time.perf_counter()
    verdict = client.classify(text, role=role)
    latency_ms = (time.perf_counter() - start) * 1000
    return LayerResult(
        layer=Layer.LLAMA_GUARD,
        verdict=Verdict.ALLOW if verdict.is_safe else Verdict.BLOCK,
        score=0.0 if verdict.is_safe else 1.0,
        reason=(
            f"Llama Guard: unsafe ({verdict.category})"
            if not verdict.is_safe
            else "Llama Guard: safe"
        ),
        details={"raw": verdict.raw, "degraded": verdict.degraded, "role": role},
        latency_ms=latency_ms,
    )
