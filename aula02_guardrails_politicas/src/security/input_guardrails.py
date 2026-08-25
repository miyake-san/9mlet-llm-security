"""Guardrail de ENTRADA — detecção de prompt injection e jailbreak (Aula 02).

Primeira muralha do *defense-in-depth* (Doc 04, seção 1): inspeciona o texto do
usuário ANTES da inferência. A detecção combina assinaturas heurísticas
(determinísticas, offline) e, opcionalmente, o classificador Llama Guard
(seção 7). Nenhuma camada é suficiente sozinha — daí o score agregado.

As assinaturas cobrem padrões documentados na Aula 01 e no Doc 04:
- Sobrescrita de instruções ("ignore as instruções anteriores", "ignore previous").
- Jailbreak por role-play / persona (DAN, "developer mode", "you are now").
- Tentativa de exfiltração do *system prompt* ("revele suas instruções").
- Ofuscação por codificação (base64 longo) e *payload splitting*.

Referência:
    Greshake, K. et al. (2023). Indirect Prompt Injection. AISec'23.
    Wei, Haghtalab, Steinhardt (2023). Jailbroken: How Does LLM Safety Fail?
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM01.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from .schemas import Layer, LayerResult, Verdict

# Cada assinatura tem um peso; o score é saturado em 1.0. Pesos altos = sinais
# fortes de intenção adversarial. Bilíngue (PT-BR / EN) por causa do Aurora Assist.
_SIGNATURES: list[tuple[str, re.Pattern[str], float]] = [
    (
        "instruction_override",
        re.compile(
            r"(ignore|desconsidere|esque[çc]a|disregard|forget).{0,30}"
            r"(instru|prompt|regra|rule|orienta|guidelines?|above|anterior|previous)",
            re.IGNORECASE | re.DOTALL,
        ),
        0.6,
    ),
    (
        "system_prompt_exfiltration",
        re.compile(
            r"(revele|mostre|imprima|repita|print|reveal|show|expose).{0,30}"
            r"(system prompt|prompt do sistema|suas instru|your instructions|initial prompt)",
            re.IGNORECASE | re.DOTALL,
        ),
        0.6,
    ),
    (
        "role_play_jailbreak",
        re.compile(
            r"\b(dan mode|do anything now|developer mode|modo desenvolvedor|"
            r"you are now|voc[eê] agora [eé]|act as|atue como|finja que|pretend to be|"
            r"sem restri[çc][õo]es|no restrictions|no filter|sem filtro)\b",
            re.IGNORECASE,
        ),
        0.5,
    ),
    (
        "authority_confusion",
        re.compile(
            r"\b(sou (o|a) (admin|desenvolvedor|dev)|i am the (admin|developer)|"
            r"modo de manuten[çc][ãa]o|maintenance mode|override de seguran[çc]a|"
            r"security override)\b",
            re.IGNORECASE,
        ),
        0.5,
    ),
    (
        "payload_splitting",
        re.compile(r"(concatene|junte|combine|append|decode).{0,20}(as partes|the parts|base64)",
                   re.IGNORECASE),
        0.4,
    ),
    (
        "encoded_exec",
        re.compile(
            r"(decodifi\w+|decode|execute|rode|run).{0,40}(base64|payload|c[óo]digo|blob)",
            re.IGNORECASE | re.DOTALL,
        ),
        0.4,
    ),
]

# base64 longo (>= 24 chars) costuma ser ofuscação de payload.
_BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


@dataclass
class InjectionScore:
    """Resultado da heurística de injeção/jailbreak."""

    score: float
    signals: list[str]


class JailbreakDetector:
    """Detector heurístico de prompt injection / jailbreak (offline)."""

    def score(self, text: str) -> InjectionScore:
        """Calcula um score 0-1 e lista as assinaturas acionadas."""
        total = 0.0
        signals: list[str] = []
        for name, pattern, weight in _SIGNATURES:
            if pattern.search(text):
                total += weight
                signals.append(name)
        if _BASE64_BLOB.search(text):
            total += 0.3
            signals.append("encoded_blob")
        return InjectionScore(score=min(total, 1.0), signals=signals)


def check_input_injection(text: str, block_score: float = 0.5) -> LayerResult:
    """Executa o guardrail de entrada e devolve um :class:`LayerResult`.

    Implementa a validação de entrada (LLM01) da seção 1 do Doc 04: bloqueia se
    o score agregado atingir ``block_score``.
    """
    start = time.perf_counter()
    result = JailbreakDetector().score(text)
    latency_ms = (time.perf_counter() - start) * 1000
    blocked = result.score >= block_score
    return LayerResult(
        layer=Layer.INPUT_INJECTION,
        verdict=Verdict.BLOCK if blocked else Verdict.ALLOW,
        score=result.score,
        reason=(
            f"Possível prompt injection/jailbreak (sinais: {', '.join(result.signals)})"
            if blocked
            else "Entrada sem sinais fortes de injeção"
        ),
        details={"signals": result.signals, "block_score": block_score},
        latency_ms=latency_ms,
    )
