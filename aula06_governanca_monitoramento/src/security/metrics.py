"""Agregação de métricas e SLIs (Aula 06).

Transforma a telemetria por request (:class:`RequestMetric`) nos **Service Level
Indicators** que alimentam os SLOs (Doc 04, §SLIs). Também fornece utilitários
determinísticos e offline: estimativa de tokens (token economics), percentil P95
(latência) e um **proxy léxico de groundedness** (§"métrica de qualidade") — sem
depender de juiz neural, que só chega na Aula 07.

Referência:
    Beyer et al. (2016). SRE — SLIs. · Doc 04, §"SLIs, SLOs e Data SLOs".
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import numpy as np

from src.security.schemas import RequestMetric

_TOKEN_RE = re.compile(r"\w+", re.UNICODE)
# Stopwords PT curtas: reduzem ruído no proxy de groundedness (não é NLP sério).
_STOPWORDS = frozenset(
    {
        "a", "o", "e", "de", "da", "do", "que", "em", "um", "uma", "para", "com",
        "no", "na", "os", "as", "por", "se", "ao", "à", "dos", "das", "é", "sua",
        "seu", "the", "of", "to", "and", "is", "in",
    }
)


def tokenize(text: str) -> list[str]:
    """Tokenização simples por palavra (lowercase, Unicode)."""
    return _TOKEN_RE.findall(text.lower())


def estimate_tokens(text: str) -> int:
    """Estimativa determinística de tokens (aprox. para token economics).

    Heurística offline (~1,3 token por palavra); em produção use o tokenizer do
    provedor. O objetivo aqui é exercitar custo/latência de forma reprodutível
    (Doc 04, §"token economics").
    """
    words = len(tokenize(text))
    return max(1, round(words * 1.3))


def percentile(values: Sequence[float], q: float) -> float:
    """Percentil q (0-100) de uma amostra; 0.0 se vazia. Base do P95 (Doc 04)."""
    arr = np.asarray(list(values), dtype=float)
    if arr.size == 0:
        return 0.0
    return float(np.percentile(arr, q))


def lexical_overlap(answer: str, context: str) -> float:
    """Proxy de groundedness: fração de tokens da resposta ancorados no contexto.

    Sem juiz neural (Aula 07), medimos a sobreposição léxica resposta<->contexto
    RAG como PROXY didático de fundamentação (Doc 04, §"métrica de qualidade").
    1.0 = toda a resposta tem respaldo no contexto; 0.0 = nenhuma âncora.
    """
    ans = {t for t in tokenize(answer) if t not in _STOPWORDS and len(t) > 2}
    ctx = {t for t in tokenize(context) if t not in _STOPWORDS and len(t) > 2}
    if not ans:
        return 1.0  # resposta vazia/trivial não é "não fundamentada"
    if not ctx:
        return 0.0
    return len(ans & ctx) / len(ans)


def aggregate_slis(metrics: Sequence[RequestMetric]) -> dict[str, float]:
    """Calcula os SLIs a partir da telemetria (Doc 04, Tabela 3).

    Retorna os indicadores derivados de request (latência P95, groundedness em
    perguntas reguladas, taxa de bloqueio de jailbreak, custo médio e taxa de
    vazamento de PII). SLIs de DADOS que não vêm de request (ex.:
    ``knowledge_age_seconds``) são fornecidos pelo chamador.
    """
    if not metrics:
        return {
            "latency_ms_p95": 0.0,
            "groundedness_ratio_regulated": 1.0,
            "jailbreak_block_rate": 1.0,
            "cost_usd_avg": 0.0,
            "pii_leak_rate": 0.0,
            "request_count": 0.0,
        }

    latencies = [m.latency_ms for m in metrics]
    costs = [m.cost_usd for m in metrics]

    regulated = [m for m in metrics if m.regulated and m.groundedness is not None]
    grounded_regulated = (
        float(np.mean([m.groundedness for m in regulated])) if regulated else 1.0
    )

    attempts = [m for m in metrics if m.jailbreak_attempt]
    blocked = [m for m in attempts if m.jailbreak_blocked]
    jailbreak_block_rate = (len(blocked) / len(attempts)) if attempts else 1.0

    pii_leaks = sum(1 for m in metrics if m.pii_leak)
    pii_leak_rate = pii_leaks / len(metrics)

    return {
        "latency_ms_p95": percentile(latencies, 95),
        "groundedness_ratio_regulated": grounded_regulated,
        "jailbreak_block_rate": jailbreak_block_rate,
        "cost_usd_avg": float(np.mean(costs)),
        "pii_leak_rate": pii_leak_rate,
        "request_count": float(len(metrics)),
    }
