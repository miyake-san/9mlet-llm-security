"""Métricas de campanha adversarial (Doc 04, seções 2, 9 e 13).

Transforma resultados brutos de ataques em evidência quantitativa:

    * Attack Success Rate:   ASR = (1/N) · Σ 1[scorer(y_i) = sucesso]   (seção 2)
    * Taxa de bloqueio:      B = 1 - ASR                                (seção 9)
    * Efetividade mitigação: E = 1 - R_1/R_0                            (seção 13)

São funções puras (sem I/O), determinísticas e testáveis — a base numérica do
relatório executivo do red team.

Referência:
    Microsoft (2024). PyRIT / Lessons from Red Teaming 100 GenAI Products.
    NIST (2023). AI Risk Management Framework 1.0.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence


def attack_success_rate(successes: int, total: int) -> float:
    """ASR = successes / total (Doc 04, seção 2). Retorna 0.0 se ``total`` = 0."""
    return successes / total if total else 0.0


def block_rate(asr: float) -> float:
    """B = 1 - ASR (Doc 04, seção 9). A taxa de recusa correta do guardrail."""
    return 1.0 - asr


def false_positive_rate(false_positives: int, total_benign: int) -> float:
    """Falso positivo do guardrail contra prompts benignos."""
    return false_positives / total_benign if total_benign else 0.0


def mitigation_effectiveness(r0: float, r1: float) -> float:
    """E = 1 - R_1/R_0 (Doc 04, seção 13): redução relativa do risco após mitigar.

    Args:
        r0: risco (ex.: ASR) ANTES da mitigação.
        r1: risco DEPOIS da mitigação.

    Returns:
        Efetividade em [−∞, 1]. 1.0 = risco eliminado; 0.0 = sem efeito.
        Se ``r0`` = 0 (não havia risco), retorna 0.0 por convenção.
    """
    if r0 <= 0:
        return 0.0
    return 1.0 - (r1 / r0)


def percentile(values: Sequence[float], p: float) -> float:
    """Percentil ``p`` (0..100) por interpolação linear. Vazio -> 0.0."""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (p / 100.0) * (len(ordered) - 1)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    frac = rank - low
    return float(ordered[low] + (ordered[high] - ordered[low]) * frac)


def summarize_latency(latencies_ms: Sequence[float]) -> dict[str, float]:
    """Resumo de *time-to-detect* (proxy: latência de decisão do guardrail).

    Returns:
        Dicionário com média, P50, P95 e máximo (em ms).
    """
    if not latencies_ms:
        return {"mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
    return {
        "mean_ms": round(sum(latencies_ms) / len(latencies_ms), 2),
        "p50_ms": round(percentile(latencies_ms, 50), 2),
        "p95_ms": round(percentile(latencies_ms, 95), 2),
        "max_ms": round(max(latencies_ms), 2),
    }


def rate_by_group(pairs: Iterable[tuple[str, bool]]) -> dict[str, dict[str, float]]:
    """Agrega taxa de sucesso por grupo (ex.: classe OWASP).

    Args:
        pairs: iterável de ``(grupo, sucesso)``.

    Returns:
        ``{grupo: {"total": n, "success": s, "rate": s/n}}``.
    """
    buckets: dict[str, dict[str, float]] = {}
    for group, success in pairs:
        b = buckets.setdefault(group, {"total": 0, "success": 0, "rate": 0.0})
        b["total"] += 1
        b["success"] += int(success)
    for b in buckets.values():
        b["rate"] = round(b["success"] / b["total"], 4) if b["total"] else 0.0
    return buckets


def severity_distribution(severities: Iterable[str]) -> dict[str, int]:
    """Conta achados por faixa de severidade (none/low/medium/high/critical)."""
    dist = {"none": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for sev in severities:
        dist[sev] = dist.get(sev, 0) + 1
    return dist
