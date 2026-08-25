"""Observabilidade do agente: custo, spans gen_ai.* e minimização de PII (Aula 06).

Núcleo de domínio (agnóstico de framework) para a §"Observabilidade" do Doc 04,
integrado ao agente do capstone. O **Microsoft Agent Framework** constrói agentes
com observabilidade nativa (Doc 04, §9): aqui, cada invocação do agente emite um
span ``gen_ai.*`` (modelo, tokens, custo, latência, bloqueio, groundedness) que
alimenta os dashboards de qualidade/custo/segurança (Grafana/Langfuse) e os SLOs.

Implementação pura (sem numpy/SDK): mantém o lab *offline-first*. O wiring de
produção (OTLP/Langfuse/Prometheus) é documentado no ``docker-compose.yml``.

Referência:
    OpenTelemetry (2024). Semantic Conventions for Generative AI Systems.
    Langfuse (2024). · Microsoft (2025). Microsoft Agent Framework. · Doc 04, §§6,9.
"""

from __future__ import annotations

import re
import threading
import uuid

from src.security.schemas import GenAISpan

_MASK = "[REDACTED]"
_PII_PATTERNS = (
    re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),  # CPF
    re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),  # CNPJ
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),  # e-mail
    re.compile(r"\(?\d{2}\)?\s?9?\d{4}-?\d{4}\b"),  # telefone
)


def redact_preview(text: str, max_chars: int = 120) -> str:
    """Mascara PII e trunca o texto para virar um *preview* seguro no span.

    A telemetria aplica minimização de dados (Doc 04, §Obs.): só um trecho
    mascarado do prompt é registrado, nunca PII em claro — a observabilidade não
    pode virar nova fonte de risco.
    """
    redacted = text
    for pattern in _PII_PATTERNS:
        redacted = pattern.sub(_MASK, redacted)
    return " ".join(redacted.split())[:max_chars]


class CostModel:
    """Custo por request a partir de tokens de entrada/saída (token economics)."""

    def __init__(self, input_per_1k: float = 0.005, output_per_1k: float = 0.015) -> None:
        self.input_per_1k = input_per_1k
        self.output_per_1k = output_per_1k

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens / 1000.0) * self.input_per_1k + (
            output_tokens / 1000.0
        ) * self.output_per_1k


class InMemoryTraceStore:
    """Coletor de spans gen_ai.* em memória (offline; espelha OpenTelemetry).

    Serve à Figura 3 do Doc 04 (trace de conversa) sem exigir o OTel SDK; guarda
    apenas metadados já mascarados. Usa ``RLock`` (reentrante) por segurança.
    """

    def __init__(self, capacity: int = 1024) -> None:
        self._spans: list[GenAISpan] = []
        self._lock = threading.RLock()
        self._capacity = capacity

    def new_span(self, operation: str, model: str) -> GenAISpan:
        return GenAISpan(span_id=uuid.uuid4().hex[:16], operation=operation, model=model)

    def record(self, span: GenAISpan) -> GenAISpan:
        with self._lock:
            self._spans.append(span)
            while len(self._spans) > self._capacity:
                self._spans.pop(0)
        return span

    @property
    def spans(self) -> list[GenAISpan]:
        with self._lock:
            return list(self._spans)

    def summary(self) -> dict:
        """Agrega os SLIs a partir dos spans (base dos dashboards e SLOs)."""
        with self._lock:
            spans = list(self._spans)
        if not spans:
            return {"count": 0}
        latencies = sorted(s.latency_ms for s in spans)
        p95 = latencies[min(len(latencies) - 1, int(round(0.95 * (len(latencies) - 1))))]
        blocked = sum(1 for s in spans if s.blocked)
        grounded = sum(1 for s in spans if s.grounded)
        return {
            "count": len(spans),
            "latency_p95_ms": round(p95, 3),
            "block_rate": round(blocked / len(spans), 4),
            "groundedness": round(grounded / len(spans), 4),
            "total_cost_usd": round(sum(s.cost_usd for s in spans), 6),
            "total_tokens": sum(s.input_tokens + s.output_tokens for s in spans),
        }

    def reset(self) -> None:
        with self._lock:
            self._spans.clear()
