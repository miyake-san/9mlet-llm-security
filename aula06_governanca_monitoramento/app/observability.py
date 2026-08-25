"""Wiring de observabilidade do app: Prometheus, OpenTelemetry e Langfuse (Aula 06).

Camada de PRODUÇÃO que conecta o núcleo de domínio (``src/security/observability``)
às ferramentas reais discutidas no Doc 04 (§Observabilidade):

* **Prometheus** — expõe as métricas SLI em ``/metrics`` (raspadas pelo Grafana).
* **OpenTelemetry** (opcional, grupo ``otel``) — exporta spans gen_ai.* via OTLP.
* **Langfuse** (opcional, grupo ``langfuse``) — tracing por step (latência/tokens/
  custo), a "cascata legível" da Figura 3.

Toda exportação é *best-effort*: falha de telemetria NUNCA derruba o request
(a observabilidade não pode virar nova fonte de risco — Doc 04, §Obs.).

Referência:
    OpenTelemetry (2024). gen_ai.* · Langfuse (2024). · Doc 04, §Observabilidade.
"""

from __future__ import annotations

import logging

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from app.config import Settings
from src.security.observability import (
    CostModel,
    InMemoryTraceStore,
    SemanticCache,
    route_model,
)
from src.security.schemas import GenAISpan, RequestMetric

logger = logging.getLogger(__name__)

_LATENCY_BUCKETS = (10, 25, 50, 100, 200, 400, 800, 1600, 2000, 3200, 6400, float("inf"))


class Instrumentation:
    """Fachada de instrumentação: cache, routing, custo, spans e exportação.

    Mantém um registro Prometheus PRÓPRIO (não o global) para permitir múltiplas
    instâncias em testes sem colisão de métricas duplicadas.
    """

    def __init__(
        self,
        settings: Settings,
        cost_model: CostModel,
        cache: SemanticCache,
        trace_store: InMemoryTraceStore,
        routing_cfg: dict,
    ) -> None:
        self.settings = settings
        self.cost = cost_model
        self.cache = cache
        self.trace_store = trace_store
        self.routing_cfg = routing_cfg
        self.registry = CollectorRegistry()
        self._build_metrics()
        self._tracer = self._maybe_build_tracer()
        self._langfuse = self._maybe_build_langfuse()

    # ---- Prometheus ------------------------------------------------------- #
    def _build_metrics(self) -> None:
        reg = self.registry
        self.m_requests = Counter(
            "aurora_requests_total",
            "Requests ao Aurora Assist",
            ["backend", "blocked"],
            registry=reg,
        )
        self.m_latency = Histogram(
            "aurora_request_latency_ms",
            "Latência por request (ms)",
            buckets=_LATENCY_BUCKETS,
            registry=reg,
        )
        self.m_tokens = Counter(
            "aurora_tokens_total", "Tokens consumidos", ["direction"], registry=reg
        )
        self.m_cost = Counter("aurora_cost_usd_total", "Custo acumulado (USD)", registry=reg)
        self.m_cache = Counter("aurora_cache_hits_total", "Hits do cache semântico", registry=reg)
        self.m_pii = Counter("aurora_pii_leaks_total", "Respostas com PII vazada", registry=reg)
        self.m_jb_attempts = Counter(
            "aurora_jailbreak_attempts_total", "Tentativas de jailbreak", registry=reg
        )
        self.m_jb_blocked = Counter(
            "aurora_jailbreak_blocked_total", "Jailbreaks bloqueados", registry=reg
        )
        self.m_grounded = Gauge(
            "aurora_groundedness", "Groundedness (proxy) da última resposta", registry=reg
        )
        self.m_drift = Gauge(
            "aurora_drift_score", "Score de drift por método", ["method"], registry=reg
        )

    def prometheus_text(self) -> bytes:
        """Exposição no formato Prometheus (raspada por prometheus/grafana)."""
        return generate_latest(self.registry)

    # ---- OpenTelemetry (opcional) ---------------------------------------- #
    def _maybe_build_tracer(self):
        endpoint = self.settings.otel_exporter_otlp_endpoint
        if not (self.settings.otel_traces_enabled and endpoint):
            return None
        try:
            from opentelemetry import trace
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except ImportError:
            logger.warning("OTel indisponível (instale o grupo `otel`); usando coletor em memória.")
            return None
        resource = Resource.create({"service.name": self.settings.otel_service_name})
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces"))
        )
        trace.set_tracer_provider(provider)
        logger.info("OTel OTLP habilitado -> %s", endpoint)
        return trace.get_tracer("aurora-assist")

    def _maybe_build_langfuse(self):
        if not self.settings.langfuse_enabled:
            return None
        try:
            from langfuse import Langfuse
        except ImportError:
            logger.warning("Langfuse indisponível (instale o grupo `langfuse`).")
            return None
        try:
            return Langfuse(
                host=self.settings.langfuse_host,
                public_key=self.settings.langfuse_public_key,
                secret_key=self.settings.langfuse_secret_key,
            )
        except Exception as exc:  # limite: SDK externo — best-effort
            logger.warning("Falha ao iniciar Langfuse: %s", exc)
            return None

    # ---- Token economics -------------------------------------------------- #
    def route(self, prompt: str) -> tuple[str, bool]:
        return route_model(prompt, self.routing_cfg)

    def cache_lookup(self, prompt: str) -> str | None:
        if not self.settings.semantic_cache_enabled:
            return None
        return self.cache.get(prompt)

    def cache_store(self, prompt: str, answer: str) -> None:
        if self.settings.semantic_cache_enabled:
            self.cache.put(prompt, answer)

    # ---- Registro de span (Prometheus + OTel + Langfuse) ------------------ #
    def record(self, span: GenAISpan) -> GenAISpan:
        """Registra o span em todas as saídas de telemetria (best-effort)."""
        self.trace_store.record(span)
        self._update_prometheus(span)
        self._export_otel(span)
        self._export_langfuse(span)
        return span

    def _update_prometheus(self, span: GenAISpan) -> None:
        self.m_requests.labels(backend=span.gen_ai_system, blocked=str(span.blocked).lower()).inc()
        self.m_latency.observe(span.latency_ms)
        self.m_tokens.labels(direction="input").inc(span.input_tokens)
        self.m_tokens.labels(direction="output").inc(span.output_tokens)
        self.m_cost.inc(span.cost_usd)
        if span.cache_hit:
            self.m_cache.inc()
        if span.pii_leak:
            self.m_pii.inc()
        if span.block_reason == "jailbreak":
            self.m_jb_attempts.inc()
            if span.blocked:
                self.m_jb_blocked.inc()
        if span.groundedness is not None:
            self.m_grounded.set(span.groundedness)

    def set_drift_score(self, method: str, value: float) -> None:
        """Publica o score de drift mais recente (alimenta o dashboard)."""
        self.m_drift.labels(method=method).set(value)

    def _export_otel(self, span: GenAISpan) -> None:
        if self._tracer is None:
            return
        try:
            with self._tracer.start_as_current_span(span.name) as otel_span:
                for key, value in span.to_otel_attributes().items():
                    otel_span.set_attribute(key, value)
        except Exception as exc:  # limite: exportador externo — best-effort
            logger.debug("Export OTel falhou: %s", exc)

    def _export_langfuse(self, span: GenAISpan) -> None:
        if self._langfuse is None:
            return
        try:
            trace = self._langfuse.trace(name=span.name, metadata={"regulated": span.regulated})
            trace.generation(
                name="chat",
                model=span.gen_ai_request_model,
                usage={"input": span.input_tokens, "output": span.output_tokens},
                metadata=span.to_otel_attributes(),
            )
        except Exception as exc:  # limite: SDK externo — best-effort
            logger.debug("Export Langfuse falhou: %s", exc)

    def metrics(self) -> list[RequestMetric]:
        return self.trace_store.metrics()


def build_instrumentation(settings: Settings, thresholds: dict) -> Instrumentation:
    """Monta a instrumentação a partir de Settings + thresholds.yaml."""
    cost_model = CostModel.from_config(thresholds.get("cost", {}))
    cache = SemanticCache(
        threshold=settings.semantic_cache_threshold,
        max_entries=int(thresholds.get("semantic_cache", {}).get("max_entries", 512)),
    )
    trace_store = InMemoryTraceStore(path=settings.trace_store_path)
    routing_cfg = thresholds.get("routing", {})
    routing_cfg.setdefault("enabled", settings.model_routing_enabled)
    return Instrumentation(settings, cost_model, cache, trace_store, routing_cfg)


def _self_test() -> None:  # pragma: no cover - utilitário de linha de comando
    """Demo offline da instrumentação (task monitor): spans + /metrics + SLOs."""
    from rich import print as rprint

    from app.config import get_settings
    from src.security.metrics import aggregate_slis
    from src.security.observability import new_span
    from src.security.slo import evaluate_all, load_slo_definitions

    settings = get_settings()
    thresholds = {
        "cost": {"input_per_1k": 0.005, "output_per_1k": 0.015},
        "routing": {"enabled": True},
        "semantic_cache": {"max_entries": 128},
    }
    inst = build_instrumentation(settings, thresholds)
    for i in range(5):
        span = new_span(
            "aurora_assist.chat",
            system="stub-aligned",
            model="aurora-mini",
            input_tokens=20 + i,
            output_tokens=40 + i * 5,
            latency_ms=120.0 + i * 60,
            cost_usd=inst.cost.cost("aurora-mini", 20 + i, 40 + i * 5),
            groundedness=0.9,
            regulated=(i % 2 == 0),
        )
        inst.record(span)
    slis = aggregate_slis(inst.metrics())
    slis["knowledge_age_seconds"] = 3600.0
    report = evaluate_all(load_slo_definitions(), slis)
    rprint("[bold]SLIs:[/bold]", {k: round(v, 3) for k, v in slis.items()})
    rprint("[bold]SLOs saudáveis?[/bold]", report.all_healthy)
    rprint("[bold]Amostra /metrics:[/bold]")
    for line in inst.prometheus_text().decode().splitlines():
        if line.startswith("aurora_") and not line.startswith("#"):
            rprint(" ", line)


if __name__ == "__main__":  # pragma: no cover
    import sys

    if "--self-test" in sys.argv:
        _self_test()
    else:
        print("uso: python -m app.observability --self-test")
