"""Esquemas compartilhados da camada de LLMOps (Aula 06).

Define os tipos que traduzem os conceitos do Documento 04 em estruturas de
engenharia verificáveis: tipos e resultados de **drift** (§"O que é drift",
§"Detecção estatística de drift"), **spans gen_ai.*** de observabilidade
(§"Observabilidade" — OpenTelemetry), **SLIs/SLOs/Data SLOs** e error budget
(§"SLIs, SLOs e Data SLOs") e **feedback** governado (§"Feedback loops").

Tudo é *offline-first* e determinístico por padrão; adaptadores de PRODUÇÃO
(OpenTelemetry SDK, Langfuse, scipy/scikit-learn, Azure Monitor) são opcionais.

Referência:
    OpenTelemetry (2024). Semantic Conventions for Generative AI Systems.
    Beyer et al. (2016). Site Reliability Engineering. · Gama et al. (2014).
    Gretton et al. (2012). A Kernel Two-Sample Test (MMD).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, StrEnum


def utc_now_iso() -> str:
    """Timestamp ISO-8601 em UTC (proveniência de spans e relatórios)."""
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# Enums de drift (Doc 04, §"O que é drift" / §"Detecção estatística")          #
# --------------------------------------------------------------------------- #
class DriftType(StrEnum):
    """Quatro tipos de drift em LLMs (Doc 04, Figura 2)."""

    DATA = "data_drift"  # P_t(X) != P_0(X) — distribuição das entradas
    CONCEPT = "concept_drift"  # P_t(Y|X) != P_0(Y|X) — relação entrada-resposta
    PROMPT = "prompt_drift"  # como os usuários escrevem muda
    RESPONSE = "response_drift"  # qualidade das saídas degrada


class DriftMethod(StrEnum):
    """Testes estatísticos de detecção de drift (Doc 04, Tabela 2)."""

    KS = "ks"  # Kolmogorov-Smirnov (escalares)
    PSI = "psi"  # Population Stability Index (crédito)
    MMD = "mmd"  # Maximum Mean Discrepancy (embeddings)
    WASSERSTEIN = "wasserstein"  # distância de Wasserstein (deslocamentos)


class DriftSeverity(StrEnum):
    """Gravidade operacional do sinal de drift (Doc 04 — leitura integrada)."""

    NONE = "none"
    MODERATE = "moderate"
    SEVERE = "severe"


# --------------------------------------------------------------------------- #
# Enums de observabilidade e SLO                                               #
# --------------------------------------------------------------------------- #
class GenAIOperation(StrEnum):
    """gen_ai.operation.name (OpenTelemetry semantic conventions)."""

    CHAT = "chat"
    EMBEDDINGS = "embeddings"


class SLOKind(StrEnum):
    """Classe do objetivo (Doc 04, §SLOs)."""

    SLI = "sli"
    SLO = "slo"
    DATA_SLO = "data_slo"


class SLOStatus(StrEnum):
    """Estado de um SLO após avaliação contra a meta e o error budget."""

    HEALTHY = "healthy"
    AT_RISK = "at_risk"
    VIOLATED = "violated"


class MaturityLevel(IntEnum):
    """Modelo de maturidade LLMOps (Google Cloud, 2020; Doc 04, §maturidade)."""

    MANUAL = 0  # deploys manuais, métricas esparsas
    CI_CD = 1  # pipelines de validação, versionamento, dashboards
    AUTOMATED = 2  # detecção automática de drift, Data SLOs, feedback curado


# --------------------------------------------------------------------------- #
# Modelos de domínio (dataclasses serializáveis)                               #
# --------------------------------------------------------------------------- #
@dataclass
class LLMResponse:
    """Resposta do backend de LLM com contabilidade de tokens (token economics)."""

    text: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DriftResult:
    """Resultado de um teste de drift (Doc 04, §"Detecção estatística")."""

    method: DriftMethod
    drift_type: DriftType
    statistic: float
    threshold: float
    drifted: bool
    severity: DriftSeverity = DriftSeverity.NONE
    p_value: float | None = None
    n_ref: int = 0
    n_now: int = 0
    detail: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["method"] = self.method.value
        data["drift_type"] = self.drift_type.value
        data["severity"] = self.severity.value
        return data


@dataclass
class GenAISpan:
    """Span de uma chamada ao LLM com convenções semânticas gen_ai.* (OTel).

    Modela o Snippet 3 do Doc 04 e a Figura 3 (trace de conversa). Os sinais de
    SEGURANÇA (blocked, pii_leak, groundedness, cache_hit) usam um namespace
    próprio (``aurora.*``), prática comum para atributos não padronizados.
    """

    name: str
    gen_ai_system: str = "ollama"
    gen_ai_request_model: str = "llama3.2:3b"
    gen_ai_operation: GenAIOperation = GenAIOperation.CHAT
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    finish_reason: str = "stop"
    cache_hit: bool = False
    blocked: bool = False
    block_reason: str | None = None
    groundedness: float | None = None
    pii_leak: bool = False
    regulated: bool = False
    prompt_preview: str = ""
    trace_id: str = ""
    span_id: str = ""
    timestamp: str = field(default_factory=utc_now_iso)

    def to_otel_attributes(self) -> dict[str, object]:
        """Atributos no formato OpenTelemetry gen_ai.* (interoperável)."""
        attrs: dict[str, object] = {
            "gen_ai.system": self.gen_ai_system,
            "gen_ai.operation.name": self.gen_ai_operation.value,
            "gen_ai.request.model": self.gen_ai_request_model,
            "gen_ai.usage.input_tokens": self.input_tokens,
            "gen_ai.usage.output_tokens": self.output_tokens,
            "gen_ai.response.finish_reasons": [self.finish_reason],
            # Custos e sinais de segurança (namespace próprio, não padronizado).
            "aurora.cost_usd": round(self.cost_usd, 6),
            "aurora.latency_ms": round(self.latency_ms, 2),
            "aurora.cache_hit": self.cache_hit,
            "aurora.blocked": self.blocked,
            "aurora.pii_leak": self.pii_leak,
            "aurora.regulated": self.regulated,
        }
        if self.groundedness is not None:
            attrs["aurora.groundedness"] = round(self.groundedness, 4)
        if self.block_reason:
            attrs["aurora.block_reason"] = self.block_reason
        return attrs

    def to_dict(self) -> dict:
        data = asdict(self)
        data["gen_ai_operation"] = self.gen_ai_operation.value
        return data


@dataclass
class RequestMetric:
    """Linha de telemetria por request (base para SLIs — Doc 04, §SLIs)."""

    latency_ms: float
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    groundedness: float | None = None
    cache_hit: bool = False
    blocked: bool = False
    jailbreak_attempt: bool = False
    jailbreak_blocked: bool = False
    pii_leak: bool = False
    regulated: bool = False
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SLODefinition:
    """Definição de um SLI/SLO/Data SLO (configs/slo.yaml; Doc 04, Tabela 3)."""

    id: str
    name: str
    kind: SLOKind
    sli: str
    objective: float
    unit: str
    comparator: str  # "lte" | "gte"
    source: str = ""
    window: str = ""
    error_budget: float = 0.0
    action: str = ""

    def is_met(self, value: float) -> bool:
        """Verifica se o valor medido satisfaz a meta (comparador lte/gte)."""
        if self.comparator == "lte":
            return value <= self.objective
        return value >= self.objective


@dataclass
class SLOEvaluation:
    """Avaliação de um SLO contra o valor medido e o error budget."""

    slo_id: str
    name: str
    kind: SLOKind
    sli_value: float
    objective: float
    unit: str
    comparator: str
    met: bool
    status: SLOStatus
    error_budget: float = 0.0
    action: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["kind"] = self.kind.value
        data["status"] = self.status.value
        return data


@dataclass
class SLOReport:
    """Relatório consolidado de SLOs (painel de qualidade/custo/segurança)."""

    evaluations: list[SLOEvaluation] = field(default_factory=list)
    generated_at: str = field(default_factory=utc_now_iso)

    @property
    def violated(self) -> list[SLOEvaluation]:
        return [e for e in self.evaluations if e.status == SLOStatus.VIOLATED]

    @property
    def all_healthy(self) -> bool:
        return all(e.status == SLOStatus.HEALTHY for e in self.evaluations)

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "all_healthy": self.all_healthy,
            "violated_count": len(self.violated),
            "evaluations": [e.to_dict() for e in self.evaluations],
        }


@dataclass
class FeedbackRecord:
    """Feedback do usuário para o loop governado (Doc 04, §"Feedback loops").

    ⚠️ Feedback NÃO é verdade absoluta: alimentar o sistema sem triagem pode
    reforçar vieses. Por isso ``curated`` só vira True após avaliação humana.
    """

    request_id: str
    rating: int  # -1 (ruim) | 0 (neutro) | +1 (bom)
    subject_ref: str = "anon"  # pseudonimizado (nunca PII em claro)
    comment: str = ""
    curated: bool = False
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict:
        return asdict(self)
