"""Estruturas de dados compartilhadas da Aula 08 (governança + deploy seguro).

Reúne os *dataclasses* e *enums* usados pela biblioteca de segurança, pela app
(agente) e pelos notebooks. Manter as estruturas em um único módulo evita
importações circulares e documenta o vocabulário da aula (Doc 04): veredito de
guardrail, span de observabilidade, definição de SLO, token de capacidade (MCP),
incidente e estratégia de deployment.

Referência:
    NIST (2023). AI Risk Management Framework 1.0 (AI 100-1).
    Beyer et al. (2016). Site Reliability Engineering (SLO/error budget).
    OpenTelemetry (2024). Semantic Conventions for Generative AI Systems.
    Doc 04, seções 5-10.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum


# --------------------------------------------------------------------------- #
# Guardrails (reuso da Aula 02)                                                #
# --------------------------------------------------------------------------- #
class Verdict(StrEnum):
    """Veredito de uma camada de guardrail (Doc 04, §9 — DevSecOps)."""

    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"


@dataclass
class LayerResult:
    """Resultado de uma única camada de guardrail (defense-in-depth)."""

    layer: str
    verdict: Verdict
    reason: str = ""
    score: float = 0.0
    details: dict = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.verdict != Verdict.BLOCK


@dataclass
class GuardDecision:
    """Decisão agregada das camadas de guardrail sobre uma entrada/saída."""

    stage: str
    results: list[LayerResult] = field(default_factory=list)
    final_text: str | None = None

    def add(self, result: LayerResult) -> LayerResult:
        self.results.append(result)
        return result

    @property
    def allowed(self) -> bool:
        return all(r.allowed for r in self.results)

    @property
    def blocked_by(self) -> str | None:
        for r in self.results:
            if r.verdict == Verdict.BLOCK:
                return r.layer
        return None

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "allowed": self.allowed,
            "blocked_by": self.blocked_by,
            "layers": [
                {"layer": r.layer, "verdict": r.verdict.value, "reason": r.reason, "score": r.score}
                for r in self.results
            ],
        }


# --------------------------------------------------------------------------- #
# Capability token para ferramentas MCP (reuso da Aula 03)                     #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class CapabilityToken:
    """Token de capacidade que atrela um sujeito a UMA ferramenta e escopos.

    Materializa o menor privilégio (Doc 04, §9): a autoridade é verificada a cada
    chamada de ferramenta, defendendo contra *confused deputy* e *scope creep*.
    """

    subject: str
    tool: str
    scopes: frozenset[str]
    issued_at: float
    expires_at: float
    signature: str

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at


@dataclass
class ToolResult:
    """Resultado de uma tentativa de chamada de ferramenta MCP."""

    tool: str
    allowed: bool
    reason: str = ""
    output: str = ""

    def to_dict(self) -> dict:
        return {"tool": self.tool, "allowed": self.allowed, "reason": self.reason}


# --------------------------------------------------------------------------- #
# Observabilidade — span gen_ai.* (reuso da Aula 06)                           #
# --------------------------------------------------------------------------- #
@dataclass
class GenAISpan:
    """Span de observabilidade seguindo as convenções gen_ai.* do OpenTelemetry.

    Reúne, por request do agente, o que a Figura 3 do Doc 04 mostra: modelo,
    tokens, custo, latência e sinais de segurança (bloqueio, groundedness).
    """

    span_id: str
    operation: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    blocked: bool = False
    grounded: bool = True
    tool_calls: int = 0
    prompt_preview: str = ""
    attributes: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "span_id": self.span_id,
            "gen_ai.operation.name": self.operation,
            "gen_ai.request.model": self.model,
            "gen_ai.usage.input_tokens": self.input_tokens,
            "gen_ai.usage.output_tokens": self.output_tokens,
            "gen_ai.usage.cost_usd": round(self.cost_usd, 6),
            "latency_ms": round(self.latency_ms, 3),
            "security.blocked": self.blocked,
            "security.grounded": self.grounded,
            "gen_ai.tool.calls": self.tool_calls,
            "gen_ai.prompt.preview": self.prompt_preview,
            **self.attributes,
        }


# --------------------------------------------------------------------------- #
# SLO / error budget (reuso da Aula 06; base do rollback — Doc 04, §6-7)       #
# --------------------------------------------------------------------------- #
class SLOStatus(StrEnum):
    HEALTHY = "healthy"
    AT_RISK = "at_risk"
    VIOLATED = "violated"


@dataclass
class SLODefinition:
    """Definição de um SLO (Doc 04, §7 — SRE para IA)."""

    id: str
    name: str
    sli: str
    objective: float
    comparator: str = "lte"  # "lte" (bom = menor) | "gte" (bom = maior)
    unit: str = ""
    error_budget: float = 0.0
    critical: bool = False  # gatilho de rollback automatizado (Snippet 2 do Doc 04)
    action: str = ""

    def is_met(self, value: float) -> bool:
        if self.comparator == "gte":
            return value >= self.objective
        return value <= self.objective

    def violates(self, value: float) -> bool:
        """Violação direcional do limiar (operador ▷ da fórmula do Doc 04, §6)."""
        return not self.is_met(value)


@dataclass
class SLOEvaluation:
    slo_id: str
    name: str
    sli_value: float
    objective: float
    comparator: str
    unit: str
    met: bool
    status: SLOStatus
    critical: bool
    action: str = ""

    def to_dict(self) -> dict:
        return {
            "slo_id": self.slo_id,
            "name": self.name,
            "sli_value": self.sli_value,
            "objective": self.objective,
            "comparator": self.comparator,
            "unit": self.unit,
            "met": self.met,
            "status": self.status.value,
            "critical": self.critical,
            "action": self.action,
        }


@dataclass
class SLOReport:
    evaluations: list[SLOEvaluation] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return all(e.met for e in self.evaluations)

    @property
    def violated(self) -> list[SLOEvaluation]:
        return [e for e in self.evaluations if not e.met]

    def to_dict(self) -> dict:
        return {
            "healthy": self.healthy,
            "total": len(self.evaluations),
            "violated": [e.slo_id for e in self.violated],
            "evaluations": [e.to_dict() for e in self.evaluations],
        }


# --------------------------------------------------------------------------- #
# Deployment (Doc 04, §6)                                                      #
# --------------------------------------------------------------------------- #
class DeploymentStrategy(StrEnum):
    BLUE_GREEN = "blue_green"
    CANARY = "canary"
    SHADOW = "shadow"


# --------------------------------------------------------------------------- #
# Resposta a incidentes (Doc 04, §7)                                          #
# --------------------------------------------------------------------------- #
class IncidentSeverity(StrEnum):
    SEV1 = "SEV1"  # crítico: contenção imediata (rollback/bloqueio)
    SEV2 = "SEV2"  # alto
    SEV3 = "SEV3"  # moderado


@dataclass
class Incident:
    """Incidente de IA classificado pelo playbook (Doc 04, Figura 4)."""

    incident_id: str
    kind: str  # jailbreak_escape | data_leak | drift_critico
    severity: IncidentSeverity
    summary: str
    triggered_by: str = ""
    containment: str = ""

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "kind": self.kind,
            "severity": self.severity.value,
            "summary": self.summary,
            "triggered_by": self.triggered_by,
            "containment": self.containment,
        }
