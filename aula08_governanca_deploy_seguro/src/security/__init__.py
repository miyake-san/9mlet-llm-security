"""Biblioteca de segurança reutilizável da Aula 08 (governança + deploy seguro).

Expõe as implementações **puras e offline** que integram os controles das Aulas
1-7 sob governança de produção (Doc 04): guardrails (Aula 02), isolamento MCP
(Aula 03), auditoria imutável (Aula 04), SLO/observabilidade (Aula 06), além dos
artefatos novos da Aula 08 — frameworks de governança, padrões de deployment,
AIBOM e resposta a incidentes. As bibliotecas de referência (CycloneDX, PyRIT,
Garak) ficam no grupo opcional ``security``.
"""

from src.security.aibom import aibom_completeness, build_aibom, write_aibom
from src.security.audit import HashChain
from src.security.deployment import (
    CanaryController,
    CanaryOutcome,
    TrafficRouter,
)
from src.security.governance import (
    assess_maturity,
    build_crosswalk,
    coverage_report,
)
from src.security.guardrails import GuardrailPipeline, detect_injection, redact_pii
from src.security.incident import blameless_postmortem, classify_incident, run_playbook
from src.security.mcp import ToolAuthorizer, issue_token, verify_signature
from src.security.schemas import (
    CapabilityToken,
    DeploymentStrategy,
    GenAISpan,
    GuardDecision,
    Incident,
    IncidentSeverity,
    LayerResult,
    SLODefinition,
    SLOReport,
    SLOStatus,
    ToolResult,
    Verdict,
)
from src.security.slo import (
    error_budget_status,
    evaluate_all,
    load_slo_definitions,
    rollback_decision,
    should_rollback,
)

__all__ = [
    # guardrails
    "GuardrailPipeline",
    "detect_injection",
    "redact_pii",
    # mcp
    "ToolAuthorizer",
    "issue_token",
    "verify_signature",
    # audit
    "HashChain",
    # slo / rollback
    "load_slo_definitions",
    "evaluate_all",
    "error_budget_status",
    "should_rollback",
    "rollback_decision",
    # deployment
    "TrafficRouter",
    "CanaryController",
    "CanaryOutcome",
    # governance
    "build_crosswalk",
    "coverage_report",
    "assess_maturity",
    # aibom
    "build_aibom",
    "write_aibom",
    "aibom_completeness",
    # incident
    "classify_incident",
    "run_playbook",
    "blameless_postmortem",
    # schemas
    "Verdict",
    "LayerResult",
    "GuardDecision",
    "CapabilityToken",
    "ToolResult",
    "GenAISpan",
    "SLODefinition",
    "SLOStatus",
    "SLOReport",
    "DeploymentStrategy",
    "Incident",
    "IncidentSeverity",
]
